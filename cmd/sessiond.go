package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
	"github.com/neozmmv/blindspot/internal/network"
	"github.com/neozmmv/blindspot/internal/session"
	bstun "github.com/neozmmv/blindspot/internal/tun"
	"github.com/neozmmv/blindspot/internal/utils"
)

// daemonParams is everything the session daemon needs that differs between the
// two ways of finding peers: the clearnet rendezvous server (`blindspot
// rendezvous`) and a room's onion service (`blindspot connect`).
//
// Everything below the discovery layer — STUN, the Noise transport, TUN setup,
// the packet pumps, stats and teardown — is identical either way, which is why
// it lives here rather than being duplicated per command.
type daemonParams struct {
	// discovery announces this peer and reports the others. It is a reference
	// rather than a client so that an onion room can move hosting to another
	// peer mid-session without tearing down the transport or the TUN device.
	discovery *discoveryRef
	// createSession maps to the rendezvous server's "create a password session"
	// step. Onion rooms have no such concept and always pass false.
	createSession bool
	// pskPassword and pskSessionID feed the Noise pre-shared key and handshake
	// prologue. For an onion room these are the room name and password, so the
	// PSK remains a real second factor independent of the onion address.
	pskPassword  string
	pskSessionID string
	upMbit       int
	statusFile   string
}

// progressPrefix marks a status-file line as a non-terminal progress update, so
// the foreground process reports it and keeps waiting instead of treating it as
// the final outcome.
const progressPrefix = "progress:"

// superviseDaemon re-executes this same command with --daemon (elevating first
// if the TUN device needs it) and blocks until the child reports its status.
//
// startupTimeout differs sharply per command: a clearnet rendezvous answers in
// seconds, while an onion room must bootstrap Tor and publish or fetch a
// descriptor first — measured anywhere from ~28s to ~187s.
func superviseDaemon(successMsg string, startupTimeout time.Duration) {
	if isSessionRunning() {
		fmt.Println("Already connected to a network. Run 'blindspot disconnect' first.")
		return
	}

	tmp, err := os.CreateTemp("", "blindspot-status-*")
	if err != nil {
		fmt.Println("Error creating status file:", err)
		return
	}
	tmp.Close()
	os.Remove(tmp.Name())
	statusPath := tmp.Name()

	childArgs := append(os.Args[1:], "--daemon", "--status-file="+statusPath)

	var child *exec.Cmd
	if !bstun.IsAdmin() {
		// not elevated — trigger UAC prompt and launch as admin
		if err := bstun.RelaunchAsAdmin(childArgs); err != nil {
			fmt.Println("Failed to request admin privileges:", err)
			return
		}
	} else {
		child = exec.Command(os.Args[0], childArgs...)
		child.Stdin = nil
		child.Stdout = nil
		child.Stderr = nil
		if err := child.Start(); err != nil {
			fmt.Println("Error starting background process:", err)
			return
		}
	}

	deadline := time.Now().Add(startupTimeout)
	lastProgress := ""
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(statusPath); err == nil && len(data) > 0 {
			msg := strings.TrimSpace(string(data))
			// Non-terminal updates keep the user informed across the minute-plus
			// a Tor room can take to come up, without ending the wait.
			if step, ok := strings.CutPrefix(msg, progressPrefix); ok {
				if step = strings.TrimSpace(step); step != lastProgress {
					fmt.Println("  " + step)
					lastProgress = step
				}
				time.Sleep(200 * time.Millisecond)
				continue
			}
			os.Remove(statusPath)
			if msg == "ok" {
				fmt.Println(successMsg)
			} else {
				fmt.Printf("Failed to connect: %s\n", msg)
				if child != nil {
					child.Process.Kill()
				}
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Println("Timed out waiting for connection.")
	if child != nil {
		child.Process.Kill()
	}
}

// runSessionDaemon owns the live session: it registers with the discovery
// endpoint, brings up the TUN device, and pumps packets until quit. It returns
// only once the session is torn down.
func runSessionDaemon(p daemonParams) {
	pidFile := sessionPIDFile()
	os.MkdirAll(filepath.Dir(pidFile), 0700)
	os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0600)

	writeStatus := func(msg string) {
		if p.statusFile != "" {
			os.WriteFile(p.statusFile, []byte(msg), 0600)
		}
	}

	privateKey, publicKey, err := utils.ReadIdentity()
	if err != nil {
		keyPair, err := utils.InitIdentity()
		if err != nil {
			writeStatus("error: initializing identity: " + err.Error())
			os.Remove(pidFile)
			return
		}
		privateKey = keyPair.PrivateKey
		publicKey = keyPair.PublicKey
	}

	// PSK (second factor) from the password via Argon2id, salted with the session
	// id; prologue binds the Noise handshake to protocol version + session. Our
	// static pubkey is published to the rendezvous so peers can pin it beforehand.
	psk := crypto.DerivePSK(p.pskPassword, p.pskSessionID)
	prologue := network.Prologue(p.pskSessionID)
	myPubKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

	tr, err := network.OpenTransport()
	if err != nil {
		writeStatus("error: opening UDP transport: " + err.Error())
		os.Remove(pidFile)
		return
	}

	// from here on, defer owns all cleanup
	var (
		tunDevice  bstun.Device
		registered bool
		publicAddr string
	)
	peerConn := network.NewPeerConn(tr, privateKey, publicKey, psk, prologue)
	if p.upMbit > 0 {
		peerConn.SetFixedUploadRate(float64(p.upMbit) * 1e6 / 8)
	}
	quit := make(chan struct{})
	var quitOnce sync.Once
	closeQuit := func() { quitOnce.Do(func() { close(quit) }) }

	defer func() {
		if tunDevice != nil {
			tunDevice.Close()
		}
		exec.Command("route", "delete", "10.0.0.0", "mask", "255.0.0.0").Run() // best effort cleanup of route
		if registered {
			cur, _ := p.discovery.current()
			cur.Leave(publicAddr)
		}
		peerConn.BroadcastDead() // encrypted "dead" notice so peers tear down promptly
		peerConn.Close()         // stop handshake drivers/consumers and close the bind
		os.Remove(pidFile)
		os.Remove(sessionStopFile())
		os.Remove(peersFile())
	}()

	publicAddr, err = peerConn.DiscoverPublicAddr()
	if err != nil {
		writeStatus("error: discovering public address: " + err.Error())
		return
	}

	regClient, _ := p.discovery.current()
	peers, selfIndex, err := regClient.Register(publicAddr, myPubKeyB64, p.createSession)
	if err != nil {
		writeStatus("error: " + err.Error())
		return
	}
	registered = true
	p.discovery.setSelfIndex(selfIndex)

	myVirtualIP := bstun.VirtualIPv4(publicKey)
	tunDevice, err = bstun.Create(myVirtualIP)
	if err != nil {
		writeStatus("error: creating TUN interface: " + err.Error())
		return
	}

	myPublicIP := strings.Split(publicAddr, ":")[0]

	// knownPeers tracks which resolved peer addresses have been handed to
	// AddKnownPeer, so rendezvous announcements are not re-added while a session
	// is live. Entries are removed when a peer dies so it can reconnect later.
	// Guarded by peersMu: it is touched by the initial loop, the SSE stream, the
	// periodic re-register, and the Dead handler.
	var peersMu sync.Mutex
	knownPeers := make(map[string]bool)

	// addPeer validates a rendezvous-announced peer and, if it is new, registers
	// its pinned static key and kicks off the Noise handshake.
	addPeer := func(peer session.PeerAddr) {
		peerAddrStr := peer.Public
		if strings.Split(peer.Public, ":")[0] == myPublicIP && peer.Local != "" {
			peerAddrStr = peer.Local
		}
		peerAddr, err := net.ResolveUDPAddr("udp", peerAddrStr)
		if err != nil {
			return
		}
		if !network.IsValidPeerAddr(peerAddr) {
			return // reject broadcast/multicast/unspecified IPs and privileged ports
		}
		pub, err := base64.StdEncoding.DecodeString(peer.PubKey)
		if err != nil || len(pub) != 32 {
			return // no valid pubkey from the rendezvous → cannot handshake
		}
		peersMu.Lock()
		if knownPeers[peerAddr.String()] {
			peersMu.Unlock()
			return
		}
		knownPeers[peerAddr.String()] = true
		peersMu.Unlock()
		peerConn.AddKnownPeer(peerAddr, pub)
	}

	for _, peer := range peers {
		addPeer(peer)
	}

	// Periodically re-register to keep the rendezvous session TTL alive. The
	// response lists the session's current peers — feed it through addPeer so a
	// peer that died and was forgotten (or an announcement the stream missed)
	// gets picked up again.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-p.discovery.wakeCh():
				// discovery moved to a new host; register there right away
				cur, _ := p.discovery.current()
				if current, idx, err := cur.Register(publicAddr, myPubKeyB64, false); err == nil {
					p.discovery.setSelfIndex(idx)
					for _, peer := range current {
						addPeer(peer)
					}
				}
			case <-ticker.C:
				cur, _ := p.discovery.current()
				if current, idx, err := cur.Register(publicAddr, myPubKeyB64, false); err == nil {
					p.discovery.setSelfIndex(idx)
					for _, peer := range current {
						addPeer(peer)
					}
				}
			}
		}
	}()

	// The stream is re-established whenever discovery is swapped, so a handover
	// to a new host reconnects instead of silently going deaf on the old one.
	go func() {
		for {
			select {
			case <-quit:
				return
			default:
			}
			cur, superseded := p.discovery.current()
			for peer := range cur.StreamPeers(publicAddr, anyClosed(quit, superseded)) {
				addPeer(peer)
			}
		}
	}()

	// virtualIPMap maps each peer's virtual IP to their UDP address for TUN routing.
	var virtualIPMap sync.Map
	// addrToVIP is the reverse map (peer UDP addr → virtual IP) used by the TUN
	// reverse-path filter to verify the inner source IP of incoming tunnel packets.
	var addrToVIP sync.Map

	// Single place peer death is handled: both graceful departures (CtrlDead)
	// and keepalive timeouts arrive on the Dead channel. Clear the routing
	// mappings and forget the peer so a later rendezvous announcement (after a
	// crash/rejoin) starts a fresh handshake instead of being ignored.
	go func() {
		for {
			select {
			case <-quit:
				return
			case addr := <-peerConn.Dead:
				addrToVIP.Delete(addr.String())
				virtualIPMap.Range(func(k, v any) bool {
					if v.(*net.UDPAddr).String() == addr.String() {
						virtualIPMap.Delete(k)
						return false
					}
					return true
				})
				writePeers(&virtualIPMap)
				peersMu.Lock()
				delete(knownPeers, addr.String())
				peersMu.Unlock()
			}
		}
	}()

	// TUN-side counters for the stats log: what enters from the OS, what is
	// written back to the OS, and what the reverse-path filter rejects.
	var tunInPkts, tunInBytes, tunOutPkts, tunOutBytes, rpfDrops, noPeerDrops atomic.Uint64

	// Stats logger: once per second, append a delta line to stats.log while
	// there is tunnel activity. Comparing this file across the two machines
	// shows exactly where packets die: sender tx vs receiver rx is path
	// loss; rx vs tun_out is local processing loss; dec_fail/replay/rekey
	// indicate session-level trouble.
	go func() {
		logPath := filepath.Join(utils.GetBlindspotDir(), "stats.log")
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return
		}
		defer f.Close()
		type snap struct {
			txP, txB, txE, rxP, rxB, dec, rep, rek, tmo uint64
			tiP, tiB, toP, toB, rpf, nop                uint64
		}
		take := func() snap {
			s := &network.Stats
			return snap{
				s.TxPkts.Load(), s.TxBytes.Load(), s.TxErrs.Load(),
				s.RxPkts.Load(), s.RxBytes.Load(),
				s.RxDecryptFail.Load(), s.RxReplayDrop.Load(),
				s.Rekeys.Load(), s.Timeouts.Load(),
				tunInPkts.Load(), tunInBytes.Load(),
				tunOutPkts.Load(), tunOutBytes.Load(),
				rpfDrops.Load(), noPeerDrops.Load(),
			}
		}
		prev := take()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
				cur := take()
				if cur == prev {
					continue
				}
				fmt.Fprintf(f,
					"%s tun_in=%d/%dB tx=%d/%dB txerr=%d | rx=%d/%dB tun_out=%d/%dB dec_fail=%d replay=%d rpf=%d nopeer=%d | rekey=%d timeout=%d pace=%dbps\n",
					time.Now().Format("15:04:05"),
					cur.tiP-prev.tiP, cur.tiB-prev.tiB, cur.txP-prev.txP, cur.txB-prev.txB, cur.txE-prev.txE,
					cur.rxP-prev.rxP, cur.rxB-prev.rxB, cur.toP-prev.toP, cur.toB-prev.toB,
					cur.dec-prev.dec, cur.rep-prev.rep, cur.rpf-prev.rpf, cur.nop-prev.nop,
					cur.rek-prev.rek, cur.tmo-prev.tmo, network.Stats.PaceBps.Load()*8)
				prev = cur
			}
		}
	}()

	// tunBufPool recycles packet buffers across both pump directions so the
	// steady state allocates nothing per packet.
	tunBufPool := sync.Pool{New: func() any {
		b := make([]byte, 1600)
		return &b
	}}
	getTunBuf := func() []byte { return *tunBufPool.Get().(*[]byte) }
	putTunBuf := func(b []byte) {
		if cap(b) >= 1600 {
			b = b[:1600]
			tunBufPool.Put(&b)
		}
	}

	// UDP → TUN: drain decrypted tunnel packets in batches (parallel AEAD in
	// ReadTunBatch) and hand each surviving batch to the TUN device in a
	// single Write call instead of one ring transition per packet.
	go func() {
		batch := peerConn.BatchSize()
		bufs := make([][]byte, batch)
		for i := range bufs {
			bufs[i] = getTunBuf()
		}
		senders := make([]string, batch)
		wr := make([][]byte, 0, batch)
		for {
			n, err := peerConn.ReadTunBatch(bufs, senders)
			if err != nil {
				return // transport closed
			}
			wr = wr[:0]
			for i := 0; i < n; i++ {
				// Reverse-path filter: the inner IPv4 source address must equal the
				// sender's virtual IP. Otherwise a malicious member could inject packets
				// spoofing another peer's virtual IP inside the (authenticated) tunnel.
				expectedVIP, ok := addrToVIP.Load(senders[i])
				if !ok || !bstun.SrcIPMatchesVirtualIP(bufs[i], expectedVIP.(string)) {
					rpfDrops.Add(1)
					continue
				}
				wr = append(wr, bufs[i])
				tunOutPkts.Add(1)
				tunOutBytes.Add(uint64(len(bufs[i])))
			}
			if len(wr) == 0 {
				continue
			}
			network.UpdateLastSeen()
			tunDevice.Write(wr, 0)
		}
	}()

	// TUN → UDP is split into a reader and a sender joined by a channel, so
	// packets read one at a time (wintun's batch size is 1) still aggregate
	// into batches for the encrypt+send path.
	outCh := make(chan []byte, 512)

	// Reader: pull outbound IP packets off the TUN device and hand their
	// (pooled) buffers to the sender.
	go func() {
		batchSize := tunDevice.BatchSize()
		bufs := make([][]byte, batchSize)
		sizes := make([]int, batchSize)
		for i := range bufs {
			bufs[i] = getTunBuf()
		}
		for {
			n, err := tunDevice.Read(bufs, sizes, 0)
			if err != nil {
				close(outCh)
				return // TUN closed
			}
			for i := 0; i < n; i++ {
				packet := bufs[i][:sizes[i]]
				if len(packet) < 20 || packet[0]>>4 != 4 {
					continue // not an IPv4 packet
				}
				tunInPkts.Add(1)
				tunInBytes.Add(uint64(len(packet)))
				select {
				case outCh <- packet:
					bufs[i] = getTunBuf() // buffer ownership moved to the sender
				case <-quit:
					return
				}
			}
		}
	}()

	// Sender: aggregate whatever the reader has produced, group consecutive
	// packets by destination peer, and push each group through one batched
	// encrypt+send (one counter reservation, parallel AEAD, few syscalls).
	// Upload shaping happens inside SendTunBatch: adaptive by default
	// (engages only when CtrlAck feedback shows path loss), or fixed when
	// --up-mbit / config override it.
	go func() {
		pending := make([][]byte, 0, 128)
		flush := func() {
			for start := 0; start < len(pending); {
				destIP := net.IP(pending[start][16:20]).String()
				addrVal, ok := virtualIPMap.Load(destIP)
				if !ok {
					noPeerDrops.Add(1)
					putTunBuf(pending[start]) // no peer with that virtual IP
					start++
					continue
				}
				end := start + 1
				for end < len(pending) && bytes.Equal(pending[end][16:20], pending[start][16:20]) {
					end++
				}
				peerConn.SendTunBatch(addrVal.(*net.UDPAddr), pending[start:end])
				for _, b := range pending[start:end] {
					putTunBuf(b)
				}
				start = end
			}
			pending = pending[:0]
		}
		for {
			select {
			case pkt, ok := <-outCh:
				if !ok {
					return
				}
				pending = append(pending, pkt)
			drain:
				for len(pending) < cap(pending) {
					select {
					case more, ok := <-outCh:
						if !ok {
							flush()
							return
						}
						pending = append(pending, more)
					default:
						break drain
					}
				}
				flush()
			case <-quit:
				return
			}
		}
	}()

	// watch for disconnect command via stop file
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
				if _, err := os.Stat(sessionStopFile()); err == nil {
					closeQuit()
					return
				}
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		closeQuit()
	}()

	writeStatus("ok")

	// on each new peer: register their virtual IP and (for the first peer) start keepalive/watchdog
	go func() {
		first := true
		for addr := range peerConn.Connected {
			network.UpdateLastSeen()
			if pubKey, ok := peerConn.PeerPublicKey(addr); ok {
				vip := bstun.VirtualIPv4(pubKey)
				virtualIPMap.Store(vip, addr)
				addrToVIP.Store(addr.String(), vip)
				writePeers(&virtualIPMap)
			}
			if first {
				first = false
				go network.KeepAliveAll(peerConn)
			}
		}
	}()

	<-quit
}
