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
		detachDaemon(child)
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

// leaveTimeout bounds the "remove me from the room" request on the way out.
//
// For an onion room that request is a Tor round-trip on a client whose timeout
// is roomProbeTimeout (75s) — far longer than the 10s `blindspot disconnect`
// waits for the PID file to disappear before declaring the session unclean and
// cleaning up under a daemon that is in fact still shutting down. Leaving is
// best-effort anyway: peers that never see it drop us on keepalive timeout, and
// the room expires the registration on its own TTL.
const leaveTimeout = 5 * time.Second

// leaveOnShutdown deregisters from discovery, giving up after leaveTimeout. The
// goroutine outlives the wait, but only until the process exits moments later.
func leaveOnShutdown(roster *peerRoster) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		roster.leave()
	}()
	select {
	case <-done:
	case <-time.After(leaveTimeout):
	}
}

// runSessionDaemon owns the live session: it registers with the discovery
// endpoint, brings up the TUN device, and pumps packets until quit. It returns
// only once the session is torn down.
func runSessionDaemon(p daemonParams) {
	pidFile := sessionPIDFile()
	utils.WriteStateFile(pidFile, fmt.Appendf(nil, "%d", os.Getpid()), 0600)
	// A session that was killed rather than shut down leaves its peer list
	// behind, and this one only rewrites the file once a peer connects. Clearing
	// it up front stops `blindspot list` from reporting the previous session's
	// peers — addresses nothing is listening on any more — as though they were
	// live members of this one.
	os.Remove(peersFile())

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
		roster     *peerRoster
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
			leaveOnShutdown(roster)
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

	roster = newPeerRoster(p.discovery, peerConn, publicAddr, myPubKeyB64)
	peers, err := roster.join(p.createSession)
	if err != nil {
		writeStatus("error: " + err.Error())
		return
	}
	registered = true

	myVirtualIP := bstun.VirtualIPv4(publicKey)
	tunDevice, err = bstun.Create(myVirtualIP)
	if err != nil {
		writeStatus("error: creating TUN interface: " + err.Error())
		return
	}

	for _, peer := range peers {
		roster.add(peer)
	}
	go roster.keepRegistered(quit, nil)
	go roster.followStream(quit, nil)
	go roster.keepMappingAlive(quit, nil)

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
				roster.forget(addr)
			}
		}
	}()

	// TUN-side counters for the stats log: what enters from the OS, what is
	// written back to the OS, and what the reverse-path filter rejects.
	var tunInPkts, tunInBytes, tunOutPkts, tunOutBytes, rpfDrops, noPeerDrops, tunWriteErrs atomic.Uint64

	// Stats logger: once per second, append a delta line to stats.log while
	// there is tunnel activity. Comparing this file across the two machines
	// shows exactly where packets die: sender tx vs receiver rx is path
	// loss; rx vs tun_out is local processing loss; dec_fail/replay/rekey
	// indicate session-level trouble.
	go func() {
		logPath := filepath.Join(utils.GetBlindspotDir(), "stats.log")
		f, err := utils.CreateStateFile(logPath, 0600)
		if err != nil {
			return
		}
		defer f.Close()
		type snap struct {
			txP, txB, txE, rxP, rxB, dec, rep, rek, tmo uint64
			tiP, tiB, toP, toB, rpf, nop, tunErr        uint64
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
				rpfDrops.Load(), noPeerDrops.Load(), tunWriteErrs.Load(),
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
					"%s tun_in=%d/%dB tx=%d/%dB txerr=%d | rx=%d/%dB tun_out=%d/%dB dec_fail=%d replay=%d rpf=%d nopeer=%d tunerr=%d | rekey=%d timeout=%d pace=%dbps\n",
					time.Now().Format("15:04:05"),
					cur.tiP-prev.tiP, cur.tiB-prev.tiB, cur.txP-prev.txP, cur.txB-prev.txB, cur.txE-prev.txE,
					cur.rxP-prev.rxP, cur.rxB-prev.rxB, cur.toP-prev.toP, cur.toB-prev.toB,
					cur.dec-prev.dec, cur.rep-prev.rep, cur.rpf-prev.rpf, cur.nop-prev.nop, cur.tunErr-prev.tunErr,
					cur.rek-prev.rek, cur.tmo-prev.tmo, network.Stats.PaceBps.Load()*8)
				prev = cur
			}
		}
	}()

	// tunBufPool recycles packet buffers across both pump directions so the
	// steady state allocates nothing per packet. Each buffer carries
	// tun.WriteOffset bytes of headroom on top of the packet itself, so a
	// decrypted packet can go to the TUN device without being copied.
	tunBufPool := sync.Pool{New: func() any {
		b := make([]byte, bstun.WriteOffset+1600)
		return &b
	}}
	getTunBuf := func() []byte { return *tunBufPool.Get().(*[]byte) }
	putTunBuf := func(b []byte) {
		if cap(b) >= bstun.WriteOffset+1600 {
			b = b[:bstun.WriteOffset+1600]
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
			n, err := peerConn.ReadTunBatch(bufs, senders, bstun.WriteOffset)
			if err != nil {
				return // transport closed
			}
			wr = wr[:0]
			for i := 0; i < n; i++ {
				// Each buffer is [headroom][packet]; the packet alone is what the
				// filter and the counters are about.
				packet := bufs[i][bstun.WriteOffset:]
				// Reverse-path filter: the inner IPv4 source address must equal the
				// sender's virtual IP. Otherwise a malicious member could inject packets
				// spoofing another peer's virtual IP inside the (authenticated) tunnel.
				expectedVIP, ok := addrToVIP.Load(senders[i])
				if !ok || !bstun.SrcIPMatchesVirtualIP(packet, expectedVIP.(string)) {
					rpfDrops.Add(1)
					continue
				}
				wr = append(wr, bufs[i])
				tunOutPkts.Add(1)
				tunOutBytes.Add(uint64(len(packet)))
			}
			if len(wr) == 0 {
				continue
			}
			network.UpdateLastSeen()
			if _, err := tunDevice.Write(wr, bstun.WriteOffset); err != nil {
				// Counted, not logged per packet: a device that rejects writes
				// rejects every one of them, and this is the last step before the
				// local network stack — silence here is a tunnel that looks
				// connected while nothing ever arrives.
				tunWriteErrs.Add(1)
			}
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
