package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
	"github.com/neozmmv/blindspot/internal/network"
	"github.com/neozmmv/blindspot/internal/session"
	bstun "github.com/neozmmv/blindspot/internal/tun"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

func sessionPIDFile() string  { return filepath.Join(utils.GetBlindspotDir(), "session.pid") }
func sessionStopFile() string { return filepath.Join(utils.GetBlindspotDir(), "session.stop") }
func peersFile() string       { return filepath.Join(utils.GetBlindspotDir(), "peers.json") }

// isSessionRunning returns true only if the session PID file exists AND the recorded
// process is still alive. If the file exists but the process is gone (e.g. after an
// unclean shutdown), the stale files are removed and false is returned.
func isSessionRunning() bool {
	data, err := os.ReadFile(sessionPIDFile())
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || !isProcessAlive(pid) {
		os.Remove(sessionPIDFile())
		os.Remove(sessionStopFile())
		os.Remove(peersFile())
		return false
	}
	return true
}

type PeerEntry struct {
	VirtualIP  string `json:"virtual_ip"`
	PublicAddr string `json:"public_addr"`
}

func writePeers(m *sync.Map) {
	var entries []PeerEntry
	m.Range(func(k, v any) bool {
		entries = append(entries, PeerEntry{
			VirtualIP:  k.(string),
			PublicAddr: v.(*net.UDPAddr).String(),
		})
		return true
	})
	data, _ := json.Marshal(entries)
	os.WriteFile(peersFile(), data, 0600)
}

var ConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to a blindspot network",
	Run: func(cmd *cobra.Command, args []string) {
		hostname, _ := cmd.Flags().GetString("hostname")
		sessionId, _ := cmd.Flags().GetString("session")
		password, _ := cmd.Flags().GetString("password")
		isNew, _ := cmd.Flags().GetBool("new")
		daemon, _ := cmd.Flags().GetBool("daemon")
		statusFile, _ := cmd.Flags().GetString("status-file")

		if len(password) < 8 && isNew {
			fmt.Println("Password must be at least 8 characters long")
			return
		}

		if !daemon {
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

			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				if data, err := os.ReadFile(statusPath); err == nil && len(data) > 0 {
					os.Remove(statusPath)
					msg := strings.TrimSpace(string(data))
					if msg == "ok" {
						fmt.Printf("Connected to network %s\n", sessionId)
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
			return
		}

		// --- daemon mode ---

		pidFile := sessionPIDFile()
		os.MkdirAll(filepath.Dir(pidFile), 0700)
		os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0600)

		writeStatus := func(msg string) {
			if statusFile != "" {
				os.WriteFile(statusFile, []byte(msg), 0600)
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

		conn, publicAddr, err := network.OpenUDPConn()
		if err != nil {
			writeStatus("error: opening UDP connection: " + err.Error())
			os.Remove(pidFile)
			return
		}

		// from here on, defer owns all cleanup
		var (
			peerConn   *network.PeerConn
			tunDevice  bstun.Device
			registered bool
		)
		quit := make(chan struct{})
		var quitOnce sync.Once
		closeQuit := func() { quitOnce.Do(func() { close(quit) }) }

		defer func() {
			if tunDevice != nil {
				tunDevice.Close()
			}
			exec.Command("route", "delete", "10.0.0.0", "mask", "255.0.0.0").Run() // best effort cleanup of route
			if registered {
				session.Leave(hostname, sessionId, password, publicAddr)
			}
			if peerConn != nil {
				peerConn.BroadcastDead() // encrypted "dead" notice so peers tear down promptly
				peerConn.Shutdown()      // stop any in-flight handshake drivers
			}
			conn.Close()
			os.Remove(pidFile)
			os.Remove(sessionStopFile())
			os.Remove(peersFile())
		}()

		// PSK (second factor) from the password via Argon2id, salted with the session
		// id; prologue binds the Noise handshake to protocol version + session. Our
		// static pubkey is published to the rendezvous so peers can pin it beforehand.
		psk := crypto.DerivePSK(password, sessionId)
		prologue := network.Prologue(sessionId)
		myPubKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

		peers, err := session.Register(hostname, sessionId, password, publicAddr, myPubKeyB64, isNew)
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

		myPublicIP := strings.Split(publicAddr, ":")[0]
		peerConn = network.NewPeerConn(conn, privateKey, publicKey, psk, prologue)

		knownPeers := make(map[string]bool)

		for _, peer := range peers {
			peerAddrStr := peer.Public
			if strings.Split(peer.Public, ":")[0] == myPublicIP && peer.Local != "" {
				peerAddrStr = peer.Local
			}
			peerAddr, err := net.ResolveUDPAddr("udp", peerAddrStr)
			if err != nil {
				continue
			}
			if !network.IsValidPeerAddr(peerAddr) {
				continue // reject broadcast/multicast/unspecified IPs and privileged ports
			}
			pub, err := base64.StdEncoding.DecodeString(peer.PubKey)
			if err != nil || len(pub) != 32 {
				continue // no valid pubkey from the rendezvous → cannot handshake
			}
			knownPeers[peerAddrStr] = true
			// Register the rendezvous-pinned static key and kick off the Noise handshake.
			peerConn.AddKnownPeer(peerAddr, pub)
		}

		// Periodically re-register to keep the rendezvous session TTL alive.
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-quit:
					return
				case <-ticker.C:
					session.Register(hostname, sessionId, password, publicAddr, myPubKeyB64, false)
				}
			}
		}()

		peerStream := session.StreamPeers(hostname, sessionId, password, publicAddr, quit)
		go func() {
			for peer := range peerStream {
				peerAddrStr := peer.Public
				if strings.Split(peer.Public, ":")[0] == myPublicIP && peer.Local != "" {
					peerAddrStr = peer.Local
				}
				if knownPeers[peerAddrStr] {
					continue
				}
				peerAddr, err := net.ResolveUDPAddr("udp", peerAddrStr)
				if err != nil {
					continue
				}
				if !network.IsValidPeerAddr(peerAddr) {
					continue // reject broadcast/multicast/unspecified IPs and privileged ports
				}
				pub, err := base64.StdEncoding.DecodeString(peer.PubKey)
				if err != nil || len(pub) != 32 {
					continue // no valid pubkey from the rendezvous → cannot handshake
				}
				knownPeers[peerAddrStr] = true
				peerConn.AddKnownPeer(peerAddr, pub)
			}
		}()

		// virtualIPMap maps each peer's virtual IP to their UDP address for TUN routing
		var virtualIPMap sync.Map

		go func() {
			for {
				select {
				case <-quit:
					return
				case addr := <-peerConn.Dead:
					virtualIPMap.Range(func(k, v any) bool {
						if v.(*net.UDPAddr).String() == addr.String() {
							virtualIPMap.Delete(k)
							return false
						}
						return true
					})
					writePeers(&virtualIPMap)
				}
			}
		}()

		// UDP → TUN: decrypt incoming packets and write into the TUN interface
		go func() {
			for {
				pktType, plaintext, addr, err := peerConn.Read()
				if err != nil {
					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					if strings.Contains(err.Error(), "peer is dead") && addr != nil {
						virtualIPMap.Range(func(k, v any) bool {
							if v.(*net.UDPAddr).String() == addr.String() {
								virtualIPMap.Delete(k)
								return false
							}
							return true
						})
						writePeers(&virtualIPMap)
					}
					continue
				}
				if pktType != network.PacketTun {
					continue
				}
				network.UpdateLastSeen()
				tunDevice.Write([][]byte{plaintext}, 0)
			}
		}()

		// TUN → UDP: read outbound IP packets and route to the right peer
		go func() {
			batchSize := tunDevice.BatchSize()
			bufs := make([][]byte, batchSize)
			sizes := make([]int, batchSize)
			for i := range bufs {
				bufs[i] = make([]byte, 1500)
			}
			for {
				n, err := tunDevice.Read(bufs, sizes, 0)
				if err != nil {
					return // TUN closed
				}
				for i := 0; i < n; i++ {
					packet := bufs[i][:sizes[i]]
					if len(packet) < 20 || packet[0]>>4 != 4 {
						continue // not an IPv4 packet
					}
					destIP := net.IP(packet[16:20]).String()
					addrVal, ok := virtualIPMap.Load(destIP)
					if !ok {
						continue // no peer with that virtual IP
					}
					peerConn.SendTun(addrVal.(*net.UDPAddr), packet)
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
					virtualIPMap.Store(bstun.VirtualIPv4(pubKey), addr)
					writePeers(&virtualIPMap)
				}
				if first {
					first = false
					go network.KeepAliveAll(peerConn)
				}
			}
		}()

		<-quit
	},
}

func init() {
	ConnectCmd.Flags().StringP("hostname", "H", "", "Rendezvous server hostname")
	ConnectCmd.Flags().StringP("session", "s", "", "Session ID")
	ConnectCmd.Flags().StringP("password", "p", "", "Session password")
	ConnectCmd.Flags().BoolP("new", "n", false, "Create new session with password")
	ConnectCmd.MarkFlagRequired("session")
	ConnectCmd.Flags().Bool("daemon", false, "")
	ConnectCmd.Flags().String("status-file", "", "")
	ConnectCmd.Flags().MarkHidden("daemon")
	ConnectCmd.Flags().MarkHidden("status-file")
}
