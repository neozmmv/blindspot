package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
	"github.com/neozmmv/blindspot/internal/network"
	"github.com/neozmmv/blindspot/internal/session"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

var ChatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Chat with a peer in the blindspot network",
	Run: func(cmd *cobra.Command, args []string) {
		hostname, _ := cmd.Flags().GetString("hostname")
		sessionId, _ := cmd.Flags().GetString("session")
		password, _ := cmd.Flags().GetString("password")
		new, _ := cmd.Flags().GetBool("new")
		insecure, _ := cmd.Flags().GetBool("insecure")

		if len(password) < 8 && new {
			fmt.Println("Password must be at least 8 characters long")
			return
		}

		// Resolve the rendezvous URL and refuse plaintext http:// unless --insecure.
		hostname, err := session.NormalizeHostname(hostname, insecure)
		if err != nil {
			fmt.Println(err)
			return
		}

		privateKey, publicKey, err := utils.ReadIdentity()
		if err != nil {
			keyPair, err := utils.InitIdentity()
			if err != nil {
				fmt.Println("Error initializing identity:", err)
				return
			}
			privateKey = keyPair.PrivateKey
			publicKey = keyPair.PublicKey
		}

		// PSK second factor + Noise prologue, and our published static pubkey.
		psk := crypto.DerivePSK(password, sessionId)
		prologue := network.Prologue(sessionId)
		myPubKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

		tr, err := network.OpenTransport()
		if err != nil {
			fmt.Println("Error opening UDP transport:", err)
			return
		}
		peerConn := network.NewPeerConn(tr, privateKey, publicKey, psk, prologue)

		publicAddr, err := peerConn.DiscoverPublicAddr()
		if err != nil {
			fmt.Println("Error discovering public address:", err)
			peerConn.Close()
			return
		}
		fmt.Println("Public addr:", publicAddr)

		peers, err := session.Register(hostname, sessionId, password, publicAddr, myPubKeyB64, new)
		if err != nil {
			fmt.Printf("Error registering: %v\n", err)
			peerConn.Close()
			return
		}

		myPublicIP := strings.Split(publicAddr, ":")[0]

		defer func() {
			session.Leave(hostname, sessionId, password, publicAddr)
			peerConn.BroadcastDead() // encrypted "dead" notice so peers tear down promptly
			peerConn.Close()         // stop handshake drivers/consumers and close the bind
		}()

		// knownPeers tracks which resolved peer addresses have been handed to
		// AddKnownPeer; entries are removed when a peer dies so it can rejoin later.
		// Guarded by peersMu: it is touched by the initial loop, the SSE stream, the
		// periodic re-register, and the Dead handler.
		var peersMu sync.Mutex
		knownPeers := make(map[string]bool)

		// addPeer validates a rendezvous-announced peer and, if it is new, registers
		// its pinned static key and kicks off the Noise handshake. It reports the
		// chosen address and whether the peer was newly added, so callers can print.
		addPeer := func(peer session.PeerAddr) (string, bool) {
			peerAddrStr := peer.Public
			if strings.Split(peer.Public, ":")[0] == myPublicIP && peer.Local != "" {
				peerAddrStr = peer.Local
			}
			peerAddr, err := net.ResolveUDPAddr("udp", peerAddrStr)
			if err != nil {
				return peerAddrStr, false
			}
			if !network.IsValidPeerAddr(peerAddr) {
				return peerAddrStr, false // reject broadcast/multicast/unspecified IPs and privileged ports
			}
			pub, err := base64.StdEncoding.DecodeString(peer.PubKey)
			if err != nil || len(pub) != 32 {
				return peerAddrStr, false // no valid pubkey from the rendezvous → cannot handshake
			}
			peersMu.Lock()
			if knownPeers[peerAddr.String()] {
				peersMu.Unlock()
				return peerAddrStr, false
			}
			knownPeers[peerAddr.String()] = true
			peersMu.Unlock()
			peerConn.AddKnownPeer(peerAddr, pub)
			return peerAddrStr, true
		}

		for _, peer := range peers {
			if strings.Split(peer.Public, ":")[0] == myPublicIP && peer.Local != "" {
				fmt.Printf("Same network detected, connecting locally to %s\n", peer.Public)
			}
			if addrStr, added := addPeer(peer); added {
				fmt.Printf("Peer addr: %s\n", addrStr)
			}
		}

		quit := make(chan struct{})

		// handle Ctrl+C — set up early so quit is closed even while waiting for peers
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		go func() {
			<-sigCh
			fmt.Println("\nDisconnecting...")
			close(quit)
		}()

		// Peer death (graceful CtrlDead or keepalive timeout) arrives on the Dead
		// channel; forget the peer so it can reconnect via a fresh announcement.
		go func() {
			for {
				select {
				case <-quit:
					return
				case addr := <-peerConn.Dead:
					fmt.Printf("\n[%s] disconnected.\n> ", addr)
					peersMu.Lock()
					delete(knownPeers, addr.String())
					peersMu.Unlock()
				}
			}
		}()

		// Periodically re-register so the rendezvous TTL doesn't expire mid-chat;
		// the response also re-announces peers we may have dropped or missed.
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-quit:
					return
				case <-ticker.C:
					if current, err := session.Register(hostname, sessionId, password, publicAddr, myPubKeyB64, false); err == nil {
						for _, peer := range current {
							addPeer(peer)
						}
					}
				}
			}
		}()

		peerStream := session.StreamPeers(hostname, sessionId, password, publicAddr, quit)
		go func() {
			for peer := range peerStream {
				if addrStr, added := addPeer(peer); added {
					fmt.Printf("\nNew peer discovered: %s\n> ", addrStr)
				}
			}
		}()

		// single read loop
		go func() {
			for {
				pktType, plaintext, addr, err := peerConn.Read()
				if err != nil {
					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					continue
				}
				if pktType != network.PacketData {
					continue
				}
				// go time format is the dumbest thing i've ever seen
				// like wdym "15:04:05" instead of like "HH:mm:ss"
				fmt.Printf("\n[%s] - [%s]: %s\n> ", time.Now().Format(time.TimeOnly), addr, string(plaintext))
				network.UpdateLastSeen()
			}
		}()

		// notify as peers join
		atLeastOne := make(chan struct{}, 1)
		go func() {
			for addr := range peerConn.Connected {
				fmt.Printf("\n%s joined!\n> ", addr)
				network.UpdateLastSeen()
				select {
				case atLeastOne <- struct{}{}:
				default:
				}
			}
		}()

		fmt.Println("Waiting for peers...")
		select {
		case <-atLeastOne:
		case <-quit:
			return
		}
		fmt.Println("Connected! Type to chat.")

		go network.KeepAliveAll(peerConn)

		// watch connection
		go func() {
			if err := network.WatchConnection(peerConn.HasPeers); err != nil {
				fmt.Println("Connection lost, exiting chat...")
				close(quit)
			}
		}()

		// reads from stdin
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("> ")
			if !scanner.Scan() {
				break
			}
			text := scanner.Text()
			if strings.TrimSpace(text) == "" {
				continue
			}
			if strings.TrimSpace(text) == "/quit" || strings.TrimSpace(text) == "/exit" {
				fmt.Println("Disconnecting...")
				break
			}
			select {
			case <-quit:
				return
			default:
				peerConn.Broadcast([]byte(text))
			}
		}

		// wait for quit signal if not already received
		select {
		case <-quit:
		default:
		}

		if scanner.Err() != nil {
			fmt.Println("Error reading from stdin:", scanner.Err())
		}
	},
}

func init() {
	ChatCmd.Flags().StringP("hostname", "H", "", "Rendezvous server hostname")
	ChatCmd.Flags().StringP("session", "s", "", "Session ID")
	ChatCmd.Flags().StringP("password", "p", "", "Session password")
	ChatCmd.Flags().BoolP("new", "n", false, "Create new session with password")
	ChatCmd.Flags().Bool("insecure", false, "Allow a plaintext http:// rendezvous (NOT recommended)")
	ChatCmd.MarkFlagRequired("session")
}
