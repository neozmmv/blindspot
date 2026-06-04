package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

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

		if len(password) < 8 && new {
			fmt.Println("Password must be at least 8 characters long")
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

		conn, publicAddr, err := network.OpenUDPConn()
		if err != nil {
			fmt.Println("Error opening UDP connection:", err)
			return
		}

		fmt.Println("Public addr:", publicAddr)

		peers, err := session.Register(hostname, sessionId, password, publicAddr, new)
		if err != nil {
			fmt.Printf("Error registering: %v\n", err)
			conn.Close()
			return
		}

		myPublicIP := strings.Split(publicAddr, ":")[0]
		peerConn := network.NewPeerConn(conn, privateKey, publicKey)

		defer func() {
			session.Leave(hostname, sessionId, password, publicAddr)
			peerConn.BroadcastRaw([]byte{network.PacketDead})
			conn.Close()
		}()

		knownPeers := make(map[string]bool)

		for _, peer := range peers {
			peerAddrStr := peer.Public
			if strings.Split(peer.Public, ":")[0] == myPublicIP && peer.Local != "" {
				fmt.Printf("Same network detected, connecting locally to %s\n", peer.Public)
				peerAddrStr = peer.Local
			}
			peerAddr, err := net.ResolveUDPAddr("udp", peerAddrStr)
			if err != nil {
				fmt.Printf("Error resolving peer address: %v\n", err)
				continue
			}
			fmt.Printf("Peer addr: %s\n", peerAddrStr)
			knownPeers[peerAddrStr] = true
			go peerConn.PunchHole(peerAddr)
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
				knownPeers[peerAddrStr] = true
				peerAddr, err := net.ResolveUDPAddr("udp", peerAddrStr)
				if err != nil {
					continue
				}
				fmt.Printf("\nNew peer discovered: %s\n> ", peerAddrStr)
				go peerConn.PunchHole(peerAddr)
			}
		}()

		// single read loop
		go func() {
			for {
				pktType, plaintext, addr, err := peerConn.Read()
				if err != nil {
					if strings.Contains(err.Error(), "peer is dead") {
						fmt.Printf("\n[%s] disconnected.\n> ", addr)
						continue
					}
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
			if err := network.WatchConnection(conn, peerConn.HasPeers); err != nil {
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
	ChatCmd.MarkFlagRequired("session")
}
