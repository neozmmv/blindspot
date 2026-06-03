package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"

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
		create, _ := cmd.Flags().GetBool("create")

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

		peers, err := session.Register(hostname, sessionId, password, publicAddr, create)
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
			go peerConn.PunchHole(peerAddr)
		}

		quit := make(chan struct{})

		// single read loop
		go func() {
			for {
				plaintext, addr, err := peerConn.Read()
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
				fmt.Printf("\n[%s]: %s\n> ", addr, string(plaintext))
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
		<-atLeastOne
		fmt.Println("Connected! Type to chat.")

		go network.KeepAliveAll(peerConn)

		// watch connection
		go func() {
			if err := network.WatchConnection(conn); err != nil {
				fmt.Println("Connection lost, exiting chat...")
				close(quit)
			}
		}()

		// handle Ctrl+C
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		go func() {
			<-sigCh
			fmt.Println("\nDisconnecting...")
			close(quit)
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
	ChatCmd.Flags().BoolP("create", "c", false, "Create session with password")
	ChatCmd.MarkFlagRequired("session")
}
