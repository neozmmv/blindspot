package cmd

import (
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

var ConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to a blindspot network",
	Run: func(cmd *cobra.Command, args []string) {
		hostname, _ := cmd.Flags().GetString("hostname")
		sessionId, _ := cmd.Flags().GetString("session")
		password, _ := cmd.Flags().GetString("password")
		create, _ := cmd.Flags().GetBool("create")

		if len(password) < 8 && create {
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

		peers, err := session.Register(hostname, sessionId, password, publicAddr, create)
		if err != nil {
			fmt.Println("Error registering:", err)
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
				fmt.Printf("\nNew peer discovered: %s\n", peerAddrStr)
				go peerConn.PunchHole(peerAddr)
			}
		}()

		go func() {
			for {
				_, addr, err := peerConn.Read()
				if err != nil {
					if strings.Contains(err.Error(), "peer is dead") {
						fmt.Printf("\n[%s] disconnected.\n", addr)
						continue
					}
					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					continue
				}
				network.UpdateLastSeen()
			}
		}()

		atLeastOne := make(chan struct{}, 1)
		go func() {
			for addr := range peerConn.Connected {
				fmt.Printf("\n%s joined!\n", addr)
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
		fmt.Println("Connected!")

		go network.KeepAliveAll(peerConn)

		go func() {
			if err := network.WatchConnection(conn); err != nil {
				fmt.Println("Connection lost, exiting...")
				close(quit)
			}
		}()

		<-quit
	},
}

func init() {
	ConnectCmd.Flags().StringP("hostname", "H", "", "Rendezvous server hostname")
	ConnectCmd.Flags().StringP("session", "s", "", "Session ID")
	ConnectCmd.Flags().StringP("password", "p", "", "Session password")
	ConnectCmd.Flags().BoolP("create", "c", false, "Create session with password")
	ConnectCmd.MarkFlagRequired("session")
}
