package cmd

import (
	"fmt"
	"net"
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

		// loads identity (private key + public key)
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

		// open UDP connection and get public address
		conn, publicAddr, err := network.OpenUDPConn()
		if err != nil {
			fmt.Println("Error opening UDP connection:", err)
			return
		}
		defer conn.Close()

		fmt.Println("Public addr:", publicAddr)

		// register with the rendezvous server
		peers, err := session.Register(hostname, sessionId, password, publicAddr, create)
		if err != nil {
			fmt.Println("Error registering:", err)
			return
		}

		myPublicIP := strings.Split(publicAddr, ":")[0]

		peerConn := network.NewPeerConn(conn, privateKey, publicKey)

		// hole punching with all peers
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

		// listens for HELLO from peers

		go func() {
			for {
				peerConn.Read()
			}
		}()

		// wait for first peer to connect
		connectedAddr := <-peerConn.Connected
		fmt.Printf("%s connected!\n", connectedAddr)
		network.UpdateLastSeen()

		// just block to keep the connection
		// this will be the vpn connection
		// not fully done yet
		select {}
	},
}

func init() {
	ConnectCmd.Flags().StringP("hostname", "H", "", "Rendezvous server hostname")
	ConnectCmd.Flags().StringP("session", "s", "", "Session ID")
	ConnectCmd.Flags().StringP("password", "p", "", "Session password")
	ConnectCmd.Flags().BoolP("create", "c", false, "Create session with password")
	ConnectCmd.MarkFlagRequired("session")
}
