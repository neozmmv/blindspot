package cmd

import (
	"fmt"
	"net"

	"github.com/neozmmv/blindspot/internal/crypto"
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
			// if identity doesn't exist, create one and save it
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

		// register with the rendezvous server and wait for the peer
		peerAddrStr, err := session.Register(hostname, sessionId, password, publicAddr, create)
		if err != nil {
			fmt.Println("Error registering:", err)
			return
		}

		fmt.Println("Peer addr:", peerAddrStr)

		// gets peer address
		peerAddr, err := net.ResolveUDPAddr("udp", peerAddrStr)
		if err != nil {
			fmt.Println("Error resolving peer address:", err)
			return
		}

		// hole punching + handshake
		go network.PunchHole(conn, peerAddr, publicKey)
		peerPublicKey, err := network.WaitForHello(conn)
		if err != nil {
			fmt.Println("Error waiting for hello:", err)
			return
		}

		// derive shared key
		sharedKey, err := crypto.DeriveSharedKey(privateKey, peerPublicKey)
		if err != nil {
			fmt.Println("Error deriving shared key:", err)
			return
		}

		fmt.Println("Connected! Shared key:", sharedKey[:8], "...")
	},
}

func init() {
	ConnectCmd.Flags().StringP("hostname", "H", "", "Rendezvous server hostname")
	ConnectCmd.Flags().StringP("session", "s", "", "Session ID")
	ConnectCmd.Flags().StringP("password", "p", "", "Session password")
	ConnectCmd.Flags().BoolP("create", "c", false, "Create session with password")
	ConnectCmd.MarkFlagRequired("session")
}
