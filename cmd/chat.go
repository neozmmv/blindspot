package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"

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
		peerPublicAddrStr, peerLocalAddrStr, err := session.Register(hostname, sessionId, password, publicAddr, create)
		if err != nil {
			fmt.Println("Error registering:", err)
			return
		}

		myPublicAddr := strings.Split(publicAddr, ":")[0]
		peerPublicAddr := strings.Split(peerPublicAddrStr, ":")[0]

		var peerAddrStr string

		if myPublicAddr == peerPublicAddr {
			peerAddrStr = peerLocalAddrStr
		} else {
			peerAddrStr = peerPublicAddrStr
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

		network.UpdateLastSeen()

		fmt.Println("Connected! Shared key:", sharedKey[:8], "...")

		// keeps reading from peer
		go func() {
			for {
				plaintext, _, err := network.ReadFromPeer(conn, sharedKey)
				if err != nil {
					// suppress expected errors on client disconnect
					if strings.Contains(err.Error(), "peer is dead") {
						fmt.Println("Peer has disconnected.")
						os.Exit(0)
					}
					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					fmt.Println("Error reading from peer:", err)
					return
				}
				fmt.Println("Peer:", string(plaintext))
				network.UpdateLastSeen()
			}
		}()

		// send keepalive every 10s
		go network.KeepAlive(conn, peerAddr)

		// go network.WatchConnection(conn)

		go func() {
			if err := network.WatchConnection(conn); err != nil {
				fmt.Println("Connection lost, exiting chat...")
				os.Exit(0)
			}
		}()

		// handle shutdown gracefully
		// sends 0x05 (DEAD) to peer before closing connection
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt) // works on linux
		// windows is dumb asf and doesnt work
		// there is nothing we can do about it, as far as i know :(
		go func() {
			<-sigCh
			fmt.Println("\nDisconnecting from peer...")
			conn.WriteToUDP([]byte{network.PacketDead}, peerAddr)
			conn.Close()
			os.Exit(0)
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

			if err := network.SendToPeer(conn, peerAddr, sharedKey, []byte(text)); err != nil {
				fmt.Println("Error sending to peer:", err)
			}
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
