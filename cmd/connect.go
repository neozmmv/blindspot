package cmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/neozmmv/blindspot/internal/network"
	"github.com/neozmmv/blindspot/internal/session"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

func sessionPIDFile() string  { return filepath.Join(utils.GetBlindspotDir(), "session.pid") }
func sessionStopFile() string { return filepath.Join(utils.GetBlindspotDir(), "session.stop") }

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
			if _, err := os.Stat(sessionPIDFile()); err == nil {
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
			child := exec.Command(os.Args[0], childArgs...)
			child.Stdin = nil
			child.Stdout = nil
			child.Stderr = nil
			if err := child.Start(); err != nil {
				fmt.Println("Error starting background process:", err)
				return
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
						child.Process.Kill()
					}
					return
				}
				time.Sleep(200 * time.Millisecond)
			}
			fmt.Println("Timed out waiting for connection.")
			child.Process.Kill()
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
			registered bool
		)
		quit := make(chan struct{})
		var quitOnce sync.Once
		closeQuit := func() { quitOnce.Do(func() { close(quit) }) }

		defer func() {
			if registered {
				session.Leave(hostname, sessionId, password, publicAddr)
			}
			if peerConn != nil {
				peerConn.BroadcastRaw([]byte{network.PacketDead})
			}
			conn.Close()
			os.Remove(pidFile)
			os.Remove(sessionStopFile())
		}()

		peers, err := session.Register(hostname, sessionId, password, publicAddr, isNew)
		if err != nil {
			writeStatus("error: " + err.Error())
			return
		}
		registered = true

		myPublicIP := strings.Split(publicAddr, ":")[0]
		peerConn = network.NewPeerConn(conn, privateKey, publicKey)

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
			knownPeers[peerAddrStr] = true
			go peerConn.PunchHole(peerAddr)
		}

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
				go peerConn.PunchHole(peerAddr)
			}
		}()

		go func() {
			for {
				_, _, err := peerConn.Read()
				if err != nil {
					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					continue
				}
				network.UpdateLastSeen()
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
		signal.Notify(sigCh, os.Interrupt)
		go func() {
			<-sigCh
			closeQuit()
		}()

		writeStatus("ok")

		// start keepalive and watchdog only after first peer connects
		go func() {
			for range peerConn.Connected {
				network.UpdateLastSeen()
				go network.KeepAliveAll(peerConn)
				go func() {
					if err := network.WatchConnection(conn); err != nil {
						closeQuit()
					}
				}()
				return
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
