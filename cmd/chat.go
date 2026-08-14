package cmd

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
	"github.com/neozmmv/blindspot/internal/network"
	"github.com/neozmmv/blindspot/internal/roomkey"
	"github.com/neozmmv/blindspot/internal/roomserver"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

var ChatCmd = &cobra.Command{
	Use:   "chat <name> <password>",
	Short: "Chat with peers in a serverless room, discovered over Tor",
	Long: `Chat with everyone who joins a room identified only by a name and password.

Discovery works exactly as it does for 'blindspot connect': both strings are fed
through Argon2id to derive a Tor v3 onion service key, so every peer that knows
the pair computes the same .onion address with no DNS and no rendezvous server.
Whoever arrives first hosts the room; the others join it. Messages themselves
never touch Tor — they go peer-to-peer over the encrypted UDP transport, same as
in VPN mode.

Unlike 'connect', this needs no TUN device and so no administrator privileges.

The name must be at least 4 characters and the password at least 8. Those are
minimums, not advice: the password is the only thing protecting the room, and
guessing it is an offline exercise nobody can rate-limit, so prefer a passphrase.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		name, password := args[0], args[1]
		if err := roomkey.Validate(name, password); err != nil {
			fmt.Println(err)
			return
		}
		runChatRoom(name, password)
	},
}

// runChatRoom joins the room over Tor and runs the chat session on top of it.
//
// Unlike `connect`, this stays in the foreground: there is no daemon to
// supervise and no status file, so progress goes straight to stdout.
func runChatRoom(name, password string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The room supervisor keeps reporting (a host stepping down, a takeover)
	// long after startup, by which point the user is at a "> " prompt. Once the
	// session is live those messages have to break the line and redraw the
	// prompt, the same as an incoming message does.
	var live atomic.Bool
	progress := func(msg string) {
		if live.Load() {
			fmt.Printf("\n%s\n> ", msg)
			return
		}
		fmt.Println("  " + msg)
	}

	fmt.Println("Deriving room address and starting Tor; this can take a minute...")
	room, err := joinRoom(ctx, name, password, roomserver.ModeChat, progress)
	if err != nil {
		fmt.Println("Error joining room:", err)
		return
	}
	defer room.close()

	runChatSession(room.ref, name, password, &live)
}

// runChatSession runs the chat itself against an already-joined room: it
// announces this peer, connects to everyone the room reports, and pumps stdin
// and incoming messages until the user quits or the last peer disappears.
func runChatSession(ref *discoveryRef, roomName, password string, live *atomic.Bool) {
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

	// PSK second factor + Noise prologue, and our published static pubkey. The
	// PSK comes from the same password as the onion address, so it is not an
	// independent factor here; it still covers the case where the address leaks
	// without the password.
	//
	// The chat prologue is what makes a handshake with a VPN peer impossible
	// rather than merely unlikely — see network.ChatPrologue.
	psk := crypto.DerivePSK(password, roomName)
	prologue := network.ChatPrologue(roomName)
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

	roster := newPeerRoster(ref, peerConn, publicAddr, myPubKeyB64)
	// Onion rooms have no server-side session to create.
	peers, err := roster.join(false)
	if err != nil {
		fmt.Printf("Error registering: %v\n", err)
		peerConn.Close()
		return
	}

	defer func() {
		roster.leave()
		peerConn.BroadcastDead() // encrypted "dead" notice so peers tear down promptly
		peerConn.Close()         // stop handshake drivers/consumers and close the bind
	}()

	for _, peer := range peers {
		addrStr, added := roster.add(peer)
		if !added {
			continue
		}
		if addrStr != peer.Public {
			fmt.Printf("Same network detected, connecting locally to %s\n", addrStr)
		}
		fmt.Printf("Peer addr: %s\n", addrStr)
	}

	quit := make(chan struct{})
	var quitOnce sync.Once
	closeQuit := func() {
		quitOnce.Do(func() {
			close(quit)
			// Unblock the stdin scanner below. Without this the session — and
			// the Tor process behind it — would stay up until the user also
			// pressed Enter, since Scan is blocked and signal.Notify has taken
			// the interrupt away from the runtime.
			os.Stdin.Close()
		})
	}

	// handle Ctrl+C — set up early so quit is closed even while waiting for peers
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nDisconnecting...")
		closeQuit()
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
				roster.forget(addr)
			}
		}
	}()

	announce := func(addrStr string) { fmt.Printf("\nNew peer discovered: %s\n> ", addrStr) }
	go roster.keepRegistered(quit, announce)
	go roster.followStream(quit, announce)

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
			closeQuit()
		}
	}()

	// From here the prompt owns the last line, so anything printed from another
	// goroutine — including the room supervisor's — has to redraw it.
	live.Store(true)

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

	// A scanner error after quit is just the closed stdin that unblocked it, and
	// reporting it would bury the reason the session actually ended.
	select {
	case <-quit:
	default:
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading from stdin:", err)
		}
	}
}
