package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/neozmmv/blindspot/internal/roomkey"
	"github.com/neozmmv/blindspot/internal/roomserver"
	"github.com/neozmmv/blindspot/internal/session"
	"github.com/neozmmv/blindspot/internal/tornet"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

// Timeouts here are set from measured behaviour, not guessed. Cold starts of the
// full derive → bootstrap → publish → first-fetch chain ranged from ~28s to
// ~187s across runs of identical code, so anything tuned to the fast case
// misfires badly on the slow one.
const (
	// roomProbeTimeout bounds a single "is somebody already hosting?" request.
	// A fetch of a known-good onion service was measured at 7.8s, 12.5s and
	// 62.8s; timing out early makes this peer wrongly conclude the room is empty
	// and publish a competing descriptor, which is the split-brain case, so this
	// errs long.
	roomProbeTimeout = 75 * time.Second
	// roomProbeAttempts is the ceiling on attempts before concluding nobody
	// hosts. Two consecutive definitive "host unreachable" replies short-circuit
	// this, so the count only matters for ambiguous failures worth retrying.
	roomProbeAttempts = 3
	// connectStartupTimeout is how long the foreground process waits for the
	// daemon to report readiness. It must cover the worst case of the whole
	// chain above, plus registration.
	connectStartupTimeout = 6 * time.Minute
)

// roomProbeBackoff separates probe attempts. A variable rather than a constant
// so tests can exercise the retry logic without the real wait.
var roomProbeBackoff = 3 * time.Second

var ConnectCmd = &cobra.Command{
	Use:   "connect <name> <password>",
	Short: "Join a serverless room, discovered over Tor",
	Long: `Join a room identified only by a name and password.

Both are fed through Argon2id to derive a Tor v3 onion service key, so every
peer that knows the pair computes the same .onion address with no DNS and no
rendezvous server. Whoever arrives first hosts the room; the others join it.

The name must be at least 4 characters and the password at least 8. Those are
minimums, not advice: the password is the only thing protecting the room, and
guessing it is an offline exercise nobody can rate-limit, so prefer a passphrase.

For the server-based flow, see 'blindspot rendezvous'.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		name, password := args[0], args[1]
		daemon, _ := cmd.Flags().GetBool("daemon")
		statusFile, _ := cmd.Flags().GetString("status-file")

		// Same precedence as `rendezvous`: flag > env > persistent config.
		upMbit, _ := cmd.Flags().GetInt("up-mbit")
		if upMbit == 0 {
			if v, err := strconv.Atoi(os.Getenv("BLINDSPOT_UP_MBIT")); err == nil && v > 0 {
				upMbit = v
			}
		}
		if upMbit == 0 {
			upMbit = utils.LoadConfig().UpMbit
		}

		// Fail on bad input before spending ~0.1s on Argon2id and far longer on Tor.
		if _, _, err := roomkey.ForRoom(name, password); err != nil {
			fmt.Println(err)
			return
		}

		if !daemon {
			fmt.Println("Deriving room address and starting Tor; this can take a minute...")
			superviseDaemon(fmt.Sprintf("Connected to room %q", name), connectStartupTimeout)
			return
		}

		runRoomDaemon(name, password, upMbit, statusFile)
	},
}

// runRoomDaemon resolves the room's onion address, decides whether to host it or
// join an existing host, and then hands off to the shared session daemon.
func runRoomDaemon(name, password string, upMbit int, statusFile string) {
	writeStatus := func(msg string) {
		if statusFile != "" {
			os.WriteFile(statusFile, []byte(msg), 0600)
		}
	}
	progress := func(msg string) { writeStatus(progressPrefix + " " + msg) }

	priv, onionID, err := roomkey.ForRoom(name, password)
	if err != nil {
		writeStatus("error: " + err.Error())
		return
	}
	onionURL := "http://" + onionID + ".onion"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	progress("starting Tor")
	t, err := tornet.Start(ctx)
	if err != nil {
		writeStatus("error: starting tor: " + err.Error())
		return
	}
	defer t.Close()

	transport, err := tornet.HTTPTransport(ctx, t)
	if err != nil {
		writeStatus("error: building tor transport: " + err.Error())
		return
	}
	torClient := &http.Client{Transport: transport, Timeout: roomProbeTimeout}

	// Is somebody already hosting this room?
	progress("looking for an existing host at " + onionID + ".onion")
	var discovery *session.Client
	// hostedElsewhere also reports why it concluded the room was empty; it is
	// dropped here to keep the CLI line readable. Worth routing to a debug log
	// if false negatives (publishing over a live host) ever need diagnosing.
	hosted, _ := hostedElsewhere(torClient, onionURL)
	if hosted {
		progress("joining host at " + onionID + ".onion")
		discovery = session.NewClient(onionURL, roomserver.RoomSessionID, "", torClient)
	} else {
		progress("no host found. publishing " + onionID + ".onion")
		local, closeHost, err := becomeRoomHost(ctx, t, priv)
		if err != nil {
			writeStatus("error: publishing room: " + err.Error())
			return
		}
		defer closeHost()
		progress("hosting room at " + onionID + ".onion")
		// Talk to our own room over loopback rather than looping back out
		// through Tor: same server, same state, without a pointless circuit.
		discovery = session.NewClient(local, roomserver.RoomSessionID, "", http.DefaultClient)
	}

	runSessionDaemon(daemonParams{
		discovery: discovery,
		// Onion rooms have no server-side session to create.
		createSession: false,
		// The PSK is derived from the same password as the onion address, so it
		// is NOT an independent second factor here: anyone who guesses the
		// password gets both. It still defends the case where the address leaks
		// without the password (e.g. a descriptor leak), which is why it is
		// kept — but room security rests on password entropy alone.
		pskPassword:  password,
		pskSessionID: name,
		upMbit:       upMbit,
		statusFile:   statusFile,
	})
}

// hostedElsewhere reports whether the room's onion service already answers, and
// why it concluded otherwise.
//
// The reason matters for tuning and for debugging false negatives: concluding
// "empty" when a host is actually up makes this peer publish a competing
// descriptor, and since HSDir publication is last-writer-wins that shows up as
// the room's address flapping between two backends rather than as a clean error.
func hostedElsewhere(client *http.Client, onionURL string) (bool, string) {
	var last string
	misses := 0
	for i := 0; i < roomProbeAttempts; i++ {
		started := time.Now()
		resp, err := client.Get(onionURL + "/version")
		took := time.Since(started).Round(time.Second)

		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true, ""
			}
			last = fmt.Sprintf("attempt %d: HTTP %d after %s", i+1, resp.StatusCode, took)
		} else {
			last = fmt.Sprintf("attempt %d: %v after %s", i+1, err, took)
			// Tor answers with SOCKS5 "host unreachable" when it cannot reach the
			// service at all — typically because no descriptor is published, i.e.
			// nobody is hosting. That arrives in seconds, where an ambiguous
			// failure burns the full per-attempt timeout, so treating it as
			// conclusive is the difference between hosting an empty room in ~15s
			// and in ~200s.
			//
			// It is not completely unambiguous: the same code appears when a
			// descriptor exists but its introduction points are failing. Two
			// consecutive misses are required before acting, so a host having one
			// bad moment does not get a competing descriptor published over it.
			if isOnionUnreachable(err) {
				if misses++; misses >= 2 {
					return false, last
				}
				time.Sleep(roomProbeBackoff)
				continue
			}
			misses = 0
		}
		if i < roomProbeAttempts-1 {
			time.Sleep(roomProbeBackoff)
		}
	}
	return false, last
}

// isOnionUnreachable matches Tor's SOCKS5 "host unreachable" reply.
//
// golang.org/x/net/proxy renders reply codes as text and exposes no typed
// error, so this matches on that text. A false negative here is harmless — it
// only costs the slower timeout path.
func isOnionUnreachable(err error) bool {
	return strings.Contains(err.Error(), "host unreachable")
}

// becomeRoomHost publishes the onion service and serves the room API on it. The
// same handler is also served on a loopback listener, whose base URL is
// returned, so the hosting peer can register with its own room directly.
func becomeRoomHost(ctx context.Context, t *tor.Tor, priv ed25519.PrivateKey) (string, func(), error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("generating host nonce: %w", err)
	}
	srv := roomserver.New(getVersion(), hex.EncodeToString(nonce))
	handler := srv.Handler()

	loopback, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("opening local room listener: %w", err)
	}

	onionSvc, err := t.Listen(ctx, &tor.ListenConf{
		Key:         priv,
		Version3:    true,
		RemotePorts: []int{80},
	})
	if err != nil {
		loopback.Close()
		return "", nil, fmt.Errorf("publishing onion service: %w", err)
	}

	go http.Serve(onionSvc, handler)
	go http.Serve(loopback, handler)

	closeHost := func() {
		onionSvc.Close()
		loopback.Close()
	}
	return "http://" + loopback.Addr().String(), closeHost, nil
}

func init() {
	ConnectCmd.Flags().Int("up-mbit", 0, "Force a fixed upload cap in Mbit/s (0 = automatic: adapts to the path)")
	ConnectCmd.Flags().Bool("daemon", false, "")
	ConnectCmd.Flags().String("status-file", "", "")
	ConnectCmd.Flags().MarkHidden("daemon")
	ConnectCmd.Flags().MarkHidden("status-file")
}
