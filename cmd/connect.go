package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/neozmmv/blindspot/internal/roomkey"
	"github.com/neozmmv/blindspot/internal/roomserver"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

// connectStartupTimeout is how long the foreground process waits for the daemon
// to report readiness. It must cover the worst case of the whole derive →
// bootstrap → publish → first-fetch chain (measured up to ~187s), plus
// registration.
const connectStartupTimeout = 6 * time.Minute

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

		// Check the inputs without deriving: the real derivation happens once in
		// the daemon, and at 512 MiB it is not worth doing twice.
		if err := roomkey.Validate(name, password); err != nil {
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

// runRoomDaemon joins the room and hands off to the shared session daemon.
func runRoomDaemon(name, password string, upMbit int, statusFile string) {
	writeStatus := func(msg string) {
		if statusFile != "" {
			os.WriteFile(statusFile, []byte(msg), 0600)
		}
	}
	progress := func(msg string) { writeStatus(progressPrefix + " " + msg) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	room, err := joinRoom(ctx, name, password, roomserver.ModeVPN, progress)
	if err != nil {
		writeStatus("error: " + err.Error())
		return
	}
	defer room.close()

	runSessionDaemon(daemonParams{
		discovery: room.ref,
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

func init() {
	ConnectCmd.Flags().Int("up-mbit", 0, "Force a fixed upload cap in Mbit/s (0 = automatic: adapts to the path)")
	ConnectCmd.Flags().Bool("daemon", false, "")
	ConnectCmd.Flags().String("status-file", "", "")
	ConnectCmd.Flags().MarkHidden("daemon")
	ConnectCmd.Flags().MarkHidden("status-file")
}
