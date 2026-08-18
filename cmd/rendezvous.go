package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neozmmv/blindspot/internal/session"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

func sessionPIDFile() string  { return filepath.Join(utils.GetBlindspotDir(), "session.pid") }
func sessionStopFile() string { return filepath.Join(utils.GetBlindspotDir(), "session.stop") }
func peersFile() string       { return filepath.Join(utils.GetBlindspotDir(), "peers.json") }

// isSessionRunning returns true only if the session PID file exists AND the recorded
// process is still alive. If the file exists but the process is gone (e.g. after an
// unclean shutdown), the stale files are removed and false is returned.
func isSessionRunning() bool {
	data, err := os.ReadFile(sessionPIDFile())
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || !isProcessAlive(pid) {
		os.Remove(sessionPIDFile())
		os.Remove(sessionStopFile())
		os.Remove(peersFile())
		return false
	}
	return true
}

type PeerEntry struct {
	VirtualIP  string `json:"virtual_ip"`
	PublicAddr string `json:"public_addr"`
}

func writePeers(m *sync.Map) {
	var entries []PeerEntry
	m.Range(func(k, v any) bool {
		entries = append(entries, PeerEntry{
			VirtualIP:  k.(string),
			PublicAddr: v.(*net.UDPAddr).String(),
		})
		return true
	})
	data, _ := json.Marshal(entries)
	utils.WriteStateFile(peersFile(), data, 0600)
}

var RendezvousCmd = &cobra.Command{
	Use:   "rendezvous",
	Short: "Connect to a blindspot network via a rendezvous server",
	Run: func(cmd *cobra.Command, args []string) {
		hostname, _ := cmd.Flags().GetString("hostname")
		sessionId, _ := cmd.Flags().GetString("session")
		password, _ := cmd.Flags().GetString("password")
		isNew, _ := cmd.Flags().GetBool("new")
		daemon, _ := cmd.Flags().GetBool("daemon")
		statusFile, _ := cmd.Flags().GetString("status-file")
		insecure, _ := cmd.Flags().GetBool("insecure")
		// Upload cap precedence: --up-mbit flag > BLINDSPOT_UP_MBIT env >
		// persistent config ('blindspot config up-mbit N'). The config file is
		// what the tray path uses — it shells out to connect without flags, and
		// the UAC-elevated daemon shares the same ~/.blindspot.
		upMbit, _ := cmd.Flags().GetInt("up-mbit")
		if upMbit == 0 {
			if v, err := strconv.Atoi(os.Getenv("BLINDSPOT_UP_MBIT")); err == nil && v > 0 {
				upMbit = v
			}
		}
		if upMbit == 0 {
			upMbit = utils.LoadConfig().UpMbit
		}

		if len(password) < 8 && isNew {
			fmt.Println("Password must be at least 8 characters long")
			return
		}

		// Resolve the rendezvous URL and refuse plaintext http:// unless --insecure.
		hostname, err := session.NormalizeHostname(hostname, insecure)
		if err != nil {
			fmt.Println(err)
			return
		}

		if !daemon {
			superviseDaemon(fmt.Sprintf("Connected to network %s", sessionId), 30*time.Second)
			return
		}

		runSessionDaemon(daemonParams{
			discovery:     newDiscoveryRef(session.NewClient(hostname, sessionId, password, nil)),
			createSession: isNew,
			pskPassword:   password,
			pskSessionID:  sessionId,
			upMbit:        upMbit,
			statusFile:    statusFile,
		})
	},
}

func init() {
	RendezvousCmd.Flags().StringP("hostname", "H", "", "Rendezvous server hostname")
	RendezvousCmd.Flags().StringP("session", "s", "", "Session ID")
	RendezvousCmd.Flags().StringP("password", "p", "", "Session password")
	RendezvousCmd.Flags().BoolP("new", "n", false, "Create new session with password")
	RendezvousCmd.Flags().Bool("insecure", false, "Allow a plaintext http:// rendezvous (NOT recommended)")
	RendezvousCmd.Flags().Int("up-mbit", 0, "Force a fixed upload cap in Mbit/s (0 = automatic: adapts to the path)")
	RendezvousCmd.MarkFlagRequired("session")
	RendezvousCmd.Flags().Bool("daemon", false, "")
	RendezvousCmd.Flags().String("status-file", "", "")
	RendezvousCmd.Flags().MarkHidden("daemon")
	RendezvousCmd.Flags().MarkHidden("status-file")
}
