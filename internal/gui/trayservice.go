package gui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	bstun "github.com/neozmmv/blindspot/internal/tun"
	"github.com/neozmmv/blindspot/internal/utils"
)

// Session state files written by the connect daemon (see cmd/connect.go). The tray
// reads them directly for status rather than shelling out on every tick.
func sessionPIDFile() string  { return filepath.Join(utils.GetBlindspotDir(), "session.pid") }
func sessionStopFile() string { return filepath.Join(utils.GetBlindspotDir(), "session.stop") }
func peersFile() string       { return filepath.Join(utils.GetBlindspotDir(), "peers.json") }

// Peer is one connected member of the active session.
type Peer struct {
	VirtualIP  string `json:"virtualIP"`
	PublicAddr string `json:"publicAddr"`
}

// Status is the snapshot pushed to the frontend, both on request and via the
// periodic "status" event.
type Status struct {
	Connected bool   `json:"connected"`
	MyIP      string `json:"myIP"`
	Session   string `json:"session"`   // active session name, if this tray started it
	Peers     []Peer `json:"peers"`
	Busy      bool   `json:"busy"`      // a connect/send is in flight
	Receiving bool   `json:"receiving"` // a receive listener is running
	Transfer  string `json:"transfer"`  // latest file-transfer status line
}

// TrayService is the bridge exposed to the frontend. It wraps the same commands a
// user would run in a terminal — shelling out to the blindspot binary for the
// operations that need privilege elevation or long-running transfer logic
// (connect / send / receive), and reading the on-disk session state directly for
// everything else.
type TrayService struct {
	mu       sync.Mutex
	busy     bool
	transfer string
	session  string    // the session name this tray connected to, if any
	recvCmd  *exec.Cmd // running `receive` process, if any
}

// cliExe returns the path to the blindspot CLI binary the tray shells out to. The
// tray ships alongside the CLI, so it prefers a blindspot(.exe) sitting next to
// itself and falls back to whatever is on PATH.
func cliExe() string {
	name := "blindspot"
	if runtime.GOOS == "windows" {
		name = "blindspot.exe"
	}
	if exe, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(sibling); err == nil {
			return sibling
		}
	}
	return name // resolved via PATH
}

func (s *TrayService) sessionRunning() bool {
	data, err := os.ReadFile(sessionPIDFile())
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || !isProcessAlive(pid) {
		// Stale files from an unclean shutdown — clear them, matching the CLI.
		os.Remove(sessionPIDFile())
		os.Remove(sessionStopFile())
		os.Remove(peersFile())
		return false
	}
	return true
}

func (s *TrayService) readPeers() []Peer {
	data, err := os.ReadFile(peersFile())
	if err != nil || len(data) == 0 {
		return []Peer{}
	}
	// The daemon writes cmd.PeerEntry ({virtual_ip, public_addr}); decode into the
	// shape the frontend consumes.
	var raw []struct {
		VirtualIP  string `json:"virtual_ip"`
		PublicAddr string `json:"public_addr"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return []Peer{}
	}
	peers := make([]Peer, 0, len(raw))
	for _, p := range raw {
		peers = append(peers, Peer{VirtualIP: p.VirtualIP, PublicAddr: p.PublicAddr})
	}
	return peers
}

// MyIP returns this device's virtual IP, derived from the (cleartext) public key.
// Works even when the identity is encrypted at rest. Empty if no identity exists.
func (s *TrayService) MyIP() string {
	publicKey, err := utils.ReadPublicKey()
	if err != nil {
		return ""
	}
	return bstun.VirtualIPv4(publicKey)
}

// GetStatus returns the current session snapshot.
func (s *TrayService) GetStatus() Status {
	connected := s.sessionRunning()
	var peers []Peer
	if connected {
		peers = s.readPeers()
	} else {
		peers = []Peer{}
	}
	s.mu.Lock()
	busy, transfer, receiving, session := s.busy, s.transfer, s.recvCmd != nil, s.session
	s.mu.Unlock()
	if !connected {
		session = "" // a stale session name shouldn't outlive the connection
	}
	return Status{
		Connected: connected,
		MyIP:      s.MyIP(),
		Session:   session,
		Peers:     peers,
		Busy:      busy,
		Receiving: receiving,
		Transfer:  transfer,
	}
}

// emit pushes a fresh status snapshot to the frontend immediately (used after an
// action so the UI doesn't wait for the next poll tick).
func (s *TrayService) emit() {
	if app := application.Get(); app != nil {
		app.Event.Emit("status", s.GetStatus())
	}
}

func (s *TrayService) setBusy(b bool) {
	s.mu.Lock()
	s.busy = b
	s.mu.Unlock()
	s.emit()
}

func (s *TrayService) setTransfer(msg string) {
	s.mu.Lock()
	s.transfer = msg
	s.mu.Unlock()
	s.emit()
}

// Connect runs `blindspot connect -s <session> -p <password> [-n]`, which triggers
// the UAC elevation + daemon launch and blocks until the session is up (or fails).
// It returns the final status line the CLI printed.
func (s *TrayService) Connect(session, password string, isNew bool) (string, error) {
	session = strings.TrimSpace(session)
	if session == "" {
		return "", fmt.Errorf("session name is required")
	}
	if isNew && len(password) < 8 {
		return "", fmt.Errorf("a new session needs a password of at least 8 characters")
	}
	if s.sessionRunning() {
		return "", fmt.Errorf("already connected — disconnect first")
	}

	args := []string{"connect", "-s", session}
	if password != "" {
		args = append(args, "-p", password)
	}
	if isNew {
		args = append(args, "-n")
	}

	s.setBusy(true)
	defer s.setBusy(false)

	out, err := s.runCLI(args...)
	if err == nil && s.sessionRunning() {
		s.mu.Lock()
		s.session = session
		s.mu.Unlock()
	}
	s.emit()
	if err != nil {
		if out != "" {
			return "", fmt.Errorf("%s", out)
		}
		return "", err
	}
	return out, nil
}

// Disconnect signals the running daemon to stop (the same mechanism as
// `blindspot disconnect`) and waits briefly for it to tear down.
func (s *TrayService) Disconnect() (string, error) {
	s.mu.Lock()
	s.session = ""
	s.mu.Unlock()
	if !s.sessionRunning() {
		return "No active session.", nil
	}
	if err := os.WriteFile(sessionStopFile(), []byte("stop"), 0600); err != nil {
		return "", fmt.Errorf("could not signal daemon: %w", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sessionPIDFile()); os.IsNotExist(err) {
			s.emit()
			return "Disconnected.", nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Daemon didn't exit cleanly — remove leftovers, matching the CLI.
	os.Remove(sessionStopFile())
	os.Remove(sessionPIDFile())
	os.Remove(peersFile())
	s.emit()
	return "Session did not stop cleanly; cleaned up.", nil
}

// SelectFile opens a native file picker and returns the chosen path (empty if the
// user cancelled). Cancellation is not an error — it returns "" so the frontend
// simply keeps the previous selection and nothing is logged.
func (s *TrayService) SelectFile() (string, error) {
	app := application.Get()
	if app == nil {
		return "", fmt.Errorf("application not ready")
	}
	path, err := app.Dialog.OpenFile().CanChooseFiles(true).SetTitle("Select a file to send").PromptForSingleSelection()
	if err != nil {
		return "", nil // user dismissed the dialog
	}
	return path, nil
}

// SendFile runs `blindspot send <peerIP> <filePath>` and returns the CLI's final
// line. Blocks for the duration of the transfer.
func (s *TrayService) SendFile(peerIP, filePath string) (string, error) {
	peerIP = strings.TrimSpace(peerIP)
	filePath = strings.TrimSpace(filePath)
	if peerIP == "" || filePath == "" {
		return "", fmt.Errorf("a peer IP and a file are both required")
	}
	if _, err := os.Stat(filePath); err != nil {
		return "", fmt.Errorf("file not found: %s", filePath)
	}

	s.setBusy(true)
	s.setTransfer(fmt.Sprintf("Sending %s to %s…", filepath.Base(filePath), peerIP))
	defer s.setBusy(false)

	out, err := s.runCLI("send", peerIP, filePath)
	last := lastLine(out)
	if err != nil {
		if last != "" {
			s.setTransfer(last)
			return "", fmt.Errorf("%s", last)
		}
		s.setTransfer("Send failed.")
		return "", err
	}
	s.setTransfer(last)
	return last, nil
}

// StartReceive launches `blindspot receive` in the background so the tray can keep
// serving while it waits for an incoming file. Progress lines are streamed into the
// transfer status and pushed to the frontend.
func (s *TrayService) StartReceive(here bool) error {
	s.mu.Lock()
	if s.recvCmd != nil {
		s.mu.Unlock()
		return fmt.Errorf("already waiting to receive")
	}

	args := []string{"receive"}
	if here {
		args = append(args, "--here")
	}
	cmd := exec.Command(cliExe(), args...)
	hideConsole(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.recvCmd = cmd
	s.transfer = "Waiting for a file…"
	s.mu.Unlock()
	s.emit()

	// Stream the CLI output. It emits progress with carriage returns, so split on
	// both \r and \n and surface the most recent non-empty line.
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Split(scanLinesOrCR)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				s.setTransfer(line)
			}
		}
		_ = scanner.Err()
		cmd.Wait()
		s.mu.Lock()
		s.recvCmd = nil
		if strings.HasPrefix(s.transfer, "Waiting") {
			s.transfer = "Stopped waiting."
		}
		s.mu.Unlock()
		s.emit()
	}()
	return nil
}

// CancelReceive kills a pending `receive` process, if one is running.
func (s *TrayService) CancelReceive() error {
	s.mu.Lock()
	cmd := s.recvCmd
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

// Version returns the blindspot version string.
func (s *TrayService) Version() string {
	out, err := s.runCLI("version")
	if err != nil || out == "" {
		return "blindspot"
	}
	return lastLine(out)
}

// runCLI invokes a blindspot subcommand on this same binary and returns its
// combined, trimmed output.
func (s *TrayService) runCLI(args ...string) (string, error) {
	cmd := exec.Command(cliExe(), args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

// scanLinesOrCR is a bufio.SplitFunc that breaks tokens on either newline or
// carriage return, so progress-bar updates (which use \r) surface as they arrive.
func scanLinesOrCR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i, b := range data {
		if b == '\n' || b == '\r' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}
