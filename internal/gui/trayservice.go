package gui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/neozmmv/blindspot/internal/transfer"
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
	Session   string `json:"session"` // active session name, if this tray started it
	Peers     []Peer `json:"peers"`
	Busy      bool   `json:"busy"`      // a connect/send is in flight
	Receiving bool   `json:"receiving"` // a receive listener is running
	Transfer  string `json:"transfer"`  // latest file-transfer status line

	// Consent handshake (see requests.go).
	AwaitingAccept bool             `json:"awaitingAccept"` // sender: waiting for a peer to accept
	AwaitingPeer   string           `json:"awaitingPeer"`   // sender: peer we're waiting on
	Incoming       *IncomingRequest `json:"incoming"`       // receiver: pending inbound request, if any
}

// IncomingRequest is a pending inbound file offer surfaced to the frontend as an
// Accept/Decline card. It mirrors the native toast.
type IncomingRequest struct {
	ID       string `json:"id"`
	PeerIP   string `json:"peerIP"`
	Filename string `json:"filename"`
	Size     string `json:"size"`
}

// TrayService is the bridge exposed to the frontend. It shells out to the blindspot
// binary for connect (which needs privilege elevation) and calls the in-process
// internal/transfer package directly for file send/receive, while reading the on-disk
// session state directly for status and disconnect.
type TrayService struct {
	mu         sync.Mutex
	busy       bool
	transfer   string
	session    string             // the session name this tray connected to, if any
	receiver   *transfer.Receiver // in-process receive listener, while a receive is running
	recvCancel context.CancelFunc // cancels the running receive

	// Consent handshake state (see requests.go). All fields below are guarded by mu.
	reqLn      net.Listener    // control-channel listener on myIP:28126 while connected
	reqBoundIP string          // the IP reqLn is bound to (to detect a virtual-IP change)
	pendingIn  *inboundRequest // at most one pending inbound request (single-flight)
	reqCounter uint64          // monotonic source for request IDs

	pendingOutConn net.Conn // sender: open control conn while awaiting a decision
	awaitingPeer   string   // sender: peer IP we're waiting on (empty when not awaiting)
	sendCancelled  bool     // sender: set by CancelSend before it closes pendingOutConn

	// Injected once at startup (before app.Run), read-only thereafter.
	notifSvc   *notifications.NotificationService
	showWindow func() // pops the tray panel to the front
	catOnce    sync.Once
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
	busy, transfer, receiving, session := s.busy, s.transfer, s.receiver != nil, s.session
	awaitingPeer := s.awaitingPeer
	var incoming *IncomingRequest
	if s.pendingIn != nil {
		incoming = &IncomingRequest{
			ID:       s.pendingIn.id,
			PeerIP:   s.pendingIn.peerIP,
			Filename: s.pendingIn.filename,
			Size:     s.pendingIn.size,
		}
	}
	s.mu.Unlock()
	if !connected {
		session = "" // a stale session name shouldn't outlive the connection
	}
	return Status{
		Connected:      connected,
		MyIP:           s.MyIP(),
		Session:        session,
		Peers:          peers,
		Busy:           busy,
		Receiving:      receiving,
		Transfer:       transfer,
		AwaitingAccept: awaitingPeer != "",
		AwaitingPeer:   awaitingPeer,
		Incoming:       incoming,
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

// clearTransferAfter blanks the transfer line after d — but only if it still shows
// msg and no receive is running, so a newer transfer's status is never wiped.
func (s *TrayService) clearTransferAfter(msg string, d time.Duration) {
	if msg == "" {
		return
	}
	go func() {
		time.Sleep(d)
		s.mu.Lock()
		cleared := s.transfer == msg && s.receiver == nil
		if cleared {
			s.transfer = ""
		}
		s.mu.Unlock()
		if cleared {
			s.emit()
		}
	}()
}

// Connect runs `blindspot connect -s <session> -p <password> [-n] [-H <hostname>]`,
// which triggers the UAC elevation + daemon launch and blocks until the session is
// up (or fails). A non-empty hostname overrides the default rendezvous server. It
// returns the final status line the CLI printed.
func (s *TrayService) Connect(session, password string, isNew bool, hostname string) (string, error) {
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
	if hostname = strings.TrimSpace(hostname); hostname != "" {
		args = append(args, "-H", hostname)
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

// SendFile offers a file to a peer. It first asks the peer's control channel (:28126)
// for consent; on accept it streams the file over :28125. If the peer has no control
// listener (an older tray) it falls back to a direct send so mixed versions interoperate.
// Blocks until the peer decides (or a timeout) and, on accept, for the transfer. A
// failure is surfaced as the status line and returned with a nil error, matching the
// prior behavior where transfer failures were reported without an exception.
func (s *TrayService) SendFile(peerIP, filePath string) (string, error) {
	peerIP = strings.TrimSpace(peerIP)
	filePath = strings.TrimSpace(filePath)
	if peerIP == "" || filePath == "" {
		return "", fmt.Errorf("a peer IP and a file are both required")
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("file not found: %s", filePath)
	}

	s.setBusy(true)
	defer s.setBusy(false)

	// Ask for consent on the control channel first.
	ctrl, err := net.DialTimeout("tcp", peerIP+requestPort, 5*time.Second)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			// Peer is online but has no control listener (older tray). Fall back to a
			// direct send so mixed versions keep working.
			return s.directSend(peerIP, filePath)
		}
		// Timed out / unreachable — a direct dial would just burn another timeout.
		return s.reportSend("Peer is offline."), nil
	}

	if err := writeRequestHeader(ctrl, filepath.Base(filePath), uint64(info.Size())); err != nil {
		ctrl.Close()
		return s.reportSend("Peer is unreachable."), nil
	}

	s.mu.Lock()
	s.pendingOutConn = ctrl
	s.sendCancelled = false
	s.awaitingPeer = peerIP
	s.transfer = fmt.Sprintf("Waiting for %s to accept…", peerIP)
	s.mu.Unlock()
	s.emit()

	// Block on the 1-byte decision. The margin over requestTimeout lets the receiver's
	// own timeout fire first, so we normally see an explicit decline rather than a read
	// timeout.
	ctrl.SetReadDeadline(time.Now().Add(requestTimeout + 5*time.Second))
	buf := make([]byte, 1)
	_, rerr := io.ReadFull(ctrl, buf)

	// The await phase is over once the decision arrives (or the read fails). Clear it now,
	// before any transfer, so the UI stops showing "waiting"/Cancel-send during the copy.
	s.mu.Lock()
	cancelled := s.sendCancelled
	s.sendCancelled = false
	s.pendingOutConn = nil
	s.awaitingPeer = ""
	s.mu.Unlock()
	ctrl.Close()

	switch {
	case cancelled:
		// User cancelled — clear silently.
		s.setTransfer("")
		return "", nil
	case rerr != nil:
		var ne net.Error
		if errors.As(rerr, &ne) && ne.Timeout() {
			return s.reportSend("Peer didn't respond."), nil
		}
		return s.reportSend("Peer is unreachable."), nil
	case buf[0] != 1:
		return s.reportSend("Peer declined the transfer."), nil
	default:
		return s.directSend(peerIP, filePath)
	}
}

// directSend streams the file over the transfer port (:28125) and reports the outcome.
func (s *TrayService) directSend(peerIP, filePath string) (string, error) {
	s.setTransfer(fmt.Sprintf("Sending %s to %s…", filepath.Base(filePath), peerIP))
	res, err := transfer.Send(context.Background(), peerIP, filePath, nil)
	var last string
	if err != nil {
		last = err.Error()
	} else {
		last = fmt.Sprintf("Done — %s in %s (avg %s/s)",
			transfer.FormatBytes(float64(res.Bytes)), res.Elapsed.Round(time.Millisecond),
			transfer.FormatBytes(float64(res.Bytes)/res.Elapsed.Seconds()))
	}
	s.setTransfer(last)
	s.clearTransferAfter(last, 8*time.Second)
	return last, nil
}

// reportSend sets a transient transfer status line and returns it.
func (s *TrayService) reportSend(msg string) string {
	s.setTransfer(msg)
	s.clearTransferAfter(msg, 8*time.Second)
	return msg
}

// StartReceive binds an in-process receive listener so the tray can keep serving while
// it waits for an incoming file. Returning without error means the port is bound. A
// goroutine runs the one-shot Accept, streaming progress into the transfer status and
// pushing it to the frontend; when it completes the receive state clears so a later
// StartReceive rebinds cleanly.
func (s *TrayService) StartReceive(here bool) error {
	s.mu.Lock()
	if s.receiver != nil {
		s.mu.Unlock()
		return fmt.Errorf("already waiting to receive")
	}
	s.mu.Unlock()
	return s.startReceiver(here)
}

// startReceiver binds an in-process receive listener and spawns the one-shot Accept
// goroutine. It is shared by the manual StartReceive path and the consent-accept path
// in requests.go. Returning without error means the port is bound (Listen guarantees
// it), so a caller may signal readiness to a waiting sender immediately.
func (s *TrayService) startReceiver(here bool) error {
	ip := s.MyIP()
	if ip == "" {
		return fmt.Errorf("no identity found. Run 'blindspot connect' first")
	}

	var destDir string
	var err error
	if here {
		destDir, err = os.Getwd()
	} else {
		destDir, err = transfer.DownloadsDir()
	}
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	recv, err := transfer.Listen(ctx, ip)
	if err != nil {
		cancel()
		return err
	}

	s.mu.Lock()
	s.receiver = recv
	s.recvCancel = cancel
	s.transfer = "Waiting for a file…"
	s.mu.Unlock()
	s.emit()

	go func() {
		defer cancel()

		// Render progress snapshots into the transfer status: the first snapshot is the
		// "Receiving…" header, later ones overwrite a single live line.
		prog := make(chan transfer.Progress, 1)
		renderDone := make(chan struct{})
		go func() {
			var lr transfer.LineRenderer
			first := true
			for p := range prog {
				if first {
					first = false
					lr.Seed(p)
					s.setTransfer(fmt.Sprintf("Receiving %s (%d MB) from %s...", p.Name, p.Total/(1024*1024), p.PeerAddr))
					continue
				}
				s.setTransfer(strings.TrimSpace(lr.Line(p)))
			}
			close(renderDone)
		}()

		res, err := recv.Accept(ctx, destDir, prog)
		close(prog)
		<-renderDone
		recv.Close()

		s.mu.Lock()
		s.receiver = nil
		s.recvCancel = nil
		var result string
		switch {
		case errors.Is(err, context.Canceled):
			// User stopped the receive — clear rather than report.
			s.transfer = ""
		case err != nil && strings.HasPrefix(s.transfer, "Waiting"):
			// Failed before any file arrived — nothing useful to show.
			s.transfer = ""
		case err != nil:
			result = err.Error()
			s.transfer = result
		default:
			result = fmt.Sprintf("Saved to %s — %s in %s (avg %s/s)",
				res.Path, transfer.FormatBytes(float64(res.Bytes)), res.Elapsed.Round(time.Millisecond),
				transfer.FormatBytes(float64(res.Bytes)/res.Elapsed.Seconds()))
			s.transfer = result
		}
		s.mu.Unlock()
		s.emit()
		s.clearTransferAfter(result, 8*time.Second)
	}()
	return nil
}

// CancelReceive cancels a pending receive, if one is running. Cancelling the context
// unblocks the in-process Accept, whose goroutine then clears the receive state.
func (s *TrayService) CancelReceive() error {
	s.mu.Lock()
	cancel := s.recvCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
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
