package gui

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/neozmmv/blindspot/internal/transfer"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

// The consent handshake runs tray ↔ tray on a control channel separate from the
// transfer port. When a sender offers a file and the receiver is not already listening,
// the receiver is prompted (native toast + in-panel card); on accept it starts a
// receiver and the transfer proceeds on :28125.
//
// Wire protocol on :28126 (sender → receiver): uint16 nameLen, name, uint64 size, then
// the sender blocks reading a single response byte — 1 = accept, 0 = decline. The open
// connection is the "on hold" state; if the sender closes it early (cancel), the
// receiver reading the conn sees EOF and dismisses the prompt.
const (
	requestPort    = ":28126"
	requestTimeout = 45 * time.Second

	// notifCategory groups the Yes/No actions for the incoming-file toast.
	notifCategory   = "file-request"
	actionAccept    = "accept"
	actionDecline   = "decline"
	headerReadGrace = 5 * time.Second
)

// inboundRequest is a pending incoming file offer awaiting the user's decision.
type inboundRequest struct {
	id       string
	peerIP   string
	filename string
	size     string    // human-readable, via transfer.FormatBytes
	decision chan bool // buffered(1); true = accept, false = decline
}

// ensureRequestListener keeps the control-channel listener bound to myIP:28126 exactly
// when the session is running. Called from the status tick (a single goroutine), so it
// need not guard against concurrent invocation — only against the fields it shares with
// the request goroutines. Binding is non-elevated.
func (s *TrayService) ensureRequestListener() {
	running := s.sessionRunning()
	ip := s.MyIP()

	s.mu.Lock()
	ln := s.reqLn
	boundIP := s.reqBoundIP
	s.mu.Unlock()

	// Tear the listener down when disconnected, or when the virtual IP changed.
	if ln != nil && (!running || ip == "" || boundIP != ip) {
		s.mu.Lock()
		s.reqLn = nil
		s.reqBoundIP = ""
		s.mu.Unlock()
		ln.Close()
		ln = nil
	}
	if !running || ip == "" || ln != nil {
		return
	}

	newLn, err := net.Listen("tcp", ip+requestPort)
	if err != nil {
		return // transient (e.g. IP not up yet) — retry next tick
	}
	s.mu.Lock()
	s.reqLn = newLn
	s.reqBoundIP = ip
	s.mu.Unlock()
	go s.acceptRequests(newLn)
}

// acceptRequests serves the control listener until it is closed (on disconnect/rebind).
func (s *TrayService) acceptRequests(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handleRequestConn(conn)
	}
}

// handleRequestConn processes one inbound offer: read the header, apply the auto-accept
// and single-flight rules, otherwise prompt and wait for a decision, sender cancel, or
// timeout.
func (s *TrayService) handleRequestConn(conn net.Conn) {
	// Bounded header read so a client that connects and sends nothing can't pin the slot.
	conn.SetReadDeadline(time.Now().Add(headerReadGrace))
	name, size, err := readRequestHeader(conn)
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	peerIP := ipOnly(conn.RemoteAddr())

	s.mu.Lock()
	receiverActive := s.receiver != nil
	alreadyPending := s.pendingIn != nil
	s.mu.Unlock()

	// Already receiving → accept without a prompt (today's behavior).
	if receiverActive {
		writeDecision(conn, true)
		conn.Close()
		return
	}
	// Single-flight for v1: a second concurrent offer is declined immediately.
	if alreadyPending {
		writeDecision(conn, false)
		conn.Close()
		return
	}

	req := &inboundRequest{
		id:       s.nextRequestID(peerIP),
		peerIP:   peerIP,
		filename: name,
		size:     transfer.FormatBytes(float64(size)),
		decision: make(chan bool, 1),
	}
	s.mu.Lock()
	s.pendingIn = req
	s.mu.Unlock()
	s.emit()
	if s.showWindow != nil {
		s.showWindow()
	}
	s.sendRequestNotification(req)

	// Detect an early sender close (cancel) while we wait for the decision.
	senderGone := make(chan struct{})
	go func() {
		var b [1]byte
		if _, err := conn.Read(b[:]); err != nil {
			close(senderGone)
		}
	}()

	select {
	case accepted := <-req.decision:
		s.removeNotification(req.id)
		if !accepted {
			writeDecision(conn, false)
			s.clearPendingIn(req.id)
			conn.Close()
			return
		}
		// If the sender already cancelled (closed the conn) before the click landed,
		// don't bother starting a receiver.
		select {
		case <-senderGone:
			s.clearPendingIn(req.id)
			conn.Close()
			return
		default:
		}
		// Accept: start a receiver, then signal readiness. Because startReceiver returns
		// only once the port is bound, the accept byte is safe to write immediately after.
		if err := s.startReceiver(false); err != nil {
			// e.g. an external `blindspot receive` already holds the port — decline cleanly.
			writeDecision(conn, false)
			s.clearPendingIn(req.id)
			conn.Close()
			return
		}
		// Cancel-race guard: if writing the accept fails, the sender vanished between the
		// check above and here, so it will never dial :28125 — tear the receiver back down
		// rather than leave it listening forever.
		if err := writeDecision(conn, true); err != nil {
			s.CancelReceive()
		}
		s.clearPendingIn(req.id)
		conn.Close()

	case <-senderGone:
		s.removeNotification(req.id)
		s.clearPendingIn(req.id)
		conn.Close()

	case <-time.After(requestTimeout):
		writeDecision(conn, false)
		s.removeNotification(req.id)
		s.clearPendingIn(req.id)
		conn.Close()
	}
}

// AcceptRequest / DeclineRequest are invoked from the frontend panel buttons and from
// the notification-response callback. Both deliver on the pending request's decision
// channel; a late call (after timeout/cancel) is a harmless no-op.
func (s *TrayService) AcceptRequest(id string) error {
	s.deliverDecision(id, true)
	return nil
}

func (s *TrayService) DeclineRequest(id string) error {
	s.deliverDecision(id, false)
	return nil
}

func (s *TrayService) deliverDecision(id string, accept bool) {
	s.mu.Lock()
	req := s.pendingIn
	s.mu.Unlock()
	if req == nil || req.id != id {
		return
	}
	select {
	case req.decision <- accept:
	default: // already decided/cancelled
	}
}

// CancelSend aborts a pending outbound offer. The cancelled flag is set before the conn
// is closed so the blocked response read observes it and clears silently instead of
// reporting an error; closing the conn also makes the receiver's prompt dismiss (EOF).
func (s *TrayService) CancelSend() error {
	s.mu.Lock()
	conn := s.pendingOutConn
	if conn != nil {
		s.sendCancelled = true
	}
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	return nil
}

func (s *TrayService) clearPendingIn(id string) {
	s.mu.Lock()
	if s.pendingIn != nil && s.pendingIn.id == id {
		s.pendingIn = nil
	}
	s.mu.Unlock()
	s.emit()
}

func (s *TrayService) nextRequestID(peerIP string) string {
	s.mu.Lock()
	s.reqCounter++
	n := s.reqCounter
	s.mu.Unlock()
	return fmt.Sprintf("%s-%d", peerIP, n)
}

// sendRequestNotification pushes the native toast with Yes/No actions. The category is
// registered lazily on first use, safely after the notification service has started.
func (s *TrayService) sendRequestNotification(req *inboundRequest) {
	if s.notifSvc == nil {
		return
	}
	s.catOnce.Do(func() {
		s.notifSvc.RequestNotificationAuthorization()
		s.notifSvc.RegisterNotificationCategory(notifications.NotificationCategory{
			ID: notifCategory,
			Actions: []notifications.NotificationAction{
				{ID: actionAccept, Title: "Accept"},
				{ID: actionDecline, Title: "Decline"},
			},
		})
	})
	s.notifSvc.SendNotificationWithActions(notifications.NotificationOptions{
		ID:         req.id,
		Title:      "Incoming file",
		Body:       fmt.Sprintf("%s wants to send you %s (%s)", req.peerIP, req.filename, req.size),
		CategoryID: notifCategory,
		Data:       map[string]any{"requestID": req.id},
	})
}

func (s *TrayService) removeNotification(id string) {
	if s.notifSvc != nil {
		s.notifSvc.RemoveNotification(id)
	}
}

// --- control-channel framing (shared shape with the transfer header, distinct port) ---

func writeRequestHeader(conn net.Conn, name string, size uint64) error {
	nb := []byte(name)
	if err := binary.Write(conn, binary.BigEndian, uint16(len(nb))); err != nil {
		return err
	}
	if _, err := conn.Write(nb); err != nil {
		return err
	}
	return binary.Write(conn, binary.BigEndian, size)
}

func readRequestHeader(conn net.Conn) (name string, size uint64, err error) {
	var nameLen uint16
	if err = binary.Read(conn, binary.BigEndian, &nameLen); err != nil {
		return "", 0, err
	}
	nb := make([]byte, nameLen)
	if _, err = io.ReadFull(conn, nb); err != nil {
		return "", 0, err
	}
	if err = binary.Read(conn, binary.BigEndian, &size); err != nil {
		return "", 0, err
	}
	return string(nb), size, nil
}

func writeDecision(conn net.Conn, accept bool) error {
	b := byte(0)
	if accept {
		b = 1
	}
	_, err := conn.Write([]byte{b})
	return err
}

// ipOnly strips the port from a net.Addr, yielding the peer's virtual IP.
func ipOnly(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
