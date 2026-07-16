package transfer

import "fmt"

// Op identifies the phase of a transfer that failed. Callers may switch on it, but
// the Error's own message already reproduces the user-facing wording, so the common
// path is simply to print the error.
type Op string

const (
	OpOpenFile       Op = "open_file"
	OpStat           Op = "stat"
	OpDial           Op = "dial"
	OpSendNameLen    Op = "send_name_len"
	OpSendName       Op = "send_name"
	OpSendSize       Op = "send_size"
	OpSendBody       Op = "send_body"
	OpListen         Op = "listen"
	OpAccept         Op = "accept"
	OpReadNameLen    Op = "read_name_len"
	OpReadName       Op = "read_name"
	OpReadSize       Op = "read_size"
	OpCreateFile     Op = "create_file"
	OpRecvBody       Op = "recv_body"
	OpHomeDir        Op = "home_dir"
	OpMkdirDownloads Op = "mkdir_downloads"
)

// Error is a typed transfer error carrying the phase that failed plus the context
// needed to render the exact user-facing message. Its Error() string is identical to
// what the CLI historically printed, so both the CLI and the tray can surface it
// directly without re-deriving the wording. It unwraps to the underlying cause.
type Error struct {
	Op    Op
	Err   error  // underlying cause (nil for OpDial, which is intentionally friendly)
	Peer  string // OpDial: the peer IP
	Addr  string // OpListen: the address we tried to bind
	Got   int64  // OpRecvBody: bytes received before the failure
	Total int64  // OpRecvBody: expected total
}

func (e *Error) Error() string {
	switch e.Op {
	case OpOpenFile:
		return fmt.Sprintf("Error opening file: %v", e.Err)
	case OpStat:
		return fmt.Sprintf("Error reading file info: %v", e.Err)
	case OpDial:
		return fmt.Sprintf("Peer %s is not receiving. Ask them to run 'blindspot receive'.", e.Peer)
	case OpSendNameLen:
		return fmt.Sprintf("Error sending filename length: %v", e.Err)
	case OpSendName:
		return fmt.Sprintf("Error sending filename: %v", e.Err)
	case OpSendSize:
		return fmt.Sprintf("Error sending file size: %v", e.Err)
	case OpSendBody:
		return fmt.Sprintf("Error sending file: %v", e.Err)
	case OpListen:
		return fmt.Sprintf("Could not listen on %s: %v", e.Addr, e.Err)
	case OpAccept:
		return fmt.Sprintf("Error accepting connection: %v", e.Err)
	case OpReadNameLen:
		return fmt.Sprintf("Error reading filename length: %v", e.Err)
	case OpReadName:
		return fmt.Sprintf("Error reading filename: %v", e.Err)
	case OpReadSize:
		return fmt.Sprintf("Error reading file size: %v", e.Err)
	case OpCreateFile:
		return fmt.Sprintf("Error creating file: %v", e.Err)
	case OpRecvBody:
		return fmt.Sprintf("Error receiving file (got %d/%d bytes): %v", e.Got, e.Total, e.Err)
	case OpHomeDir:
		return fmt.Sprintf("Error finding home directory: %v", e.Err)
	case OpMkdirDownloads:
		return fmt.Sprintf("Error creating Downloads directory: %v", e.Err)
	default:
		return fmt.Sprintf("transfer error (%s): %v", e.Op, e.Err)
	}
}

func (e *Error) Unwrap() error { return e.Err }
