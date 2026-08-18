//go:build !windows

package cmd

import (
	"errors"
	"os"
	"syscall"
)

func isProcessAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// EPERM means the process is there but belongs to someone we may not signal:
	// the daemon runs as root (it needs the TUN device) while `blindspot list`
	// usually does not. Reading that as "dead" would not just misreport the
	// session, it would take the caller down the stale-file cleanup path and
	// delete the live session's state.
	return errors.Is(err, os.ErrPermission)
}
