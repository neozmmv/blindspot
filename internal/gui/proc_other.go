//go:build !windows

package gui

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// isProcessAlive reports whether the process with the given PID is still running,
// using signal 0 (the POSIX liveness probe). EPERM counts as alive: the daemon
// runs as root and the tray does not, and treating that as dead would send the
// caller into deleting the live session's state as though it were stale.
func isProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, os.ErrPermission)
}

// hideConsole is a no-op off Windows.
func hideConsole(cmd *exec.Cmd) {}
