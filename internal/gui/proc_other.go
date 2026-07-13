//go:build !windows

package gui

import (
	"os"
	"os/exec"
	"syscall"
)

// isProcessAlive reports whether the process with the given PID is still running,
// using signal 0 (the POSIX liveness probe).
func isProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// hideConsole is a no-op off Windows.
func hideConsole(cmd *exec.Cmd) {}
