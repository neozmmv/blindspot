//go:build !windows

package cmd

import (
	"os"
	"os/exec"
	"testing"
)

// TestIsProcessAliveOtherUser pins the case that made `blindspot list` report a
// live session as dead: the daemon runs as root, the CLI does not, and signal 0
// across that boundary fails with EPERM rather than succeeding.
func TestIsProcessAliveOtherUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs an unprivileged process to probe a root-owned one")
	}
	// PID 1 is root-owned on any system this matters on, and never exits.
	if !isProcessAlive(1) {
		t.Fatal("isProcessAlive(1) = false; a process we may not signal is still a running process")
	}
}

func TestIsProcessAlive(t *testing.T) {
	if !isProcessAlive(os.Getpid()) {
		t.Fatal("isProcessAlive(self) = false, want true")
	}

	// A reaped child's PID is free again, which is what a stale session.pid
	// looks like and the only case that may report dead.
	child := exec.Command("/bin/sh", "-c", "exit 0")
	if err := child.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	pid := child.Process.Pid
	if err := child.Wait(); err != nil {
		t.Fatalf("waiting for child: %v", err)
	}
	if isProcessAlive(pid) {
		t.Fatalf("isProcessAlive(%d) = true for an exited, reaped process", pid)
	}
}
