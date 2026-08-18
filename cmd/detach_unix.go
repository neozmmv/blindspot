//go:build !windows

package cmd

import (
	"os/exec"
	"syscall"
)

// detachDaemon puts the daemon in its own session, with no controlling
// terminal.
//
// Without this the daemon inherits the foreground process group of whatever
// terminal started it, which under sudo is fatal. Since 1.9.14 sudo defaults to
// use_pty: the command runs in a new pseudo-terminal owned by a "monitor"
// process that is the session leader. When `blindspot connect` returns, the
// monitor exits too, and the kernel sends SIGHUP to that pty's foreground
// process group — which the daemon is in. Go's default action for SIGHUP is to
// terminate, so the session died a few milliseconds after reporting "Connected
// to room", leaving no PID file and no chance to leave the room or stop Tor.
func detachDaemon(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
