package cmd

import "os/exec"

// detachDaemon is a no-op on Windows: the daemon is started through
// RelaunchAsAdmin (ShellExecute), which already gives it a life of its own, and
// there is no process group hangup to escape.
func detachDaemon(cmd *exec.Cmd) {}
