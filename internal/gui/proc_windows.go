//go:build windows

package gui

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// isProcessAlive reports whether the process with the given PID is still running.
// Mirrors cmd/pid_windows.go so tray status matches what the CLI reports.
func isProcessAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == 259 // STILL_ACTIVE
}

// hideConsole prevents a console window from flashing when the tray shells out to
// the blindspot CLI binary.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
