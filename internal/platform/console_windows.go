//go:build windows

package platform

import (
	"syscall"
	"unsafe"
)

const attachParentProcess = ^uint32(0)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procAttachConsole         = kernel32.NewProc("AttachConsole")
)

// WasLaunchedFromTerminal detects whether the process was started from an
// existing console (cmd/PowerShell) versus spawned fresh via double-click.
func WasLaunchedFromTerminal() bool {
	procAttachConsole.Call(uintptr(attachParentProcess))

	var pids [2]uint32
	ret, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)

	return ret > 1
}

// AttachToParentConsole attaches stdout/stderr to the console of the
// process that launched this one (e.g. cmd.exe or PowerShell).
func AttachToParentConsole() {
	procAttachConsole.Call(uintptr(attachParentProcess))
}
