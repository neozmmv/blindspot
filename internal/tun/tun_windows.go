package tun

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

var (
	shell32       = windows.NewLazySystemDLL("shell32.dll")
	shellExecuteW = shell32.NewProc("ShellExecuteW")
)

//go:embed wintun.dll
var WintunDLL []byte

// IsAdmin returns true if the current process has administrator privileges.
func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// RelaunchAsAdmin re-launches the current executable with the given args
// via the Windows "runas" verb, triggering a UAC prompt.
func RelaunchAsAdmin(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting executable path: %w", err)
	}

	quoted := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(a, " ") {
			quoted[i] = `"` + a + `"`
		} else {
			quoted[i] = a
		}
	}
	params := strings.Join(quoted, " ")

	verbPtr, _ := windows.UTF16PtrFromString("runas")
	exePtr, _ := windows.UTF16PtrFromString(exe)
	paramsPtr, _ := windows.UTF16PtrFromString(params)

	ret, _, _ := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
		0,
		0, // SW_HIDE
	)
	if ret <= 32 {
		return fmt.Errorf("requesting elevation failed (code %d)", ret)
	}
	return nil
}

// Create extracts wintun.dll, creates the TUN adapter, assigns the virtual IP,
// opens the firewall for the virtual network, and sets the network profile to
// Private so Windows file sharing (SMB) works without manual configuration.
func Create(virtualIP string) (Device, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("getting executable path: %w", err)
	}
	dllPath := filepath.Join(filepath.Dir(exePath), "wintun.dll")
	if err := os.WriteFile(dllPath, WintunDLL, 0644); err != nil {
		return nil, fmt.Errorf("extracting wintun.dll: %w", err)
	}

	device, err := wgtun.CreateTUN("blindspot", 1420)
	if err != nil {
		return nil, fmt.Errorf("creating TUN adapter (run as administrator?): %w", err)
	}

	// wait for the adapter to signal it's up before configuring it
	up := make(chan struct{}, 1)
	var once sync.Once
	go func() {
		for ev := range device.Events() {
			if ev == wgtun.EventUp {
				once.Do(func() { close(up) })
				return
			}
		}
	}()
	select {
	case <-up:
	case <-time.After(5 * time.Second):
	}

	// assign virtual IP
	out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		"blindspot", "static", virtualIP, "255.0.0.0").CombinedOutput()
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("assigning IP %s: %w — %s", virtualIP, err, out)
	}

	// allow all inbound traffic from the virtual network (HTTP, SMB, RDP, etc.)
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=blindspot").Run()
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=blindspot", "dir=in", "action=allow", "remoteip=10.0.0.0/8").Run()

	// set network profile to Private — required for Windows file sharing (SMB)
	exec.Command("powershell", "-NonInteractive", "-Command",
		"Set-NetConnectionProfile -InterfaceAlias blindspot -NetworkCategory Private").Run()

	return device, nil
}
