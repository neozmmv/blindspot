package tun

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	// quote individual args that contain spaces
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
		0, // SW_HIDE — no console window
	)
	if ret <= 32 {
		return fmt.Errorf("requesting elevation failed (code %d)", ret)
	}
	return nil
}

// Create extracts wintun.dll next to the executable (required by the loader),
// creates the TUN adapter named "blindspot", and assigns the virtual IP.
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
		return nil, fmt.Errorf("creating TUN adapter: %w", err)
	}

	out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		"blindspot", "static", virtualIP, "255.0.0.0").CombinedOutput()
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("assigning IP %s: %w — %s", virtualIP, err, out)
	}

	return device, nil
}
