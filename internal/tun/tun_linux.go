//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// IsAdmin returns true if the current process is running as root.
func IsAdmin() bool {
	return os.Getuid() == 0
}

// RelaunchAsAdmin on Linux cannot reliably background a sudo process,
// so it returns an error with instructions instead.
func RelaunchAsAdmin(args []string) error {
	// strip --daemon and --status-file from the user-facing hint
	userArgs := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "--daemon") || strings.HasPrefix(a, "--status-file") {
			continue
		}
		userArgs = append(userArgs, a)
	}
	return fmt.Errorf("TUN requires root — re-run with: sudo blindspot %s", strings.Join(userArgs, " "))
}

// Create creates the TUN adapter named "blindspot" and assigns the virtual IP.
func Create(virtualIP string) (Device, error) {
	device, err := wgtun.CreateTUN("blindspot", 1420)
	if err != nil {
		return nil, fmt.Errorf("creating TUN adapter (run as root?): %w", err)
	}

	out, err := exec.Command("ip", "addr", "add", virtualIP+"/8", "dev", "blindspot").CombinedOutput()
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("assigning IP %s: %w — %s", virtualIP, err, out)
	}

	out, err = exec.Command("ip", "link", "set", "blindspot", "up").CombinedOutput()
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("bringing interface up: %w — %s", err, out)
	}

	return device, nil
}
