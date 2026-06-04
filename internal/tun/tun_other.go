//go:build !windows && !linux

package tun

import "fmt"

func IsAdmin() bool {
	return false
}

func RelaunchAsAdmin(args []string) error {
	return fmt.Errorf("TUN not yet implemented on this platform")
}

func Create(virtualIP string) (Device, error) {
	return nil, fmt.Errorf("TUN not yet implemented on this platform")
}
