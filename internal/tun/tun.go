package tun

import (
	"crypto/sha256"
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Device re-exports the wireguard TUN interface so callers don't need to import wireguard directly.
type Device = wgtun.Device

// VirtualIPv4 derives a stable virtual IPv4 address from a peer's public key.
func VirtualIPv4(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return fmt.Sprintf("10.%d.%d.%d", hash[0], hash[1], hash[2])
}
