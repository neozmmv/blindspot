package tun

import (
	"crypto/sha256"
	"fmt"
	"net"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Device re-exports the wireguard TUN interface so callers don't need to import wireguard directly.
type Device = wgtun.Device

// VirtualIPv4 derives a stable virtual IPv4 address from a peer's public key.
func VirtualIPv4(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return fmt.Sprintf("10.%d.%d.%d", hash[0], hash[1], hash[2])
}

// SrcIPMatchesVirtualIP implements the reverse-path check for a tunnelled packet:
// it reports whether packet is a well-formed IPv4 packet whose source address
// equals expectedVIP. A tunnel packet failing this check must be dropped, because
// its sender is claiming to originate traffic from an address that is not theirs.
func SrcIPMatchesVirtualIP(packet []byte, expectedVIP string) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	return net.IP(packet[12:16]).String() == expectedVIP
}
