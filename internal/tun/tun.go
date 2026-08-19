package tun

import (
	"crypto/sha256"
	"fmt"
	"net"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Device re-exports the wireguard TUN interface so callers don't need to import wireguard directly.
type Device = wgtun.Device

// WriteOffset is the headroom every packet handed to Device.Write must carry in
// front of it: the packet has to sit at buf[WriteOffset:], not at buf[0:].
//
// Linux is why. The kernel gives a modern TUN device a virtio net header
// (IFF_VNET_HDR), so wireguard-go writes a 10-byte header into the bytes
// immediately before the packet — and rejects the whole batch with "invalid
// offset" when there is no room for it. Nothing else reports the problem: the
// read direction has no such requirement, so a tunnel with no headroom looks
// half-alive, sending fine while every packet arriving from a peer is dropped
// at the last step before the local network stack.
//
// The value matches wireguard-go's own MessageTransportOffsetContent rather
// than the 10 bytes strictly needed, so the same figure is correct on every
// platform (Windows and Darwin honour any offset) and stays correct if the
// header ever grows.
const WriteOffset = 16

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
