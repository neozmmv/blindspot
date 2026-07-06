package network

import "net"

// IsValidPeerAddr reports whether addr is safe to use as a peer endpoint.
//
// The rendezvous server is trusted, but a compromised or buggy server — or a
// malicious member echoing a crafted address — must not be able to aim this
// client's hole-punching traffic at broadcast/multicast destinations or at
// privileged well-known service ports (turning peers into a UDP reflector aimed
// at, e.g., DNS on 53 or NTP on 123).
//
// Loopback and private addresses are allowed on purpose: same-NAT peers connect
// via their private local_addr.
func IsValidPeerAddr(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	ip := addr.IP
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	// Reject the limited broadcast address 255.255.255.255.
	if ip4 := ip.To4(); ip4 != nil && ip4.Equal(net.IPv4bcast) {
		return false
	}
	// Reject port 0 and privileged well-known ports (< 1024). Peers always advertise
	// high ephemeral ports (the UDP socket binds port 0), so this never rejects a
	// legitimate endpoint.
	if addr.Port < 1024 || addr.Port > 65535 {
		return false
	}
	return true
}
