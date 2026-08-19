//go:build linux

package tun

import (
	"os"
	"testing"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// TestWriteOffset checks the headroom contract against a real device, which is
// the only place it is enforced: on a kernel that gives the TUN a virtio net
// header, wireguard-go rejects a batch whose packets have no room in front of
// them for the header, and blindspot's inbound direction goes silently dead.
//
// Needs root, so it skips by default: run it with `sudo -E go test ./internal/tun`.
func TestWriteOffset(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a TUN device needs root")
	}
	dev, err := wgtun.CreateTUN("bstest0", 1420)
	if err != nil {
		t.Fatalf("CreateTUN: %v", err)
	}
	defer dev.Close()

	// A minimal well-formed IPv4/ICMP echo request, the traffic that exposed this.
	packet := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00,
		10, 0, 0, 1, // src
		10, 0, 0, 2, // dst
		0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01,
	}

	buf := make([]byte, WriteOffset+len(packet))
	copy(buf[WriteOffset:], packet)
	if _, err := dev.Write([][]byte{buf}, WriteOffset); err != nil {
		t.Fatalf("Write with WriteOffset=%d headroom: %v", WriteOffset, err)
	}

	// The regression itself: no headroom. It is an error only on a device with a
	// virtio header, which is every current kernel but not a guaranteed one, so
	// report rather than fail when this device happens to accept it.
	if _, err := dev.Write([][]byte{packet}, 0); err != nil {
		t.Logf("as expected, writing at offset 0 fails on this device: %v", err)
	} else {
		t.Log("this device has no virtio net header; offset 0 happens to work here")
	}
}
