// Command blindspot-tray is the system-tray GUI for Blindspot. It is built as a
// GUI-subsystem binary (-H windowsgui) so launching it never opens a console
// window. It drives the P2P VPN by shelling out to the sibling blindspot CLI, so
// the two binaries ship side by side.
package main

import "github.com/neozmmv/blindspot/internal/gui"

func main() {
	gui.Run()
}
