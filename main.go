package main

import (
	"os"

	"github.com/neozmmv/blindspot/cmd"
)

// blindspot is the console-subsystem CLI. The system-tray GUI is a separate,
// GUI-subsystem binary (cmd/tray → blindspot-tray.exe) so that running blindspot
// from a terminal behaves like an ordinary command-line tool.
func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
