package main

import (
	"os"
	"runtime"

	"github.com/neozmmv/blindspot/cmd"
	"github.com/neozmmv/blindspot/internal/gui"
	"github.com/neozmmv/blindspot/internal/platform"
)

func main() {
	// Explicit CLI command (e.g. "blindspot connect ...", "blindspot list")
	if len(os.Args) > 1 {
		if err := cmd.Execute(); err != nil {
			os.Exit(1)
		}
		return
	}

	// No arguments passed. On Windows, distinguish between:
	// "blindspot" inside an existing terminal -> show help
	// double-clicked from Explorer/Start Menu -> launch tray GUI
	if runtime.GOOS == "windows" && platform.WasLaunchedFromTerminal() {
		platform.AttachToParentConsole()
		if err := cmd.Execute(); err != nil {
			os.Exit(1)
		}
		return
	}

	// Double-click (Windows) or plain "./blindspot" launched fresh (Linux) -> tray
	gui.Run()
}
