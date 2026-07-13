package main

import (
	_ "embed"
	"os"
	"runtime"

	"github.com/neozmmv/blindspot/cmd"
	"github.com/neozmmv/blindspot/internal/gui"
	"github.com/neozmmv/blindspot/internal/platform"
)

// appIcon is embedded here (not in internal/gui) because go:embed can only reach
// files at or below the embedding package's directory — it can't use ".." to climb
// out. The repo root sits above public/, so it can embed the icon and hand the
// bytes to the GUI, avoiding a duplicate copy inside internal/gui.
//
// It must be a PNG, not an .ico: Wails' tray SetIcon feeds the bytes straight to
// CreateIconFromResourceEx, which wants a single image — an .ico container's
// directory header makes it render blank.
//
//go:embed public/BLINDSPOT_tray.png
var appIcon []byte

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
	gui.Run(appIcon)
}
