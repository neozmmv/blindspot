package gui

import (
	"embed"
	"log"
	"runtime"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/icons"
)

//go:embed all:frontend/dist
var assets embed.FS

// trayIcon is the tray/menu-bar icon. It must be a PNG (Wails' Windows SetIcon feeds
// the bytes to CreateIconFromResourceEx, which rejects .ico containers).
//
//go:embed icon.png
var trayIcon []byte

func init() {
	// Payload emitted to the frontend whenever the session state changes.
	application.RegisterEvent[Status]("status")
}

// Run launches the system-tray GUI. It is the entry point of the blindspot-tray
// binary; the CLI lives in the separate console-subsystem blindspot binary.
func Run() {
	tray := &TrayService{}

	// Declared up front so the SingleInstance callback below (and the tray menu) can
	// close over them; assigned once the app exists. The tray is captured too so those
	// paths open the panel anchored to the tray icon (ShowWindow) rather than letting
	// Wails center a bare window.Show().
	var window *application.WebviewWindow
	var systemTray *application.SystemTray

	app := application.New(application.Options{
		Name:        "Blindspot",
		Description: "P2P Toolkit: VPN, File Sharing, Chat, and More",
		Services: []application.Service{
			application.NewService(tray),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ActivationPolicy: application.ActivationPolicyAccessory,
		},
		// Enforce a single running tray: a second launch exits immediately and asks
		// the existing instance to surface its window instead of opening another one.
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "dev.enzogp.blindspot.tray",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				if systemTray != nil {
					systemTray.ShowWindow() // anchored to the tray, like a tray-icon click
				} else if window != nil {
					window.Show().Focus()
				}
			},
		},
	})

	systemTray = app.SystemTray.New()

	// quitting flips true only when the user chooses Quit, so the close hook below
	// knows to let the app actually terminate instead of just hiding the window.
	quitting := false

	window = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "Blindspot",
		Width:            400,
		Height:           600,
		Frameless:        true,
		AlwaysOnTop:      true,
		Hidden:           true,
		DisableResize:    true,
		HideOnEscape:     true,
		// Stay open when the user alt-tabs or clicks away — the panel only hides via
		// the minimize button, Escape, the tray icon, or clicking outside is a no-op.
		// It keeps AlwaysOnTop so it floats above other windows while visible.
		HideOnFocusLost:  false,
		BackgroundColour: application.NewRGB(0, 0, 0),
		URL:              "/",
		EnableFileDrop:   true,
		Windows: application.WindowsWindow{
			HiddenOnTaskbar: true,
		},
	})

	// Drag-and-drop send: each peer card in the frontend is tagged
	// data-file-drop-target + data-peer-ip. Dropping OS files onto one fires this
	// with the target's attributes, so we send each file to that peer.
	//
	// Must be OnWindowEvent, NOT RegisterHook: Wails dispatches WindowFilesDropped
	// only to eventListeners (OnWindowEvent), never to eventHooks (RegisterHook), so
	// a hook here silently never fires — the drag highlight works but no send starts.
	window.OnWindowEvent(events.Common.WindowFilesDropped, func(e *application.WindowEvent) {
		ctx := e.Context()
		files := ctx.DroppedFiles()
		details := ctx.DropTargetDetails()
		if details == nil || len(files) == 0 {
			return
		}
		peerIP := details.Attributes["data-peer-ip"]
		if peerIP == "" {
			return
		}
		go func() {
			for _, f := range files {
				tray.SendFile(peerIP, f)
			}
		}()
	})

	// Closing the tray window just hides it — the app keeps running in the tray,
	// unless the user picked Quit from the tray menu.
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if quitting {
			return
		}
		window.Hide()
		e.Cancel()
	})

	// Custom tray icon + hover tooltip. macOS wants a monochrome template icon, so
	// keep the built-in there; every other platform gets the Blindspot icon.
	if runtime.GOOS == "darwin" {
		systemTray.SetTemplateIcon(icons.SystrayMacTemplate)
	} else {
		systemTray.SetIcon(trayIcon)
	}
	systemTray.SetTooltip("Blindspot")

	systemTray.AttachWindow(window).WindowOffset(5)

	// Right-click menu on the tray icon. Left-click still toggles the panel;
	// setting a menu makes Wails wire right-click to open it (see SystemTray.bind).
	trayMenu := application.NewMenu()
	trayMenu.Add("Show Blindspot").OnClick(func(_ *application.Context) {
		systemTray.ShowWindow() // anchored to the tray, like a tray-icon click
	})
	trayMenu.AddSeparator()
	trayMenu.Add("Quit Blindspot").OnClick(func(_ *application.Context) {
		quitting = true
		app.Quit()
	})
	systemTray.SetMenu(trayMenu)

	// Push session status to the frontend on a slow tick so the panel reflects the
	// daemon coming up, peers joining/leaving, or the daemon dying, without the UI
	// having to poll over the bindings.
	go func() {
		for {
			app.Event.Emit("status", tray.GetStatus())
			time.Sleep(2 * time.Second)
		}
	}()

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
