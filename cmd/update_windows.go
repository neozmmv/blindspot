package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

// pwshScript downloads the latest CLI and tray binaries, then hands off to a small
// batch file that (after this process exits) replaces both in place. The tray is
// stopped before its exe is swapped and restarted afterwards if it had been running.
// Destinations are passed in via BS_CLI_DEST / BS_TRAY_DEST so the update lands
// wherever blindspot is actually installed, keeping the two binaries side by side.
var pwshScript = `
$ErrorActionPreference = "Stop"
$Base     = "https://github.com/neozmmv/blindspot/releases/latest/download"
$RawIcon  = "https://raw.githubusercontent.com/neozmmv/blindspot/master/public/BLINDSPOT.ico"
$CliDest  = $env:BS_CLI_DEST
$TrayDest = $env:BS_TRAY_DEST
$TmpCli   = "$env:TEMP\blindspot_update.exe"
$TmpTray  = "$env:TEMP\blindspot_tray_update.exe"

Write-Host "Downloading latest Blindspot (CLI + tray)..."
Invoke-WebRequest -Uri "$Base/blindspot.exe"      -OutFile $TmpCli
Invoke-WebRequest -Uri "$Base/blindspot-tray.exe" -OutFile $TmpTray

# Refresh the Start Menu shortcut so the tray stays findable in search after an
# update. Older installs may lack it (update used to only swap binaries), which
# left the tray unsearchable since the exes live in WindowsApps, not a shortcut.
$InstallDir = Split-Path $TrayDest
$IconPath   = "$InstallDir\blindspot.ico"
try {
    Invoke-WebRequest -Uri $RawIcon -OutFile $IconPath -ErrorAction Stop
} catch {
    $IconPath = $null
}
try {
    $Shortcut = Join-Path ([Environment]::GetFolderPath("Programs")) "Blindspot.lnk"
    $Shell = New-Object -ComObject WScript.Shell
    $Link = $Shell.CreateShortcut($Shortcut)
    $Link.TargetPath       = $TrayDest
    $Link.WorkingDirectory = $InstallDir
    $Link.Description       = "Blindspot - P2P VPN tray"
    if ($IconPath) { $Link.IconLocation = "$IconPath,0" }
    $Link.Save()
} catch {
    Write-Host "Note: could not refresh Start Menu shortcut: $_"
}

# Restart the tray afterwards only if it is currently running.
$restartLine = ""
if (Get-Process blindspot-tray -ErrorAction SilentlyContinue) {
    $restartLine = "start """" ""$TrayDest"""
}

$batch = "$env:TEMP\blindspot_update.bat"
@"
@echo off
timeout /t 1 /nobreak >nul
taskkill /f /im blindspot-tray.exe >nul 2>&1
move /y "$TmpCli" "$CliDest"
move /y "$TmpTray" "$TrayDest"
$restartLine
del "%~f0"
"@ | Out-File -FilePath $batch -Encoding ascii

Start-Process -FilePath $batch -WindowStyle Hidden
Write-Host "Update downloaded. Applying now - the tray restarts if it was running."
`

func init() {
	rootCmd.AddCommand(updateWindowsCmd)
}

var updateWindowsCmd = &cobra.Command{
	Use:   "update",
	Short: "Update blindspot (CLI and tray)",
	Run: func(cmd *cobra.Command, args []string) {
		// A running session keeps blindspot.exe open, so Windows can't overwrite it
		// during the update (the move fails with the file in use). Tell the user to
		// disconnect first, in red, and bail out before attempting anything.
		if isSessionRunning() {
			fmt.Printf("\033[31mYou are connected to a blindspot network. Disconnect before updating (run: blindspot disconnect).\033[0m\n")
			os.Exit(1)
		}

		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not locate the blindspot executable: %v\n", err)
			os.Exit(1)
		}
		dir := filepath.Dir(exe)

		fmt.Println("Starting blindspot update...")
		scriptCmd := exec.Command("powershell", "-NoProfile", "-Command", pwshScript)
		scriptCmd.Env = append(os.Environ(),
			"BS_CLI_DEST="+filepath.Join(dir, "blindspot.exe"),
			"BS_TRAY_DEST="+filepath.Join(dir, "blindspot-tray.exe"),
		)
		scriptCmd.Stdout = os.Stdout
		scriptCmd.Stderr = os.Stderr
		if err := scriptCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error occurred while updating blindspot: %v\n", err)
			os.Exit(1)
		}
	},
}
