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
$CliDest  = $env:BS_CLI_DEST
$TrayDest = $env:BS_TRAY_DEST
$TmpCli   = "$env:TEMP\blindspot_update.exe"
$TmpTray  = "$env:TEMP\blindspot_tray_update.exe"

Write-Host "Downloading latest Blindspot (CLI + tray)..."
Invoke-WebRequest -Uri "$Base/blindspot.exe"      -OutFile $TmpCli
Invoke-WebRequest -Uri "$Base/blindspot-tray.exe" -OutFile $TmpTray

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
