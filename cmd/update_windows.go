package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// batch workaround to replace the current executable on next run
var pwshScript = `
$ErrorActionPreference = "Stop"
$Url  = "https://github.com/neozmmv/blindspot/releases/latest/download/blindspot.exe"
$Dest = "$env:LOCALAPPDATA\Microsoft\WindowsApps\blindspot.exe"
$Tmp  = "$env:TEMP\blindspot_update.exe"

Write-Host "Downloading latest blindspot..."
Invoke-WebRequest -Uri $Url -OutFile $Tmp

$batch = "$env:TEMP\blindspot_update.bat"
@"
@echo off
timeout /t 1 /nobreak >nul
move /y "$Tmp" "$Dest"
del "%~f0"
"@ | Out-File -FilePath $batch -Encoding ascii

Start-Process -FilePath $batch -WindowStyle Hidden
Write-Host "Update downloaded. Applying on next run."
`

func init() {
	rootCmd.AddCommand(updateWindowsCmd)
}

var updateWindowsCmd = &cobra.Command{
	Use:   "update",
	Short: "Update blindspot",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting blindspot update...")
		scriptCmd := exec.Command("powershell", "-Command", pwshScript)
		scriptCmd.Stdout = os.Stdout
		scriptCmd.Stderr = os.Stderr
		err := scriptCmd.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error occurred while updating blindspot: %v\n", err)
			os.Exit(1)
		}
	},
}
