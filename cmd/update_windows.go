package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var pwshScript = `
$ErrorActionPreference = "Stop"

$Url  = "https://github.com/neozmmv/blindspot/releases/latest/download/blindspot.exe"
$Dest = "$env:LOCALAPPDATA\Microsoft\WindowsApps\blindspot.exe"

Write-Host "Downloading latest blindspot..."
Invoke-WebRequest -Uri $Url -OutFile $Dest

Write-Host "Installed to $Dest"
Write-Host "Run 'blindspot' from any terminal."
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
