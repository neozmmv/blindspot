package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var DisconnectCmd = &cobra.Command{
	Use:   "disconnect",
	Short: "Disconnect from the active blindspot session",
	Run: func(cmd *cobra.Command, args []string) {
		pidFile := sessionPIDFile()
		stopFile := sessionStopFile()

		if _, err := os.Stat(pidFile); os.IsNotExist(err) {
			fmt.Println("No active session found.")
			return
		}

		if err := os.WriteFile(stopFile, []byte("stop"), 0600); err != nil {
			fmt.Println("Error signaling daemon:", err)
			return
		}

		// wait up to 10s for daemon to remove its PID file
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(pidFile); os.IsNotExist(err) {
				fmt.Println("Disconnected.")
				return
			}
			time.Sleep(200 * time.Millisecond)
		}

		// daemon didn't exit cleanly — remove leftovers
		fmt.Println("Session did not stop cleanly, cleaning up...")
		os.Remove(stopFile)
		os.Remove(pidFile)
	},
}
