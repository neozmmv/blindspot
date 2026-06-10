package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List peers connected to the active session",
	Run: func(cmd *cobra.Command, args []string) {
		if !isSessionRunning() {
			fmt.Println("No active session.")
			return
		}

		data, err := os.ReadFile(peersFile())
		if err != nil || len(data) == 0 {
			fmt.Println("No peers connected.")
			return
		}

		var peers []PeerEntry
		if err := json.Unmarshal(data, &peers); err != nil {
			fmt.Println("Error reading peers:", err)
			return
		}

		if len(peers) == 0 {
			fmt.Println("No peers connected.")
			return
		}

		fmt.Printf("%-18s  %s\n", "VIRTUAL IP", "PUBLIC ADDRESS")
		for _, p := range peers {
			fmt.Printf("%-18s  %s\n", p.VirtualIP, p.PublicAddr)
		}
	},
}
