package cmd

import (
	"fmt"
	"strconv"

	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

// ConfigCmd shows or changes persistent settings in ~/.blindspot/config.json.
// Settings apply to every future connect — CLI and tray alike — so nothing
// needs to be passed per session. Changes take effect on the next connect.
var ConfigCmd = &cobra.Command{
	Use:   "config [setting] [value]",
	Short: "Show or change persistent settings",
	Long: `Show or change persistent settings (stored in ~/.blindspot/config.json).

Settings:
  up-mbit   Force a fixed upload cap in Mbit/s. 0 (the default) means
            automatic: the tunnel adapts its rate to the path on its
            own, staying uncapped until real packet loss appears.
            Only set this if automatic shaping misbehaves on your
            link. Applies on the next connect.

Examples:
  blindspot config              show current settings
  blindspot config up-mbit 80   force a fixed 80 Mbit/s cap
  blindspot config up-mbit 0    back to automatic`,
	Args: cobra.MaximumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := utils.LoadConfig()
		if len(args) == 0 {
			if cfg.UpMbit > 0 {
				fmt.Printf("up-mbit: %d (fixed cap)\n", cfg.UpMbit)
			} else {
				fmt.Println("up-mbit: 0 (automatic)")
			}
			return
		}
		if args[0] != "up-mbit" {
			fmt.Printf("Unknown setting %q. Available: up-mbit\n", args[0])
			return
		}
		if len(args) == 1 {
			fmt.Printf("up-mbit: %d\n", cfg.UpMbit)
			return
		}
		v, err := strconv.Atoi(args[1])
		if err != nil || v < 0 {
			fmt.Println("up-mbit must be a non-negative number of Mbit/s")
			return
		}
		cfg.UpMbit = v
		if err := utils.SaveConfig(cfg); err != nil {
			fmt.Println("Error saving config:", err)
			return
		}
		if v == 0 {
			fmt.Println("Upload shaping set to automatic. Takes effect on the next connect.")
		} else {
			fmt.Printf("Upload capped at %d Mbit/s. Takes effect on the next connect.\n", v)
		}
	},
}
