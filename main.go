package main

import (
	"github.com/neozmmv/blindspot/cmd"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "blindspot",
	Short: "blindspot: P2P VPN / Toolkit",
}

func init() {
	rootCmd.AddCommand(cmd.CreateCmd)
	rootCmd.AddCommand(cmd.ConnectCmd)
	rootCmd.AddCommand(cmd.DisconnectCmd)
	rootCmd.AddCommand(cmd.ChatCmd)
	rootCmd.AddCommand(cmd.VersionCmd)
}

func main() {
	rootCmd.Execute()
}
