package cmd

import (
	"fmt"

	"runtime/debug"

	"github.com/spf13/cobra"
)

var Version = "dev"

func getVersion() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return Version
}

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of blindspot",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("blindspot %s\n", getVersion())
	},
}
