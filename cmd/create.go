package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new blindspot network",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Creating a new blindspot network...")
	},
}
