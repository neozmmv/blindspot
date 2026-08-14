package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "blindspot",
	Short: `
██████╗ ██╗     ██╗███╗   ██╗██████╗ ███████╗██████╗  ██████╗ ████████╗
██╔══██╗██║     ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔═══██╗╚══██╔══╝
██████╔╝██║     ██║██╔██╗ ██║██║  ██║███████╗██████╔╝██║   ██║   ██║   
██╔══██╗██║     ██║██║╚██╗██║██║  ██║╚════██║██╔═══╝ ██║   ██║   ██║   
██████╔╝███████╗██║██║ ╚████║██████╔╝███████║██║     ╚██████╔╝   ██║   
╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝      ╚═════╝    ╚═╝   
                                                                                       
P2P Toolkit: VPN, File Sharing, Chat, and More
	`,
}

func init() {
	rootCmd.AddCommand(ConnectCmd)
	rootCmd.AddCommand(RendezvousCmd)
	rootCmd.AddCommand(DisconnectCmd)
	rootCmd.AddCommand(ListCmd)
	rootCmd.AddCommand(ChatCmd)
	rootCmd.AddCommand(IPCmd)
	rootCmd.AddCommand(SendCmd)
	rootCmd.AddCommand(ReceiveCmd)
	rootCmd.AddCommand(IdentityCmd)
	rootCmd.AddCommand(ConfigCmd)
	rootCmd.AddCommand(VersionCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
