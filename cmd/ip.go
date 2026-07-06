package cmd

import (
	"fmt"

	bstun "github.com/neozmmv/blindspot/internal/tun"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

var IPCmd = &cobra.Command{
	Use:   "ip",
	Short: "Print your virtual IP address",
	Run: func(cmd *cobra.Command, args []string) {
		// Only the public key is needed here, so use ReadPublicKey — it works even
		// when the identity is encrypted at rest, without the passphrase.
		publicKey, err := utils.ReadPublicKey()
		if err != nil {
			keyPair, err := utils.InitIdentity()
			if err != nil {
				fmt.Println("Error initializing identity:", err)
				return
			}
			publicKey = keyPair.PublicKey
		}
		fmt.Println(bstun.VirtualIPv4(publicKey))
	},
}
