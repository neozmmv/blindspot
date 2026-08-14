package cmd

import (
	"fmt"
	"os"

	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

func passphraseFromEnv() []byte {
	return []byte(os.Getenv(utils.IdentityPassphraseEnv))
}

var IdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage the on-disk identity (encrypt/decrypt the private key at rest)",
}

var identityStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether the identity is encrypted at rest",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IdentityExists() {
			fmt.Println("No identity found. Run 'blindspot connect' or 'blindspot ip' to create one.")
			return
		}
		encrypted, err := utils.IsIdentityEncrypted()
		if err != nil {
			fmt.Println("Error reading identity:", err)
			return
		}
		if encrypted {
			fmt.Println("Identity is ENCRYPTED at rest.")
		} else {
			fmt.Println("Identity is stored in PLAINTEXT.")
		}
	},
}

var identityEncryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt the identity at rest using the passphrase in " + utils.IdentityPassphraseEnv,
	Run: func(cmd *cobra.Command, args []string) {
		passphrase := passphraseFromEnv()
		if len(passphrase) == 0 {
			fmt.Printf("Set %s to the passphrase you want to use, then run this again.\n", utils.IdentityPassphraseEnv)
			return
		}
		if err := utils.RewriteIdentity(passphrase); err != nil {
			fmt.Println("Error encrypting identity:", err)
			return
		}
		fmt.Println("Identity encrypted at rest.")
	},
}

var identityDecryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt the identity back to plaintext (requires " + utils.IdentityPassphraseEnv + ")",
	Run: func(cmd *cobra.Command, args []string) {
		if err := utils.RewriteIdentity(nil); err != nil {
			fmt.Println("Error decrypting identity:", err)
			return
		}
		fmt.Println("Identity stored in plaintext.")
	},
}

func init() {
	IdentityCmd.AddCommand(identityStatusCmd)
	IdentityCmd.AddCommand(identityEncryptCmd)
	IdentityCmd.AddCommand(identityDecryptCmd)
}
