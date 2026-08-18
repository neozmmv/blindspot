package cmd

import (
	"fmt"

	"github.com/neozmmv/blindspot/internal/network"
	bstun "github.com/neozmmv/blindspot/internal/tun"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

func init() {
	IPCmd.Flags().Bool("nat", false, "Probe this network's NAT type instead, and report whether peers can punch through to it")
}

var IPCmd = &cobra.Command{
	Use:   "ip",
	Short: "Print your virtual IP address",
	Run: func(cmd *cobra.Command, args []string) {
		if nat, _ := cmd.Flags().GetBool("nat"); nat {
			printNATMapping()
			return
		}
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

// printNATMapping reports whether this network can be hole-punched into.
//
// Without it, an endpoint-dependent NAT is indistinguishable from any other
// reason a peer never shows up: the address is published, both sides punch, and
// nothing arrives. Naming the cause is the difference between "this cannot work
// here" and an unbounded wait.
func printNATMapping() {
	fmt.Println("Probing NAT mapping behaviour...")
	nat, err := network.ProbeNATMapping()
	if err != nil {
		fmt.Println("Could not determine NAT type:", err)
		return
	}
	fmt.Printf("  %-28s %s\n", nat.Servers[0], nat.Addrs[0])
	fmt.Printf("  %-28s %s\n", nat.Servers[1], nat.Addrs[1])
	fmt.Println()
	if nat.EndpointIndependent {
		fmt.Println("Endpoint-independent mapping: both servers saw the same address,")
		fmt.Println("so peers can reach you at it. Hole punching should work here.")
		return
	}
	fmt.Println("Endpoint-dependent (\"symmetric\") mapping: each destination sees a")
	fmt.Println("different port, so the address published to a room is only ever valid")
	fmt.Println("for the server that reported it, and peers punch at a port nothing is")
	fmt.Println("listening on. Direct connections will not form on this network unless")
	fmt.Println("the peer's side is permissive. A different network (or wired/Wi-Fi")
	fmt.Println("instead of mobile data) is the reliable fix.")
}
