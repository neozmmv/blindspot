package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/neozmmv/blindspot/internal/transfer"
	bstun "github.com/neozmmv/blindspot/internal/tun"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

var ReceiveCmd = &cobra.Command{
	Use:   "receive",
	Short: "Receive a file from a peer (saved to Downloads by default)",
	Run: func(cmd *cobra.Command, args []string) {
		here, _ := cmd.Flags().GetBool("here")

		// Receiving only needs the virtual IP, derived from the public key, so we
		// read just the public key — no passphrase required even if encrypted.
		publicKey, err := utils.ReadPublicKey()
		if err != nil {
			fmt.Println("No identity found. Run 'blindspot connect' first.")
			return
		}

		var destDir string
		if here {
			destDir, err = os.Getwd()
			if err != nil {
				fmt.Println("Error getting current directory:", err)
				return
			}
		} else {
			destDir, err = transfer.DownloadsDir()
			if err != nil {
				fmt.Println(err)
				return
			}
		}

		myIP := bstun.VirtualIPv4(publicKey)
		recv, err := transfer.Listen(context.Background(), myIP)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer recv.Close()

		fmt.Printf("Waiting for file on %s...\n", recv.Addr())

		// Render progress off a goroutine: the first snapshot prints the "Receiving…"
		// header, later snapshots overwrite a single live line via carriage return.
		prog := make(chan transfer.Progress, 1)
		renderDone := make(chan struct{})
		go func() {
			var lr transfer.LineRenderer
			first := true
			for p := range prog {
				if first {
					first = false
					lr.Seed(p)
					fmt.Printf("Receiving %s (%d MB) from %s...\n", p.Name, p.Total/(1024*1024), p.PeerAddr)
					continue
				}
				fmt.Print("\r" + lr.Line(p))
			}
			close(renderDone)
		}()

		res, err := recv.Accept(context.Background(), destDir, prog)
		close(prog)
		<-renderDone

		if enteredBody(err) {
			fmt.Println()
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Saved to %s — %s in %s (avg %s/s)\n",
			res.Path, transfer.FormatBytes(float64(res.Bytes)), res.Elapsed.Round(time.Millisecond),
			transfer.FormatBytes(float64(res.Bytes)/res.Elapsed.Seconds()))
	},
}

func init() {
	ReceiveCmd.Flags().Bool("here", false, "Save file to current directory instead of Downloads")
}
