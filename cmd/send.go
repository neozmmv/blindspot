package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/neozmmv/blindspot/internal/transfer"
	"github.com/spf13/cobra"
)

var SendCmd = &cobra.Command{
	Use:   "send <peer-ip> <file>",
	Short: "Send a file to a peer",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		peerIP := args[0]
		filePath := args[1]

		// Render progress off a goroutine: the first snapshot prints the "Sending…"
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
					fmt.Printf("Sending %s (%s) to %s...\n", p.Name, transfer.FormatBytes(float64(p.Total)), peerIP)
					continue
				}
				fmt.Print("\r" + lr.Line(p))
			}
			close(renderDone)
		}()

		res, err := transfer.Send(context.Background(), peerIP, filePath, prog)
		close(prog)
		<-renderDone

		if enteredBody(err) {
			fmt.Println()
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Done — %s in %s (avg %s/s)\n",
			transfer.FormatBytes(float64(res.Bytes)), res.Elapsed.Round(time.Millisecond),
			transfer.FormatBytes(float64(res.Bytes)/res.Elapsed.Seconds()))
	},
}

// enteredBody reports whether a transfer got as far as streaming the file body — i.e. it
// succeeded, or failed during the copy. It gates the blank line that terminates the live
// progress display, so a failure before the body (dial, header, file create) prints no
// stray blank line, exactly as the pre-refactor CLI did.
func enteredBody(err error) bool {
	if err == nil {
		return true
	}
	var te *transfer.Error
	if errors.As(err, &te) {
		return te.Op == transfer.OpSendBody || te.Op == transfer.OpRecvBody
	}
	return false
}
