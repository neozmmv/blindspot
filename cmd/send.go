package cmd

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

const transferPort = ":28125"

var SendCmd = &cobra.Command{
	Use:   "send <peer-ip> <file>",
	Short: "Send a file to a peer",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		peerIP := args[0]
		filePath := args[1]

		f, err := os.Open(filePath)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer f.Close()

		info, err := f.Stat()
		if err != nil {
			fmt.Println("Error reading file info:", err)
			return
		}

		conn, err := net.DialTimeout("tcp", peerIP+transferPort, 5*time.Second)
		if err != nil {
			fmt.Printf("Peer %s is not receiving. Ask them to run 'blindspot receive'.\n", peerIP)
			return
		}
		defer conn.Close()
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetWriteBuffer(1 << 20) // 1 MB
			tc.SetReadBuffer(1 << 20)
		}

		name := []byte(filepath.Base(filePath))
		if err := binary.Write(conn, binary.BigEndian, uint16(len(name))); err != nil {
			fmt.Println("Error sending filename length:", err)
			return
		}
		if _, err := conn.Write(name); err != nil {
			fmt.Println("Error sending filename:", err)
			return
		}
		if err := binary.Write(conn, binary.BigEndian, uint64(info.Size())); err != nil {
			fmt.Println("Error sending file size:", err)
			return
		}

		fmt.Printf("Sending %s (%s) to %s...\n", info.Name(), formatBytes(float64(info.Size())), peerIP)
		// wrap the file (not the conn) so the dst stays a bare *net.TCPConn
		// and the Go runtime can use sendfile(2) for zero-copy transfer
		pr := &progressReader{r: f}
		stop := startProgress(info.Size(), pr)
		start := time.Now()
		n, err := io.Copy(conn, pr)
		stop()
		fmt.Println()
		if err != nil {
			fmt.Println("Error sending file:", err)
			return
		}
		elapsed := time.Since(start)
		fmt.Printf("Done — %s in %s (avg %s/s)\n",
			formatBytes(float64(n)), elapsed.Round(time.Millisecond),
			formatBytes(float64(n)/elapsed.Seconds()))
	},
}
