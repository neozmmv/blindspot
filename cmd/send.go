package cmd

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

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

		conn, err := net.Dial("tcp", peerIP+transferPort)
		if err != nil {
			fmt.Printf("Could not connect to %s: %v\n", peerIP, err)
			return
		}
		defer conn.Close()

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

		fmt.Printf("Sending %s (%d bytes) to %s...\n", info.Name(), info.Size(), peerIP)
		n, err := io.Copy(conn, f)
		if err != nil {
			fmt.Println("Error sending file:", err)
			return
		}
		fmt.Printf("Sent %d bytes.\n", n)
	},
}
