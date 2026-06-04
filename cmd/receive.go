package cmd

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	bstun "github.com/neozmmv/blindspot/internal/tun"
	"github.com/neozmmv/blindspot/internal/utils"
	"github.com/spf13/cobra"
)

var ReceiveCmd = &cobra.Command{
	Use:   "receive",
	Short: "Receive a file from a peer (saved to Downloads by default)",
	Run: func(cmd *cobra.Command, args []string) {
		here, _ := cmd.Flags().GetBool("here")

		_, publicKey, err := utils.ReadIdentity()
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
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Println("Error finding home directory:", err)
				return
			}
			destDir = filepath.Join(home, "Downloads")
			if err := os.MkdirAll(destDir, 0755); err != nil {
				fmt.Println("Error creating Downloads directory:", err)
				return
			}
		}

		myIP := bstun.VirtualIPv4(publicKey)
		ln, err := net.Listen("tcp", myIP+transferPort)
		if err != nil {
			fmt.Printf("Could not listen on %s: %v\n", myIP+transferPort, err)
			return
		}
		defer ln.Close()

		fmt.Printf("Waiting for file on %s...\n", myIP+transferPort)

		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			return
		}
		defer conn.Close()

		var nameLen uint16
		if err := binary.Read(conn, binary.BigEndian, &nameLen); err != nil {
			fmt.Println("Error reading filename length:", err)
			return
		}
		nameBuf := make([]byte, nameLen)
		if _, err := io.ReadFull(conn, nameBuf); err != nil {
			fmt.Println("Error reading filename:", err)
			return
		}

		var fileSize uint64
		if err := binary.Read(conn, binary.BigEndian, &fileSize); err != nil {
			fmt.Println("Error reading file size:", err)
			return
		}

		filename := string(nameBuf)
		destPath := filepath.Join(destDir, filename)
		fmt.Printf("Receiving %s (%d bytes) from %s...\n", filename, fileSize, conn.RemoteAddr())

		f, err := os.Create(destPath)
		if err != nil {
			fmt.Println("Error creating file:", err)
			return
		}
		defer f.Close()

		n, err := io.CopyN(f, conn, int64(fileSize))
		if err != nil {
			fmt.Printf("Error receiving file (got %d/%d bytes): %v\n", n, fileSize, err)
			return
		}
		fmt.Printf("Saved to %s (%d bytes).\n", destPath, n)
	},
}

func init() {
	ReceiveCmd.Flags().Bool("here", false, "Save file to current directory instead of Downloads")
}
