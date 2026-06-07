//update_linux.go

package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var bashScript = `
#!/usr/bin/env bash
set -e

REPO="neozmmv/blindspot"
INSTALL_DIR="/usr/local/bin"

ARCH=$(uname -m)
case $ARCH in
    x86_64)          ARCH="amd64" ;;
    aarch64 | arm64) ARCH="arm64" ;;
    *) echo "unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
    echo "this script is for Linux only — use install.ps1 on Windows"
    exit 1
fi

URL="https://github.com/$REPO/releases/latest/download/blindspot-linux-$ARCH"
echo "downloading latest blindspot ($ARCH)..."

TMP=$(mktemp)
curl -fsSL "$URL" -o "$TMP"
chmod +x "$TMP"

if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP" "$INSTALL_DIR/blindspot"
else
    echo "installing to $INSTALL_DIR (requires sudo)..."
    sudo mv "$TMP" "$INSTALL_DIR/blindspot"
fi

echo "installed to $INSTALL_DIR/blindspot"
`

func init() {
	rootCmd.AddCommand(updateLinuxCmd)
}

var updateLinuxCmd = &cobra.Command{
	Use:   "update",
	Short: "Update blindspot",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting blindspot update...")
		scriptCmd := exec.Command("bash", "-c", bashScript)
		scriptCmd.Stdout = os.Stdout
		scriptCmd.Stderr = os.Stderr
		err := scriptCmd.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error occurred while updating blindspot: %v\n", err)
			os.Exit(1)
		}
	},
}
