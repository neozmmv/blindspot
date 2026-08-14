//update_linux.go

package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// bashScript is the Linux updater: it swaps the binary and then makes sure Tor
// is present, since a release installed before the room commands existed — or by
// any means other than scripts/install.sh — has no Tor to run.
//
// It mirrors scripts/install.sh, which is what a fresh install runs. The two are
// separate copies (the script cannot be embedded from outside this package's
// directory tree), so a change to the Tor logic in one belongs in the other.
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

# --- Tor -------------------------------------------------------------------
#
# 'blindspot connect' and 'blindspot chat' run Tor as a subprocess to reach a
# room's onion service. They look for a bundled copy next to the binary first,
# then fall back to one on PATH — which is what this installs. 'blindspot
# rendezvous' does not need Tor at all, so a failure here is a warning, not a
# fatal error.

as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

install_tor() {
    if command -v apt-get >/dev/null 2>&1; then
        as_root apt-get update -qq && as_root apt-get install -y tor
    elif command -v dnf >/dev/null 2>&1; then
        as_root dnf install -y tor
    elif command -v yum >/dev/null 2>&1; then
        as_root yum install -y tor
    elif command -v pacman >/dev/null 2>&1; then
        as_root pacman -Sy --noconfirm tor
    elif command -v zypper >/dev/null 2>&1; then
        as_root zypper --non-interactive install tor
    elif command -v apk >/dev/null 2>&1; then
        as_root apk add --no-cache tor
    else
        return 1
    fi
}

if [ -x "$INSTALL_DIR/tor/tor" ]; then
    echo "tor already present alongside blindspot"
elif command -v tor >/dev/null 2>&1; then
    echo "tor already present: $(command -v tor)"
else
    echo ""
    echo "'blindspot connect' needs Tor; installing it..."
    # Not under 'set -e': blindspot is already updated and usable without Tor.
    if install_tor; then
        if command -v tor >/dev/null 2>&1; then
            echo "tor installed: $(command -v tor)"
            # Debian and Ubuntu enable and start tor.service on install. Blindspot
            # spawns its own instance on its own control port and does not use the
            # system service, so it can be disabled if it is not otherwise wanted:
            #   sudo systemctl disable --now tor
        else
            echo "warning: the tor package installed but 'tor' is not on PATH."
        fi
    else
        echo "warning: could not detect a supported package manager."
        echo "         install Tor manually for 'blindspot connect' and"
        echo "         'blindspot chat' — 'blindspot rendezvous' works without it."
    fi
fi
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
