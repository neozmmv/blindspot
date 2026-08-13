// Package tornet starts the Tor process that Blindspot uses for onion-based
// peer discovery, and exposes an HTTP transport routed through its SOCKS proxy.
//
// Tor is run as a subprocess from a bundled executable rather than statically
// linked into the binary. Embedding it (github.com/*/go-libtor) was evaluated
// and rejected: it requires cgo, which would replace six pure-Go cross-compiles
// with six C toolchains (including osxcross plus the Apple SDK for darwin), and
// the current release does not build against glibc >= 2.36 at all — its vendored
// libevent defines an arc4random_buf that now collides with the one glibc has
// shipped since 2022.
package tornet

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cretz/bine/process"
	"github.com/cretz/bine/tor"
)

// BootstrapTimeout bounds the whole start-up. Measured cold starts ranged from
// ~28s to ~187s on identical code, so this is deliberately generous: the failure
// we care about is hanging forever with no output, not being slow once.
const BootstrapTimeout = 4 * time.Minute

// bundleDir is the directory, relative to the running executable, holding the
// bundled tor and the shared libraries it links against. It mirrors the layout
// of the Tor Expert Bundle tarball.
const bundleDir = "tor"

func exeName() string {
	if runtime.GOOS == "windows" {
		return "tor.exe"
	}
	return "tor"
}

// libPathVar is the loader search-path variable for the platform. The Expert
// Bundle's tor carries no RPATH/RUNPATH and dynamically links libssl, libcrypto
// and libevent, so without this the loader silently binds to whatever the host
// happens to have in /lib64 — or fails outright on a host that has nothing.
func libPathVar() string {
	switch runtime.GOOS {
	case "darwin":
		return "DYLD_LIBRARY_PATH"
	case "windows":
		return "" // Windows resolves DLLs from the executable's own directory
	default:
		return "LD_LIBRARY_PATH"
	}
}

// ExePath resolves the tor executable to run. It prefers the copy bundled
// alongside the blindspot binary, and falls back to one on PATH.
//
// The fallback is not just for development: the Tor Project publishes no
// linux-aarch64 Expert Bundle, so linux/arm64 builds have no binary to bundle
// and depend on a system tor.
func ExePath() (string, string, error) {
	baseDir := ""
	if self, err := os.Executable(); err == nil {
		baseDir = filepath.Dir(self)
	}
	return ExePathFrom(baseDir)
}

// ExePathFrom is ExePath with an explicit base directory to look beside, so the
// bundled-vs-PATH precedence can be exercised without reinstalling the test
// binary. It returns the executable and the directory to put on the loader path
// (empty when falling back to a system tor, which brings its own libraries).
func ExePathFrom(baseDir string) (string, string, error) {
	if baseDir != "" {
		bundled := filepath.Join(baseDir, bundleDir, exeName())
		if st, err := os.Stat(bundled); err == nil && !st.IsDir() {
			return bundled, filepath.Dir(bundled), nil
		}
	}

	found, err := exec.LookPath(exeName())
	if err != nil {
		return "", "", fmt.Errorf(
			"no tor executable: expected a bundled one next to blindspot, and none found on PATH")
	}
	return found, "", nil
}

// processCreator builds tor subprocesses with the bundle's library directory on
// the loader path, and with tor's own chatter kept off the CLI's stdout.
func processCreator(exePath, libDir string) process.Creator {
	return process.CmdCreatorFunc(func(ctx context.Context, args ...string) (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, exePath, args...)
		cmd.Env = os.Environ()
		if v := libPathVar(); v != "" && libDir != "" {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", v, libDir))
		}
		// bine's default creator wires these to os.Stdout/os.Stderr, which would
		// interleave tor's log with the CLI's own output.
		cmd.Stdout = nil
		cmd.Stderr = nil
		return cmd, nil
	})
}

// Start launches Tor and waits for it to be usable. The caller must Close the
// returned instance.
func Start(ctx context.Context) (*tor.Tor, error) {
	exePath, libDir, err := ExePath()
	if err != nil {
		return nil, err
	}

	t, err := tor.Start(ctx, &tor.StartConf{
		ProcessCreator:  processCreator(exePath, libDir),
		TempDataDirBase: os.TempDir(),
		// The temp data dir is ours alone; leaving it behind would accumulate a
		// consensus cache per run.
		RetainTempDataDir: false,
	})
	if err != nil {
		return nil, fmt.Errorf("starting tor (%s): %w", exePath, err)
	}
	return t, nil
}

// HTTPTransport returns a transport whose connections are dialled through Tor,
// for reaching a room's onion service.
func HTTPTransport(ctx context.Context, t *tor.Tor) (*http.Transport, error) {
	dialer, err := t.Dialer(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("creating tor dialer: %w", err)
	}
	return &http.Transport{DialContext: dialer.DialContext}, nil
}
