package utils

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
)

// GetBlindspotDir returns the directory holding this machine's identity, config
// and live session state: ~/.blindspot of the user blindspot is acting for.
//
// On Linux "acting for" is not the same as "running as". The session daemon
// needs root to open the TUN device, so it is started with sudo — but its state
// belongs to whoever typed the command. Resolving the directory from the
// process's own $HOME would split every install in two: the daemon writing
// session.pid, peers.json and stats.log into /root/.blindspot while the user's
// unprivileged `blindspot list` reads ~/.blindspot and reports no active
// session, and the two reading different identity.json files, so the machine's
// static key and virtual IP would change with how it was launched.
//
// Windows never had the problem: UAC elevation keeps the same user profile.
func GetBlindspotDir() string {
	if inv, ok := invoker(); ok {
		return filepath.Join(inv.home, ".blindspot")
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(homeDir, ".blindspot")
}

// EnsureStateDir creates the state directory if it is missing, owned by the
// invoking user rather than by root.
func EnsureStateDir() error {
	dir := GetBlindspotDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	chownToInvoker(dir)
	return nil
}

// WriteStateFile writes a file in the state directory, creating the directory
// first and leaving the result owned by the invoking user.
//
// The ownership half matters as much as the path: a 0600 file the root daemon
// wrote into the user's own ~/.blindspot would be root's, and unreadable to the
// unprivileged CLI that has to read it back.
func WriteStateFile(path string, data []byte, perm os.FileMode) error {
	if err := EnsureStateDir(); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	chownToInvoker(path)
	return nil
}

// CreateStateFile creates or truncates a file in the state directory, owned by
// the invoking user, and returns it open for writing.
func CreateStateFile(path string, perm os.FileMode) (*os.File, error) {
	if err := EnsureStateDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return nil, err
	}
	chownToInvoker(path)
	return f, nil
}

// chownToInvoker hands a path the root daemon created back to the user it
// belongs to. Best effort: if it fails the file is merely root's again, and
// there is nothing useful for the call site to do about it.
func chownToInvoker(path string) {
	if inv, ok := invoker(); ok {
		os.Chown(path, inv.uid, inv.gid) // gid -1 leaves the group alone
	}
}

// sudoInvoker is the unprivileged user a root process is acting on behalf of.
type sudoInvoker struct {
	home string
	uid  int
	gid  int // -1 when unknown, which os.Chown reads as "leave unchanged"
}

// invoker reports the user behind a sudo invocation, and whether there is one
// at all. Resolved once: it is derived from the environment, which does not
// change under us, and the passwd lookup is not worth repeating per file.
var invoker = sync.OnceValues(lookupInvoker)

func lookupInvoker() (sudoInvoker, bool) {
	return resolveInvoker(os.Geteuid(), os.Getenv, lookupUser)
}

// lookupUser finds a user by id, falling back to their name: a directory-service
// user may not resolve by id in a CGO_ENABLED=0 build, which reads /etc/passwd
// directly, while the name usually still works.
func lookupUser(uid, name string) (*user.User, error) {
	if u, err := user.LookupId(uid); err == nil {
		return u, nil
	}
	return user.Lookup(name)
}

// resolveInvoker finds the user sudo elevated from.
//
// It deliberately reports nothing in two cases: when we are not root (there is
// nothing to translate) and when root is genuine rather than borrowed — a real
// root login leaves SUDO_* unset, and there /root is the correct home. sudo
// itself resets HOME to root's, which is why the home directory has to come
// from the passwd database rather than the environment.
func resolveInvoker(euid int, getenv func(string) string, lookup func(uid, name string) (*user.User, error)) (sudoInvoker, bool) {
	if euid != 0 {
		return sudoInvoker{}, false
	}
	uidStr := getenv("SUDO_UID")
	uid, err := strconv.Atoi(uidStr)
	if err != nil || uid == 0 {
		return sudoInvoker{}, false
	}

	inv := sudoInvoker{uid: uid, gid: -1}
	if gid, err := strconv.Atoi(getenv("SUDO_GID")); err == nil {
		inv.gid = gid
	}

	u, err := lookup(uidStr, getenv("SUDO_USER"))
	if err != nil || u.HomeDir == "" {
		// Without a home directory there is no state directory to point at, so
		// fall back to the old behaviour rather than guessing at a path.
		return sudoInvoker{}, false
	}
	inv.home = u.HomeDir
	if inv.gid < 0 {
		if gid, err := strconv.Atoi(u.Gid); err == nil {
			inv.gid = gid
		}
	}
	return inv, true
}
