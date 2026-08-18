package utils

import (
	"errors"
	"os/user"
	"testing"
)

// fixedUser stands in for the passwd database.
func fixedUser(u *user.User, err error) func(string, string) (*user.User, error) {
	return func(string, string) (*user.User, error) { return u, err }
}

func TestResolveInvoker(t *testing.T) {
	neoz := &user.User{Uid: "1000", Gid: "1000", Username: "neoz", HomeDir: "/home/neoz"}
	sudoEnv := func(k string) string {
		switch k {
		case "SUDO_UID":
			return "1000"
		case "SUDO_GID":
			return "1000"
		case "SUDO_USER":
			return "neoz"
		}
		return ""
	}
	noEnv := func(string) string { return "" }

	tests := []struct {
		name   string
		euid   int
		getenv func(string) string
		lookup func(string, string) (*user.User, error)
		wantOK bool
		want   sudoInvoker
	}{
		{
			name:   "unprivileged process is nobody's proxy",
			euid:   1000,
			getenv: sudoEnv,
			lookup: fixedUser(neoz, nil),
		},
		{
			// A root login owns /root, so leave it alone.
			name:   "root without sudo",
			euid:   0,
			getenv: noEnv,
			lookup: fixedUser(neoz, nil),
		},
		{
			name:   "root via sudo",
			euid:   0,
			getenv: sudoEnv,
			lookup: fixedUser(neoz, nil),
			wantOK: true,
			want:   sudoInvoker{home: "/home/neoz", uid: 1000, gid: 1000},
		},
		{
			// sudo always sets SUDO_GID, but the passwd entry is a fine backstop.
			name: "gid falls back to the passwd entry",
			euid: 0,
			getenv: func(k string) string {
				if k == "SUDO_GID" {
					return ""
				}
				return sudoEnv(k)
			},
			lookup: fixedUser(neoz, nil),
			wantOK: true,
			want:   sudoInvoker{home: "/home/neoz", uid: 1000, gid: 1000},
		},
		{
			name:   "unresolvable user leaves the old behaviour in place",
			euid:   0,
			getenv: sudoEnv,
			lookup: fixedUser(nil, errors.New("no such user")),
		},
		{
			name:   "sudo from root itself is not a translation",
			euid:   0,
			getenv: func(k string) string { return map[string]string{"SUDO_UID": "0"}[k] },
			lookup: fixedUser(&user.User{Uid: "0", Gid: "0", HomeDir: "/root"}, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := resolveInvoker(tt.euid, tt.getenv, tt.lookup)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Fatalf("invoker = %+v, want %+v", got, tt.want)
			}
		})
	}
}
