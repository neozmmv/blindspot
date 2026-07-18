package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds persistent user settings, stored as ~/.blindspot/config.json.
// Both the CLI and the tray-launched daemon read it (same user profile, so the
// UAC-elevated daemon sees the same file), which is what makes a setting like
// the upload cap stick without passing flags on every connect.
type Config struct {
	// UpMbit paces the tunnel's upload at this many Mbit/s. 0 means uncapped.
	// Set it to ~90% of the machine's real uplink so tunnelled TCP transfers
	// don't overflow the bottleneck queue in line-rate bursts.
	UpMbit int `json:"up_mbit,omitempty"`
}

func configPath() string { return filepath.Join(GetBlindspotDir(), "config.json") }

// LoadConfig reads the config file. A missing or unreadable file yields the
// zero Config — settings are always optional.
func LoadConfig() Config {
	var c Config
	data, err := os.ReadFile(configPath())
	if err != nil {
		return c
	}
	json.Unmarshal(data, &c)
	return c
}

// SaveConfig writes the config file, creating ~/.blindspot if needed.
func SaveConfig(c Config) error {
	if err := os.MkdirAll(GetBlindspotDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), data, 0600)
}
