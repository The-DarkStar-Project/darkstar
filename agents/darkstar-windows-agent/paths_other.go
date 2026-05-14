//go:build !windows

package main

import (
	"os"
	"path/filepath"
)

func defaultConfigFile() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".darkstar-windows-agent", "config.json")
}

func defaultStateFile() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".darkstar-windows-agent", "agent.json")
}

func defaultLogFile() string {
	return ""
}
