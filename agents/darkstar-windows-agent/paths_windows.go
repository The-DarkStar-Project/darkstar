//go:build windows

package main

import (
	"os"
	"path/filepath"
)

func programDataDir() string {
	if value := os.Getenv("ProgramData"); value != "" {
		return filepath.Join(value, "Darkstar", "EndpointAgent")
	}
	return `C:\ProgramData\Darkstar\EndpointAgent`
}

func defaultConfigFile() string {
	return filepath.Join(programDataDir(), "config.json")
}

func defaultStateFile() string {
	return filepath.Join(programDataDir(), "agent.json")
}

func defaultLogFile() string {
	return filepath.Join(programDataDir(), "logs", "agent.log")
}
