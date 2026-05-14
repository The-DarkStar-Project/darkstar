//go:build !windows

package main

import (
	"context"
	"errors"
)

func runServiceOrLoop(opts options) error {
	return runLoop(context.Background(), opts)
}

func runInstall(options) error {
	return errors.New("service install is only supported on Windows")
}

func runUninstall(string) error {
	return errors.New("service uninstall is only supported on Windows")
}

func runServiceStart(string) error {
	return errors.New("service start is only supported on Windows")
}

func runServiceStop(string) error {
	return errors.New("service stop is only supported on Windows")
}
