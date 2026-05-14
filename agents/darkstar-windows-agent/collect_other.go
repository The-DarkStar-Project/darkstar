//go:build !windows

package main

import (
	"errors"
)

func collectInventory(_ []ProbeTarget) (Inventory, error) {
	return Inventory{}, errors.New("darkstar-windows-agent inventory collection is only implemented for Windows")
}
