//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func collectInventory(peerTargets []ProbeTarget) (Inventory, error) {
	osInfo := collectOSInfo()
	programs := collectWindowsPrograms()
	patches := collectWindowsPatches()
	ips, macs := collectNetworkIDs()
	networkProbe := collectNetworkProbe(peerTargets)
	software := make([]SoftwareItem, 0, len(programs)+len(patches)+1)
	if build := stringValue(osInfo["build"]); build != "" {
		software = append(software, SoftwareItem{
			Name:         firstNonEmpty(stringValue(osInfo["name"]), "Microsoft Windows"),
			Version:      build,
			Vendor:       "Microsoft",
			Ecosystem:    "windows_os",
			Architecture: stringValue(osInfo["arch"]),
			Source:       "windows_registry",
			PackageType:  "windows_os",
			PURL:         "pkg:generic/microsoft/windows@" + purlVersion(build),
			Raw:          map[string]interface{}(osInfo),
		})
	}
	software = append(software, programs...)
	software = append(software, patches...)
	hostname, _ := os.Hostname()
	return Inventory{
		OS:           osInfo,
		Software:     software,
		IPAddresses:  ips,
		MACAddresses: macs,
		NetworkProbe: networkProbe,
		Metadata: map[string]interface{}{
			"hostname":          firstNonEmpty(stringValue(osInfo["hostname"]), hostname),
			"collector":         "darkstar_windows_agent",
			"collector_version": agentVersion,
			"native":            true,
			"network_probe": map[string]interface{}{
				"version": 1,
				"mode":    "neighbor-cache+gateway+endpoint-peers",
			},
		},
	}, nil
}

func collectOSInfo() OSInfo {
	hostname, _ := os.Hostname()
	info := OSInfo{
		"hostname": hostname,
		"platform": "windows",
		"name":     "Microsoft Windows",
		"version":  "",
		"arch":     runtime.GOARCH,
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return info
	}
	defer key.Close()
	productName := registryString(key, "ProductName")
	displayVersion := registryString(key, "DisplayVersion")
	releaseID := registryString(key, "ReleaseId")
	buildNumber := registryString(key, "CurrentBuildNumber")
	ubr, _, _ := key.GetIntegerValue("UBR")
	build := windowsBuildVersion(buildNumber, ubr)
	info["name"] = firstNonEmpty(productName, "Microsoft Windows")
	info["version"] = firstNonEmpty(displayVersion, releaseID, build)
	info["display_version"] = displayVersion
	info["release_id"] = releaseID
	info["build"] = build
	info["build_number"] = buildNumber
	info["ubr"] = ubr
	info["installation_type"] = registryString(key, "InstallationType")
	info["edition"] = registryString(key, "EditionID")
	info["build_lab"] = registryString(key, "BuildLabEx")
	return info
}

func collectWindowsPrograms() []SoftwareItem {
	paths := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	seen := map[string]bool{}
	var items []SoftwareItem
	for _, source := range paths {
		key, err := registry.OpenKey(source.root, source.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := key.ReadSubKeyNames(-1)
		key.Close()
		if err != nil {
			continue
		}
		for _, subName := range names {
			subKey, err := registry.OpenKey(source.root, source.path+`\`+subName, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name := registryString(subKey, "DisplayName")
			if name == "" {
				subKey.Close()
				continue
			}
			version := registryString(subKey, "DisplayVersion")
			publisher := registryString(subKey, "Publisher")
			location := registryString(subKey, "InstallLocation")
			subKey.Close()
			identity := strings.ToLower(name + "|" + version + "|" + publisher + "|" + subName)
			if seen[identity] {
				continue
			}
			seen[identity] = true
			items = append(items, SoftwareItem{
				Name:            name,
				Version:         version,
				Vendor:          publisher,
				Ecosystem:       "windows_program",
				InstallLocation: location,
				Source:          "windows_uninstall_registry",
				PackageType:     "windows_program",
				Raw: map[string]interface{}{
					"name":               name,
					"version":            version,
					"publisher":          publisher,
					"install_location":   location,
					"identifying_number": subName,
					"registry_path":      source.path + `\` + subName,
				},
			})
		}
	}
	return items
}

func collectWindowsPatches() []SoftwareItem {
	command := `Get-HotFix | Select-Object @{n='hotfix_id';e={$_.HotFixID}},@{n='caption';e={$_.Description}},@{n='installed_on';e={$_.InstalledOn}} | ConvertTo-Json -Compress`
	output, err := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command).Output()
	if err != nil || len(strings.TrimSpace(string(output))) == 0 {
		return nil
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(output, &rows); err != nil {
		var row map[string]interface{}
		if err := json.Unmarshal(output, &row); err != nil {
			return nil
		}
		rows = []map[string]interface{}{row}
	}
	items := make([]SoftwareItem, 0, len(rows))
	for _, row := range rows {
		hotfix := stringValue(row["hotfix_id"])
		if hotfix == "" {
			continue
		}
		items = append(items, SoftwareItem{
			Name:        hotfix,
			Version:     stringValue(row["installed_on"]),
			Vendor:      "Microsoft",
			Ecosystem:   "windows_kb",
			Source:      "get_hotfix",
			PackageType: "windows_kb",
			Raw:         row,
		})
	}
	return items
}

func collectNetworkIDs() ([]string, []string) {
	var ips []string
	var macs []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return ips, macs
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if mac := iface.HardwareAddr.String(); mac != "" {
			macs = append(macs, mac)
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil || ip == nil || ip.IsLoopback() {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return ips, macs
}

func registryString(key registry.Key, name string) string {
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func windowsBuildVersion(build string, ubr uint64) string {
	build = strings.TrimSpace(build)
	if build == "" {
		return ""
	}
	if strings.Count(build, ".") >= 2 {
		return build
	}
	if ubr > 0 {
		return fmt.Sprintf("10.0.%s.%d", build, ubr)
	}
	return "10.0." + build
}
