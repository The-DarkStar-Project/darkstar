//go:build windows

package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const securityCheckSchemaVersion = "1"
const postureSoftwareKey = "darkstar-security-posture"

func failedSecurityCheck(id string, confidence int, evidence map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"id":         id,
		"passed":     false,
		"confidence": confidence,
		"evidence":   evidence,
	}
}

func collectSecurityChecks() []map[string]interface{} {
	checks := []map[string]interface{}{}

	if autoLogon := registryStringPath(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "AutoAdminLogon"); strings.TrimSpace(autoLogon) == "1" &&
		registryValueExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "DefaultPassword") {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-AUTOLOGON-PASSWORD", 95, map[string]interface{}{
			"registry_path":            `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			"password_value_collected": false,
		}))
	}
	if value, ok := registryDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential"); ok && value == 1 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-WDIGEST-CREDENTIAL-CACHING", 90, map[string]interface{}{
			"registry_value": `WDigest\UseLogonCredential`,
			"value":          value,
		}))
	}
	hklmElevated, hklmElevatedOK := registryDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated")
	hkcuElevated, hkcuElevatedOK := registryDWORD(registry.CURRENT_USER, `SOFTWARE\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated")
	if hklmElevatedOK && hkcuElevatedOK && hklmElevated == 1 && hkcuElevated == 1 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-ALWAYS-INSTALL-ELEVATED", 90, map[string]interface{}{
			"hklm": hklmElevated,
			"hkcu": hkcuElevated,
		}))
	}
	if value, ok := registryDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA"); ok && value == 0 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-UAC-DISABLED", 90, map[string]interface{}{
			"registry_value": `Policies\System\EnableLUA`,
			"value":          value,
		}))
	}
	if value, ok := registryDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections"); ok && value == 0 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-RDP-ENABLED", 90, map[string]interface{}{
			"registry_value": `Terminal Server\fDenyTSConnections`,
			"value":          value,
		}))
		if nla, nlaOK := registryDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication"); nlaOK && nla == 0 {
			checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-RDP-NLA-DISABLED", 90, map[string]interface{}{
				"registry_value": `RDP-Tcp\UserAuthentication`,
				"value":          nla,
			}))
		}
	}
	if value, ok := registryDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation`, "AllowInsecureGuestAuth"); ok && value == 1 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-INSECURE-GUEST-SMB", 90, map[string]interface{}{
			"registry_value": `LanmanWorkstation\AllowInsecureGuestAuth`,
			"value":          value,
		}))
	}
	if value, ok := registryDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "NoLMHash"); ok && value == 0 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-LM-HASH-STORAGE", 90, map[string]interface{}{
			"registry_value": `Lsa\NoLMHash`,
			"value":          value,
		}))
	}
	if value, ok := registryDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1"); ok && value == 1 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-SMBV1-ENABLED", 90, map[string]interface{}{
			"registry_value": `LanmanServer\Parameters\SMB1`,
			"value":          value,
		}))
	}
	if value, ok := registryDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "LocalAccountTokenFilterPolicy"); ok && value == 1 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-LOCALACCOUNT-TOKEN-FILTER", 90, map[string]interface{}{
			"registry_value": `Policies\System\LocalAccountTokenFilterPolicy`,
			"value":          value,
		}))
	}

	state := windowsSecurityPowerShellState()
	checks = append(checks, windowsAccountChecks(state)...)
	checks = append(checks, windowsServiceChecks(state)...)
	checks = append(checks, windowsFirewallChecks(state)...)
	checks = append(checks, windowsPasswordPolicyChecks(state)...)

	collectedAt := time.Now().UTC().Format(time.RFC3339)
	for _, check := range checks {
		if _, ok := check["collected_at"]; !ok {
			check["collected_at"] = collectedAt
		}
	}
	return checks
}

func registryDWORD(root registry.Key, path string, name string) (uint64, bool) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue(name)
	return value, err == nil
}

func registryStringPath(root registry.Key, path string, name string) string {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	return registryString(key, name)
}

func registryValueExists(root registry.Key, path string, name string) bool {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return false
	}
	for _, valueName := range names {
		if strings.EqualFold(valueName, name) {
			return true
		}
	}
	return false
}

func windowsSecurityPowerShellState() map[string]interface{} {
	command := `
$ErrorActionPreference = 'SilentlyContinue'
$users = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
  Select-Object Name, SID, Disabled, PasswordRequired)
$services = @(Get-CimInstance Win32_Service |
  Where-Object {
    $_.PathName -and
    $_.PathName.Contains(' ') -and
    -not $_.PathName.TrimStart().StartsWith('"') -and
    $_.PathName -match '^[A-Za-z]:\\'
  } |
  Select-Object -First 20 Name, StartName, PathName)
$firewall = @(Get-NetFirewallProfile | Select-Object Name, Enabled)
$netAccounts = ""
try { $netAccounts = (net accounts | Out-String) } catch {}
[pscustomobject]@{
  Users = $users
  UnquotedServices = $services
  FirewallProfiles = $firewall
  NetAccounts = $netAccounts
} | ConvertTo-Json -Depth 5 -Compress
`
	output, err := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command).Output()
	if err != nil || len(strings.TrimSpace(string(output))) == 0 {
		return map[string]interface{}{}
	}
	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		return map[string]interface{}{}
	}
	return data
}

func windowsAccountChecks(state map[string]interface{}) []map[string]interface{} {
	users := listOfMaps(state["Users"])
	noPasswordUsers := []string{}
	builtinAdmins := []string{}
	for _, user := range users {
		if boolValue(user["Disabled"]) {
			continue
		}
		name := stringValue(user["Name"])
		if value, ok := user["PasswordRequired"].(bool); ok && !value {
			noPasswordUsers = append(noPasswordUsers, name)
		}
		if strings.HasSuffix(stringValue(user["SID"]), "-500") {
			builtinAdmins = append(builtinAdmins, name)
		}
	}

	checks := []map[string]interface{}{}
	if len(noPasswordUsers) > 0 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-PASSWORD-NOT-REQUIRED", 90, map[string]interface{}{
			"account_count": len(noPasswordUsers),
			"accounts":      limitStrings(noPasswordUsers, 20),
		}))
	}
	if len(builtinAdmins) > 0 {
		checks = append(checks, failedSecurityCheck("DARKSTAR-WINDOWS-BUILTIN-ADMIN-ENABLED", 90, map[string]interface{}{
			"account_count": len(builtinAdmins),
			"accounts":      limitStrings(builtinAdmins, 20),
		}))
	}
	return checks
}

func windowsServiceChecks(state map[string]interface{}) []map[string]interface{} {
	services := listOfMaps(state["UnquotedServices"])
	if len(services) == 0 {
		return nil
	}
	examples := []map[string]interface{}{}
	for _, service := range services {
		if len(examples) >= 10 {
			break
		}
		path := stringValue(service["PathName"])
		if len(path) > 500 {
			path = path[:500]
		}
		examples = append(examples, map[string]interface{}{
			"name":   stringValue(service["Name"]),
			"run_as": stringValue(service["StartName"]),
			"path":   path,
		})
	}
	return []map[string]interface{}{
		failedSecurityCheck("DARKSTAR-WINDOWS-UNQUOTED-SERVICE-PATH", 90, map[string]interface{}{
			"service_count": len(services),
			"examples":      examples,
		}),
	}
}

func windowsFirewallChecks(state map[string]interface{}) []map[string]interface{} {
	disabled := []string{}
	for _, profile := range listOfMaps(state["FirewallProfiles"]) {
		if value, ok := profile["Enabled"].(bool); ok && !value {
			disabled = append(disabled, stringValue(profile["Name"]))
		}
	}
	if len(disabled) == 0 {
		return nil
	}
	return []map[string]interface{}{
		failedSecurityCheck("DARKSTAR-WINDOWS-FIREWALL-DISABLED", 90, map[string]interface{}{
			"profiles": limitStrings(disabled, 10),
		}),
	}
}

func windowsPasswordPolicyChecks(state map[string]interface{}) []map[string]interface{} {
	text := stringValue(state["NetAccounts"])
	weak := []map[string]interface{}{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.Contains(line, "Minimum password length") {
			if value, ok := firstInteger(line); ok && value < 12 {
				weak = append(weak, map[string]interface{}{"setting": "minimum_password_length", "value": value, "baseline": 12})
			}
		} else if strings.Contains(line, "Maximum password age") {
			if strings.Contains(lower, "unlimited") || strings.Contains(lower, "never") {
				weak = append(weak, map[string]interface{}{"setting": "maximum_password_age_days", "value": nil, "baseline": 90})
			} else if value, ok := firstInteger(line); ok && value > 90 {
				weak = append(weak, map[string]interface{}{"setting": "maximum_password_age_days", "value": value, "baseline": 90})
			}
		} else if strings.Contains(line, "Lockout threshold") {
			if strings.Contains(lower, "never") {
				weak = append(weak, map[string]interface{}{"setting": "lockout_threshold", "value": 0, "baseline": "non-zero"})
			} else if value, ok := firstInteger(line); ok && value == 0 {
				weak = append(weak, map[string]interface{}{"setting": "lockout_threshold", "value": value, "baseline": "non-zero"})
			}
		}
	}
	if len(weak) == 0 {
		return nil
	}
	return []map[string]interface{}{
		failedSecurityCheck("DARKSTAR-WINDOWS-WEAK-PASSWORD-POLICY", 90, map[string]interface{}{
			"weak_settings": weak,
		}),
	}
}

func listOfMaps(value interface{}) []map[string]interface{} {
	switch typed := value.(type) {
	case []interface{}:
		rows := []map[string]interface{}{}
		for _, item := range typed {
			if row, ok := item.(map[string]interface{}); ok {
				rows = append(rows, row)
			}
		}
		return rows
	case map[string]interface{}:
		return []map[string]interface{}{typed}
	default:
		return nil
	}
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func firstInteger(value string) (int, bool) {
	current := 0
	found := false
	for _, char := range value {
		if char >= '0' && char <= '9' {
			found = true
			current = current*10 + int(char-'0')
			continue
		}
		if found {
			return current, true
		}
	}
	return current, found
}

func securityPostureSoftware(osInfo OSInfo, checks []map[string]interface{}) SoftwareItem {
	return SoftwareItem{
		SoftwareKey: postureSoftwareKey,
		Name:        "Endpoint Security Posture",
		Version:     securityCheckSchemaVersion,
		Vendor:      "Darkstar",
		Ecosystem:   "security_posture",
		Source:      "darkstar_security_checks",
		PackageType: "security_posture",
		Raw: map[string]interface{}{
			"schema_version":  securityCheckSchemaVersion,
			"platform":        firstNonEmpty(stringValue(osInfo["platform"]), "windows"),
			"collected_at":    time.Now().UTC().Format(time.RFC3339),
			"security_checks": checks,
			"failed_count":    len(checks),
		},
	}
}

func securityChecksMetadata(checks []map[string]interface{}) map[string]interface{} {
	categories := map[string]int{}
	for _, check := range checks {
		id := stringValue(check["id"])
		parts := strings.Split(id, "-")
		category := "custom"
		if len(parts) >= 3 {
			category = strings.ToLower(parts[2])
		}
		categories[category]++
	}
	return map[string]interface{}{
		"schema_version": securityCheckSchemaVersion,
		"failed_count":   len(checks),
		"categories":     categories,
	}
}
