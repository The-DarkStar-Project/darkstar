//go:build windows

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const networkProbeVersion = 1

var defaultFingerprintPorts = []int{22, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443, 62078}

func collectNetworkProbe(peerTargets []ProbeTarget) map[string]interface{} {
	routes := collectRoutes()
	interfaces := collectNetworkInterfaces(routes)
	publicIP := collectPublicIP()
	neighbors := collectNeighbors(interfaces)
	selfIPs := map[string]bool{}
	for _, iface := range interfaces {
		if ip, ok := iface["ip"].(string); ok && ip != "" {
			selfIPs[ip] = true
		}
	}

	maxTargets := envInt("ENDPOINT_NETWORK_PROBE_MAX_TARGETS", 48, 4, 256)
	targets := map[string]map[string]interface{}{}
	for _, neighbor := range neighbors {
		ip := stringValue(neighbor["ip"])
		if ip != "" && !selfIPs[ip] {
			targets[ip] = cloneMap(neighbor)
		}
	}
	for _, iface := range interfaces {
		gateway := stringValue(iface["gateway"])
		if gateway != "" && isProbeIP(gateway) && !selfIPs[gateway] {
			if _, exists := targets[gateway]; !exists {
				targets[gateway] = map[string]interface{}{
					"ip":           gateway,
					"source":       "default_gateway",
					"gateway":      true,
					"interface":    iface["name"],
					"network_cidr": iface["cidr"],
				}
			}
		}
	}
	for _, peer := range peerTargets {
		ip := strings.TrimSpace(peer.IP)
		if !isProbeIP(ip) || selfIPs[ip] {
			continue
		}
		target, exists := targets[ip]
		if !exists {
			target = map[string]interface{}{
				"ip":           ip,
				"source":       "endpoint_peer",
				"network_cidr": networkForIP(ip, interfaces),
			}
			targets[ip] = target
		}
		target["peer_agent_id"] = peer.AgentID
		target["os_platform"] = peer.OSPlatform
		if stringValue(target["hostname"]) == "" {
			target["hostname"] = peer.Hostname
		}
		if stringValue(target["source"]) != "endpoint_peer" {
			target["source"] = firstNonEmpty(stringValue(target["source"]), "observed") + "+endpoint_peer"
		}
	}

	selected := make([]map[string]interface{}, 0, len(targets))
	for _, target := range targets {
		selected = append(selected, target)
		if len(selected) >= maxTargets {
			break
		}
	}

	observations := make([]map[string]interface{}, len(selected))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for index, target := range selected {
		wg.Add(1)
		go func(i int, item map[string]interface{}) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			observations[i] = probeNetworkTarget(item)
		}(index, target)
	}
	wg.Wait()

	peerChecks := make([]map[string]interface{}, 0)
	for _, observation := range observations {
		if stringValue(observation["peer_agent_id"]) == "" {
			continue
		}
		peerChecks = append(peerChecks, map[string]interface{}{
			"agent_id":   observation["peer_agent_id"],
			"hostname":   observation["hostname"],
			"ip":         observation["ip"],
			"reachable":  observation["reachable"],
			"method":     "tcp_connect+icmp_ping",
			"latency_ms": observation["latency_ms"],
			"open_ports": observation["open_ports"],
		})
	}

	return map[string]interface{}{
		"version":      networkProbeVersion,
		"collected_at": time.Now().UTC().Format(time.RFC3339),
		"public_ip":    publicIP,
		"interfaces":   interfaces,
		"routes":       routes,
		"neighbors":    observations,
		"peer_checks":  peerChecks,
		"limits": map[string]interface{}{
			"max_targets": maxTargets,
			"ports":       defaultFingerprintPorts,
			"mode":        "neighbor-cache+gateway+endpoint-peers",
		},
	}
}

func collectNetworkInterfaces(routes []map[string]interface{}) []map[string]interface{} {
	gateways := map[string]string{}
	for _, route := range routes {
		if gateway := stringValue(route["gateway"]); gateway != "" {
			gateways[stringValue(route["interface"])] = gateway
		}
	}
	systemIfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	result := []map[string]interface{}{}
	for _, iface := range systemIfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, network, err := net.ParseCIDR(addr.String())
			if err != nil || ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsMulticast() {
				continue
			}
			ones, _ := network.Mask.Size()
			cidr := network.String()
			result = append(result, map[string]interface{}{
				"name":      iface.Name,
				"ip":        ip.String(),
				"cidr":      cidr,
				"prefixlen": ones,
				"mac":       iface.HardwareAddr.String(),
				"gateway":   gateways[iface.Name],
				"family":    "ipv4",
				"private":   isProbeIP(ip.String()),
			})
		}
	}
	return result
}

func collectRoutes() []map[string]interface{} {
	script := `Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | Select-Object @{n='destination';e={$_.DestinationPrefix}},@{n='gateway';e={$_.NextHop}},@{n='interface';e={$_.InterfaceAlias}},@{n='interface_index';e={$_.InterfaceIndex}},@{n='metric';e={$_.RouteMetric}} | ConvertTo-Json -Compress`
	return powershellJSONRows(script, 12*time.Second)
}

func collectNeighbors(interfaces []map[string]interface{}) []map[string]interface{} {
	script := `Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.IPAddress -and $_.State -ne 'Unreachable' -and $_.IPAddress -notlike '224.*' } | Select-Object @{n='ip';e={$_.IPAddress}},@{n='mac';e={$_.LinkLayerAddress}},@{n='interface';e={$_.InterfaceAlias}},@{n='state';e={$_.State}} | ConvertTo-Json -Compress`
	rows := powershellJSONRows(script, 12*time.Second)
	result := []map[string]interface{}{}
	seen := map[string]bool{}
	for _, row := range rows {
		ip := stringValue(row["ip"])
		mac := stringValue(row["mac"])
		if !isProbeIP(ip) {
			continue
		}
		key := strings.ToLower(ip + "|" + mac)
		if seen[key] {
			continue
		}
		seen[key] = true
		row["source"] = "arp_neighbor"
		row["network_cidr"] = networkForIP(ip, interfaces)
		result = append(result, row)
	}
	return result
}

func collectPublicIP() string {
	client := http.Client{Timeout: 4 * time.Second}
	response, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	var payload map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return ""
	}
	return stringValue(payload["ip"])
}

func probeNetworkTarget(item map[string]interface{}) map[string]interface{} {
	ip := stringValue(item["ip"])
	openPorts := openPortsForTarget(ip, defaultFingerprintPorts)
	item["open_ports"] = openPorts
	if len(openPorts) > 0 {
		item["reachability"] = "open_tcp"
	} else if item["state"] != nil {
		item["reachability"] = item["state"]
	} else {
		item["reachability"] = "seen"
	}
	if stringValue(item["peer_agent_id"]) != "" {
		pingOK, latency := pingOnce(ip)
		item["reachable"] = len(openPorts) > 0 || pingOK
		if latency > 0 {
			item["latency_ms"] = latency
		}
	}
	return fingerprintDevice(item)
}

func openPortsForTarget(ip string, ports []int) []int {
	if ip == "" {
		return nil
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	results := make(chan int, len(ports))
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if tcpPortOpen(ip, p, 350*time.Millisecond) {
				results <- p
			}
		}(port)
	}
	wg.Wait()
	close(results)
	open := []int{}
	for port := range results {
		open = append(open, port)
	}
	sort.Ints(open)
	return open
}

func tcpPortOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func pingOnce(ip string) (bool, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	err := exec.CommandContext(ctx, "ping.exe", "-n", "1", "-w", "700", ip).Run()
	if err != nil {
		return false, 0
	}
	return true, int(time.Since(start).Milliseconds())
}

func fingerprintDevice(item map[string]interface{}) map[string]interface{} {
	ports := map[int]bool{}
	for _, value := range intSlice(item["open_ports"]) {
		ports[value] = true
	}
	hostname := strings.ToLower(stringValue(item["hostname"]))
	deviceType := "unknown"
	osFamily := ""
	confidence := 20
	if len(ports) > 0 {
		confidence = 35
	}
	if stringValue(item["peer_agent_id"]) != "" {
		deviceType = "endpoint"
		osFamily = stringValue(item["os_platform"])
		if boolValue(item["reachable"]) {
			confidence = 85
		} else {
			confidence = 60
		}
	} else if ports[135] || ports[139] || ports[445] || ports[3389] {
		deviceType = "endpoint"
		osFamily = "windows"
		confidence = 80
	} else if ports[22] {
		deviceType = "server"
		osFamily = "linux/unix"
		confidence = 65
	} else if ports[62078] || strings.Contains(hostname, "iphone") || strings.Contains(hostname, "ipad") || strings.Contains(hostname, "android") {
		deviceType = "phone"
		osFamily = "mobile"
		confidence = 65
	} else if boolValue(item["gateway"]) || (ports[53] && (ports[80] || ports[443] || ports[8080] || ports[8443])) {
		deviceType = "router"
		osFamily = "network"
		confidence = 70
	} else if ports[80] || ports[443] || ports[8080] || ports[8443] {
		deviceType = "web_service"
		confidence = 55
	}
	if strings.HasSuffix(stringValue(item["ip"]), ".1") && deviceType == "unknown" {
		deviceType = "router"
		osFamily = "network"
		confidence = 45
	}
	protocols := []string{}
	for port := range ports {
		protocols = append(protocols, "tcp/"+strconv.Itoa(port))
	}
	sort.Strings(protocols)
	item["device_type"] = deviceType
	if osFamily != "" {
		item["os_family"] = osFamily
	}
	item["confidence"] = confidence
	item["protocols"] = protocols
	return item
}

func powershellJSONRows(script string, timeout time.Duration) []map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).Output()
	if err != nil || len(strings.TrimSpace(string(output))) == 0 {
		return nil
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(output, &rows); err == nil {
		return rows
	}
	var row map[string]interface{}
	if err := json.Unmarshal(output, &row); err == nil {
		return []map[string]interface{}{row}
	}
	return nil
}

func networkForIP(ip string, interfaces []map[string]interface{}) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	for _, iface := range interfaces {
		cidr := stringValue(iface["cidr"])
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(parsed) {
			return cidr
		}
	}
	return ""
}

func isProbeIP(value string) bool {
	ip := net.ParseIP(strings.Split(value, "%")[0])
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4[0] == 127 || ip4[0] >= 224 || ip4.Equal(net.IPv4zero) {
		return false
	}
	if ip4[0] == 10 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || (ip4[0] == 192 && ip4[1] == 168) || (ip4[0] == 169 && ip4[1] == 254) {
		return true
	}
	return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}

func envInt(name string, fallback int, min int, max int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		value = fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func cloneMap(input map[string]interface{}) map[string]interface{} {
	output := map[string]interface{}{}
	for key, value := range input {
		output[key] = value
	}
	return output
}

func intSlice(value interface{}) []int {
	switch typed := value.(type) {
	case []int:
		return typed
	case []interface{}:
		result := []int{}
		for _, item := range typed {
			if number, ok := item.(float64); ok {
				result = append(result, int(number))
			}
		}
		return result
	default:
		return nil
	}
}

func boolValue(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		normalized := strings.ToLower(strings.TrimSpace(typed))
		return normalized == "true" || normalized == "1" || normalized == "yes" || normalized == "reachable" || normalized == "open"
	default:
		return false
	}
}
