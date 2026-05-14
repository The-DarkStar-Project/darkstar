package main

type OSInfo map[string]interface{}

type SoftwareItem struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version,omitempty"`
	Vendor          string                 `json:"vendor,omitempty"`
	Ecosystem       string                 `json:"ecosystem"`
	Architecture    string                 `json:"architecture,omitempty"`
	InstallLocation string                 `json:"install_location,omitempty"`
	Source          string                 `json:"source,omitempty"`
	PackageType     string                 `json:"package_type"`
	PURL            string                 `json:"purl,omitempty"`
	Raw             map[string]interface{} `json:"raw,omitempty"`
}

type Inventory struct {
	OS           OSInfo                 `json:"os"`
	Software     []SoftwareItem         `json:"software"`
	IPAddresses  []string               `json:"ip_addresses"`
	MACAddresses []string               `json:"mac_addresses"`
	NetworkProbe map[string]interface{} `json:"network_probe,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type ProbeTarget struct {
	AgentID    string `json:"agent_id,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	IP         string `json:"ip,omitempty"`
	OSPlatform string `json:"os_platform,omitempty"`
	Source     string `json:"source,omitempty"`
}

type State struct {
	AgentID             string        `json:"agent_id,omitempty"`
	AgentToken          string        `json:"agent_token,omitempty"`
	OrgDB               string        `json:"org_db,omitempty"`
	URL                 string        `json:"url,omitempty"`
	NetworkProbeTargets []ProbeTarget `json:"network_probe_targets,omitempty"`
}

type Config struct {
	URL             string `json:"url,omitempty"`
	Org             string `json:"org,omitempty"`
	EnrollmentToken string `json:"enrollment_token,omitempty"`
	AgentToken      string `json:"agent_token,omitempty"`
	StateFile       string `json:"state_file,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
}

type registerRequest struct {
	Organization    string                 `json:"organization"`
	EnrollmentToken string                 `json:"enrollment_token"`
	Hostname        string                 `json:"hostname"`
	OS              OSInfo                 `json:"os"`
	AgentVersion    string                 `json:"agent_version"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type registerResponse struct {
	OK         bool   `json:"ok"`
	AgentID    string `json:"agent_id"`
	AgentToken string `json:"agent_token"`
	Hostname   string `json:"hostname"`
	OrgDB      string `json:"org_db"`
}

type inventoryResponse struct {
	OK                  bool                   `json:"ok"`
	AgentID             string                 `json:"agent_id"`
	SoftwareCount       int                    `json:"software_count"`
	VulnerabilityCount  *int                   `json:"vulnerability_count"`
	MatchingStatus      string                 `json:"matching_status"`
	Matcher             string                 `json:"matcher"`
	MatcherStats        map[string]interface{} `json:"matcher_stats"`
	NetworkProbeTargets []ProbeTarget          `json:"network_probe_targets"`
}
