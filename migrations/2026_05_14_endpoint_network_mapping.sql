-- Endpoint internal attack-surface mapping tables.
-- Apply to each tenant schema; db_helper also creates these on demand.

CREATE TABLE IF NOT EXISTS endpoint_network_segments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    segment_key VARCHAR(128) NOT NULL,
    cidr VARCHAR(128) DEFAULT NULL,
    interface_name VARCHAR(255) DEFAULT NULL,
    ip_address VARCHAR(64) DEFAULT NULL,
    mac_address VARCHAR(64) DEFAULT NULL,
    gateway VARCHAR(64) DEFAULT NULL,
    public_ip VARCHAR(64) DEFAULT NULL,
    raw_json LONGTEXT DEFAULT NULL,
    present BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    UNIQUE KEY uniq_endpoint_network_segment (agent_id, segment_key),
    INDEX idx_endpoint_network_segment_agent (agent_id),
    INDEX idx_endpoint_network_segment_cidr (cidr),
    INDEX idx_endpoint_network_segment_public_ip (public_ip),
    INDEX idx_endpoint_network_segment_present (present)
);

CREATE TABLE IF NOT EXISTS endpoint_network_observations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    observation_key VARCHAR(128) NOT NULL,
    ip_address VARCHAR(64) DEFAULT NULL,
    hostname VARCHAR(255) DEFAULT NULL,
    mac_address VARCHAR(64) DEFAULT NULL,
    vendor_hint VARCHAR(255) DEFAULT NULL,
    device_type VARCHAR(64) DEFAULT NULL,
    os_family VARCHAR(64) DEFAULT NULL,
    confidence INT DEFAULT NULL,
    reachability VARCHAR(64) DEFAULT NULL,
    open_ports TEXT DEFAULT NULL,
    protocols TEXT DEFAULT NULL,
    source VARCHAR(64) DEFAULT NULL,
    network_cidr VARCHAR(128) DEFAULT NULL,
    interface_name VARCHAR(255) DEFAULT NULL,
    public_ip VARCHAR(64) DEFAULT NULL,
    raw_json LONGTEXT DEFAULT NULL,
    present BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    UNIQUE KEY uniq_endpoint_network_observation (agent_id, observation_key),
    INDEX idx_endpoint_network_observation_agent (agent_id),
    INDEX idx_endpoint_network_observation_ip (ip_address),
    INDEX idx_endpoint_network_observation_cidr (network_cidr),
    INDEX idx_endpoint_network_observation_type (device_type),
    INDEX idx_endpoint_network_observation_present (present)
);

CREATE TABLE IF NOT EXISTS endpoint_network_peer_checks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_agent_id VARCHAR(64) NOT NULL,
    target_agent_id VARCHAR(64) NOT NULL,
    target_ip VARCHAR(64) NOT NULL,
    reachable BOOLEAN NOT NULL DEFAULT FALSE,
    method VARCHAR(64) DEFAULT NULL,
    latency_ms INT DEFAULT NULL,
    open_ports TEXT DEFAULT NULL,
    raw_json LONGTEXT DEFAULT NULL,
    present BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    UNIQUE KEY uniq_endpoint_network_peer_check (source_agent_id, target_agent_id, target_ip),
    INDEX idx_endpoint_network_peer_source (source_agent_id),
    INDEX idx_endpoint_network_peer_target (target_agent_id),
    INDEX idx_endpoint_network_peer_present (present)
);
