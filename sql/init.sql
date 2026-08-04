CREATE TABLE IF NOT EXISTS vulnerability (
    id INT(11) NOT NULL AUTO_INCREMENT,
    cve VARCHAR(255), -- CVE identifier (unique vulnerability ID)
    title TEXT, -- Title or short description of the vulnerability
    affected_item TEXT, -- The item or system affected by the vulnerability (scanner URLs are unbounded)
    tool VARCHAR(255), -- The tool used to identify the vulnerability
    confidence INT, -- Confidence level of the vulnerability detection
    severity VARCHAR(50), -- Severity level of the vulnerability (e.g., Low, Medium, High)
    host VARCHAR(255), -- Host affected by the vulnerability
    cvss DECIMAL(4,2), -- CVSS score (Common Vulnerability Scoring System)
    epss DECIMAL(4,2), -- EPSS score (Exploit Prediction Scoring System)
    summary TEXT, -- Detailed summary or description of the vulnerability
    cwe VARCHAR(255), -- CWE identifier (Common Weakness Enumeration)
    `references` TEXT, -- References or links for more information
    capec VARCHAR(255), -- CAPEC identifier (Common Attack Pattern Enumeration and Classification)
    solution TEXT, -- Solution or mitigation for the vulnerability
    impact TEXT, -- Impact or consequences of the vulnerability
    access TEXT, -- Access vector or requirements for exploiting the vulnerability (JSON from CIRCL)
    age INT, -- Age of the vulnerability in days
    pocs TEXT, -- Proof of concepts (PoCs) or exploitation examples
    kev BOOLEAN, -- Known Exploited Vulnerability (True/False)
    priority_score DECIMAL(5,2) DEFAULT NULL,
    risk_score DECIMAL(5,2) DEFAULT NULL,
    has_poc BOOLEAN DEFAULT FALSE,
    has_public_exploit BOOLEAN DEFAULT FALSE,
    exploit_maturity VARCHAR(50) DEFAULT NULL,
    score_reason TEXT DEFAULT NULL,
    scored_at DATETIME DEFAULT NULL,
    asset_criticality VARCHAR(50) DEFAULT 'normal',
    environment VARCHAR(50) DEFAULT 'production',
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS asmevents (
    id INT(11) NOT NULL AUTO_INCREMENT, -- Unique identifier for the event
    event_type VARCHAR(50) DEFAULT NULL, -- Type of the event
    event_data TEXT DEFAULT NULL, -- Detailed data about the event
    ip_address TEXT DEFAULT NULL, -- IP address associated with the event
    source_module VARCHAR(255) DEFAULT NULL, -- Module chain that generated the event (BBOT module_sequence)
    scope_distance INT(11) DEFAULT NULL, -- Scope distance or related measure
    event_tags TEXT DEFAULT NULL, -- Tags associated with the event
    `time` DATETIME DEFAULT NULL, -- Timestamp of the event
    PRIMARY KEY (id) -- Set 'id' as the primary key
);

CREATE TABLE IF NOT EXISTS email_input (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS email_leaks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    breach_name VARCHAR(255) NOT NULL,
    breach_date DATE,
    domain VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS password_leaks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_name VARCHAR(255) NOT NULL,
    scan_mode VARCHAR(50) DEFAULT NULL,
    targets TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    error_message TEXT DEFAULT NULL,
    schedule_id INT DEFAULT NULL,
    created_at DATETIME NOT NULL,
    started_at DATETIME DEFAULT NULL,
    finished_at DATETIME DEFAULT NULL,
    requested_stop_at DATETIME DEFAULT NULL,
    stopped_at DATETIME DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    log_level VARCHAR(20) DEFAULT 'info',
    message LONGTEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    INDEX idx_scan_id (scan_id)
);

CREATE TABLE IF NOT EXISTS scan_schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_name VARCHAR(255) NOT NULL,
    scan_mode VARCHAR(50) DEFAULT NULL,
    scanner VARCHAR(100) DEFAULT NULL,
    targets TEXT NOT NULL,
    bruteforce BOOLEAN DEFAULT FALSE,
    bruteforce_timeout INT DEFAULT 300,
    interval_minutes INT NOT NULL DEFAULT 1440,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    start_at DATETIME DEFAULT NULL,
    end_at DATETIME DEFAULT NULL,
    next_run_at DATETIME NOT NULL,
    last_run_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    preferred_node_id VARCHAR(64) DEFAULT NULL,
    INDEX idx_schedule_due (enabled, next_run_at)
);

CREATE TABLE IF NOT EXISTS notification_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    channel VARCHAR(50) NOT NULL DEFAULT 'email',
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    recipients TEXT DEFAULT NULL,
    min_severity VARCHAR(50) DEFAULT 'high',
    notify_on_success BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_failure BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uniq_notification_channel (channel)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    actor VARCHAR(255) DEFAULT NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100) DEFAULT NULL,
    entity_id VARCHAR(100) DEFAULT NULL,
    metadata TEXT DEFAULT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_audit_created (created_at)
);

CREATE TABLE IF NOT EXISTS m365_graph_settings (
    id INT PRIMARY KEY DEFAULT 1,
    tenant_id VARCHAR(255) DEFAULT NULL,
    client_id VARCHAR(255) DEFAULT NULL,
    client_secret TEXT DEFAULT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS m365_secure_score_summary (
    id INT PRIMARY KEY DEFAULT 1,
    current_score DECIMAL(10,2) DEFAULT NULL,
    max_score DECIMAL(10,2) DEFAULT NULL,
    active_user_count INT DEFAULT NULL,
    licensed_user_count INT DEFAULT NULL,
    created_date_time VARCHAR(100) DEFAULT NULL,
    raw_json LONGTEXT DEFAULT NULL,
    last_synced_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS m365_secure_score_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    control_name VARCHAR(255) NOT NULL,
    title TEXT DEFAULT NULL,
    category VARCHAR(255) DEFAULT NULL,
    action_type VARCHAR(255) DEFAULT NULL,
    implementation_status VARCHAR(255) DEFAULT NULL,
    service VARCHAR(255) DEFAULT NULL,
    user_impact VARCHAR(255) DEFAULT NULL,
    threats TEXT DEFAULT NULL,
    current_score DECIMAL(10,2) DEFAULT NULL,
    max_score DECIMAL(10,2) DEFAULT NULL,
    score_impact DECIMAL(10,2) DEFAULT NULL,
    rank INT DEFAULT NULL,
    raw_json LONGTEXT DEFAULT NULL,
    last_synced_at DATETIME NOT NULL,
    UNIQUE KEY uniq_secure_score_control (control_name)
);

CREATE TABLE IF NOT EXISTS scanner_nodes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    node_id VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    token_prefix VARCHAR(24) NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    capabilities TEXT DEFAULT NULL,
    max_parallel_jobs INT NOT NULL DEFAULT 1,
    status VARCHAR(32) NOT NULL DEFAULT 'registered',
    last_seen_at DATETIME DEFAULT NULL,
    revoked_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_scanner_nodes_status (status),
    INDEX idx_scanner_nodes_seen (last_seen_at)
);

CREATE TABLE IF NOT EXISTS scanner_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_db_name VARCHAR(64) NOT NULL,
    scan_id INT NOT NULL,
    scan_name VARCHAR(255) NOT NULL,
    scan_mode VARCHAR(50) DEFAULT NULL,
    scanner VARCHAR(100) DEFAULT NULL,
    targets TEXT NOT NULL,
    payload_json LONGTEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    priority INT NOT NULL DEFAULT 100,
    attempts INT NOT NULL DEFAULT 0,
    locked_by_node_id VARCHAR(64) DEFAULT NULL,
    locked_at DATETIME DEFAULT NULL,
    lease_until DATETIME DEFAULT NULL,
    started_at DATETIME DEFAULT NULL,
    finished_at DATETIME DEFAULT NULL,
    error_message TEXT DEFAULT NULL,
    schedule_id INT DEFAULT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    preferred_node_id VARCHAR(64) DEFAULT NULL,
    UNIQUE KEY uniq_scanner_job_scan (org_db_name, scan_id),
    INDEX idx_scanner_jobs_status (status, priority, created_at),
    INDEX idx_scanner_jobs_node (locked_by_node_id, status),
    INDEX idx_scanner_jobs_lease (lease_until)
);

-- Control-plane and endpoint-module tables.
-- These are also created at runtime by db_helper._apply_org_schema() and
-- _ensure_organizations_registry(); they are mirrored here so a database
-- seeded from this file alone is complete. A fresh install seeded only from
-- the earlier part of this file had no authentication at all.
-- Kept in sync by darkstar/tests/test_schema_parity.py.

CREATE TABLE IF NOT EXISTS endpoint_enrollment_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    token_prefix VARCHAR(32) NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    expires_at DATETIME DEFAULT NULL,
    revoked_at DATETIME DEFAULT NULL,
    last_used_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_endpoint_enrollment_active (revoked_at, expires_at)
    );

CREATE TABLE IF NOT EXISTS endpoint_agents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) DEFAULT NULL,
    os_platform VARCHAR(64) DEFAULT NULL,
    os_name VARCHAR(255) DEFAULT NULL,
    os_version VARCHAR(255) DEFAULT NULL,
    os_arch VARCHAR(64) DEFAULT NULL,
    os_build VARCHAR(128) DEFAULT NULL,
    ip_addresses TEXT DEFAULT NULL,
    mac_addresses TEXT DEFAULT NULL,
    agent_version VARCHAR(64) DEFAULT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'online',
    token_prefix VARCHAR(32) NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    enrollment_token_id INT DEFAULT NULL,
    metadata_json LONGTEXT DEFAULT NULL,
    revoked_at DATETIME DEFAULT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    last_inventory_at DATETIME DEFAULT NULL,
    INDEX idx_endpoint_agents_seen (last_seen_at),
    INDEX idx_endpoint_agents_status (status)
    );

CREATE TABLE IF NOT EXISTS endpoint_software (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    software_key VARCHAR(128) NOT NULL,
    name VARCHAR(512) NOT NULL,
    version VARCHAR(255) DEFAULT NULL,
    vendor VARCHAR(255) DEFAULT NULL,
    ecosystem VARCHAR(64) NOT NULL,
    purl VARCHAR(1024) DEFAULT NULL,
    cpe VARCHAR(1024) DEFAULT NULL,
    architecture VARCHAR(64) DEFAULT NULL,
    install_location TEXT DEFAULT NULL,
    source VARCHAR(128) DEFAULT NULL,
    package_type VARCHAR(64) DEFAULT NULL,
    raw_json LONGTEXT DEFAULT NULL,
    present BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    UNIQUE KEY uniq_endpoint_software (agent_id, software_key),
    INDEX idx_endpoint_software_agent (agent_id),
    INDEX idx_endpoint_software_purl (purl(255)),
    INDEX idx_endpoint_software_ecosystem (ecosystem)
    );

CREATE TABLE IF NOT EXISTS endpoint_vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    software_key VARCHAR(128) NOT NULL,
    cve VARCHAR(64) NOT NULL,
    source VARCHAR(64) NOT NULL DEFAULT 'OSV',
    severity VARCHAR(32) DEFAULT NULL,
    cvss DECIMAL(4,2) DEFAULT NULL,
    summary TEXT DEFAULT NULL,
    fixed_version VARCHAR(255) DEFAULT NULL,
    affected_version VARCHAR(255) DEFAULT NULL,
    purl VARCHAR(1024) DEFAULT NULL,
    confidence INT NOT NULL DEFAULT 95,
    evidence_json LONGTEXT DEFAULT NULL,
    present BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    UNIQUE KEY uniq_endpoint_vuln (agent_id, software_key, cve, source),
    INDEX idx_endpoint_vuln_agent (agent_id),
    INDEX idx_endpoint_vuln_cve (cve),
    INDEX idx_endpoint_vuln_present (present)
    );

CREATE TABLE IF NOT EXISTS endpoint_vuln_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    package_identity VARCHAR(1024) NOT NULL,
    package_hash VARCHAR(64) NOT NULL,
    version VARCHAR(255) NOT NULL,
    source VARCHAR(64) NOT NULL DEFAULT 'OSV',
    findings_json LONGTEXT NOT NULL,
    last_checked_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    UNIQUE KEY uniq_endpoint_vuln_cache (package_hash, version, source),
    INDEX idx_endpoint_vuln_cache_expiry (expires_at),
    INDEX idx_endpoint_vuln_cache_package (package_hash)
    );

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

CREATE TABLE IF NOT EXISTS organizations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_name VARCHAR(255) NOT NULL UNIQUE,
    org_db_name VARCHAR(64) NOT NULL UNIQUE,
    password_salt VARCHAR(64) NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'tenant_admin',
    mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
    sso_required BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(64) DEFAULT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    sso_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    sso_issuer VARCHAR(512) DEFAULT NULL,
    sso_client_id VARCHAR(255) DEFAULT NULL,
    sso_client_secret TEXT DEFAULT NULL,
    sso_allowed_domain VARCHAR(255) DEFAULT NULL,
    last_login_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL
    );

CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_db_name VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(24) NOT NULL,
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    role VARCHAR(32) NOT NULL DEFAULT 'tenant_admin',
    last_used_at DATETIME DEFAULT NULL,
    revoked_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_api_key_org (org_db_name),
    INDEX idx_api_key_prefix (key_prefix)
    );

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) DEFAULT NULL,
    password_salt VARCHAR(64) NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    mfa_secret VARCHAR(64) DEFAULT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_users_email (email)
    );

CREATE TABLE IF NOT EXISTS organization_memberships (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    org_db_name VARCHAR(64) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    created_at DATETIME NOT NULL,
    UNIQUE KEY uniq_user_org (user_id, org_db_name),
    INDEX idx_membership_org (org_db_name),
    INDEX idx_membership_role (role),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS platform_auth_settings (
    id INT PRIMARY KEY DEFAULT 1,
    mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at DATETIME NOT NULL
    );
