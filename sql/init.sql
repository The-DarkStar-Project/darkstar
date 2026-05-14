CREATE DATABASE IF NOT EXISTS test;

USE test;

CREATE TABLE IF NOT EXISTS vulnerability (
    id INT(11) NOT NULL AUTO_INCREMENT,
    cve VARCHAR(255), -- CVE identifier (unique vulnerability ID)
    title TEXT, -- Title or short description of the vulnerability
    affected_item VARCHAR(255), -- The item or system affected by the vulnerability
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
    access VARCHAR(255), -- Access vector or requirements for exploiting the vulnerability
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
    source_module VARCHAR(50) DEFAULT NULL, -- Module that generated the event
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
    UNIQUE KEY uniq_scanner_job_scan (org_db_name, scan_id),
    INDEX idx_scanner_jobs_status (status, priority, created_at),
    INDEX idx_scanner_jobs_node (locked_by_node_id, status),
    INDEX idx_scanner_jobs_lease (lease_until)
);

-- Grant permissions to allow data_miner to create org databases
GRANT ALL PRIVILEGES ON `org_%`.* TO 'data_miner'@'%';
GRANT CREATE, ALTER, DROP ON *.* TO 'data_miner'@'%';
FLUSH PRIVILEGES;
