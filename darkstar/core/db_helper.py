"""
Database helper functions for the Darkstar security framework.

This module provides centralized database operations for storing
vulnerability data and scan results.
"""

import logging
import mysql.connector
import os
import json
import re
import hashlib
import secrets
import ipaddress
from html import escape
import pandas as pd
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from .models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


ORG_IDENTIFIER_RE = re.compile(r"^[a-z0-9_]{3,64}$")
VALID_ROLES = {"platform_admin", "tenant_admin", "security_analyst", "viewer"}
ROLE_RANK = {
    "viewer": 10,
    "security_analyst": 50,
    "tenant_admin": 80,
    "platform_admin": 100,
}


ORG_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS vulnerability (
        id INT(11) NOT NULL AUTO_INCREMENT,
        cve VARCHAR(255),
        title TEXT,
        affected_item VARCHAR(255),
        tool VARCHAR(255),
        confidence INT,
        severity VARCHAR(50),
        host VARCHAR(255),
        cvss DECIMAL(4,2),
        epss DECIMAL(4,2),
        summary TEXT,
        cwe VARCHAR(255),
        `references` TEXT,
        capec VARCHAR(255),
        solution TEXT,
        impact TEXT,
        access VARCHAR(255),
        age INT,
        pocs TEXT,
        kev BOOLEAN,
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
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS asmevents (
        id INT(11) NOT NULL AUTO_INCREMENT,
        event_type VARCHAR(50) DEFAULT NULL,
        event_data TEXT DEFAULT NULL,
        ip_address TEXT DEFAULT NULL,
        source_module VARCHAR(50) DEFAULT NULL,
        scope_distance INT(11) DEFAULT NULL,
        event_tags TEXT DEFAULT NULL,
        `time` DATETIME DEFAULT NULL,
        PRIMARY KEY (id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS email_input (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS email_leaks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        breach_name VARCHAR(255) NOT NULL,
        breach_date DATE,
        domain VARCHAR(255)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS password_leaks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL
    )
    """,
    """
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
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scan_id INT NOT NULL,
        log_level VARCHAR(20) DEFAULT 'info',
        message LONGTEXT NOT NULL,
        created_at DATETIME NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
        INDEX idx_scan_id (scan_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_schedules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scan_name VARCHAR(255) NOT NULL,
        scan_mode VARCHAR(50) DEFAULT NULL,
        scanner VARCHAR(100) DEFAULT NULL,
        targets TEXT NOT NULL,
        bruteforce BOOLEAN DEFAULT FALSE,
        bruteforce_timeout INT DEFAULT 300,
        preferred_node_id VARCHAR(64) DEFAULT NULL,
        interval_minutes INT NOT NULL DEFAULT 1440,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        start_at DATETIME DEFAULT NULL,
        end_at DATETIME DEFAULT NULL,
        next_run_at DATETIME NOT NULL,
        last_run_at DATETIME DEFAULT NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        INDEX idx_schedule_due (enabled, next_run_at)
    )
    """,
    """
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
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        actor VARCHAR(255) DEFAULT NULL,
        action VARCHAR(100) NOT NULL,
        entity_type VARCHAR(100) DEFAULT NULL,
        entity_id VARCHAR(100) DEFAULT NULL,
        metadata TEXT DEFAULT NULL,
        created_at DATETIME NOT NULL,
        INDEX idx_audit_created (created_at)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS m365_graph_settings (
        id INT PRIMARY KEY DEFAULT 1,
        tenant_id VARCHAR(255) DEFAULT NULL,
        client_id VARCHAR(255) DEFAULT NULL,
        client_secret TEXT DEFAULT NULL,
        enabled BOOLEAN NOT NULL DEFAULT FALSE,
        updated_at DATETIME NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS m365_secure_score_summary (
        id INT PRIMARY KEY DEFAULT 1,
        current_score DECIMAL(10,2) DEFAULT NULL,
        max_score DECIMAL(10,2) DEFAULT NULL,
        active_user_count INT DEFAULT NULL,
        licensed_user_count INT DEFAULT NULL,
        created_date_time VARCHAR(100) DEFAULT NULL,
        raw_json LONGTEXT DEFAULT NULL,
        last_synced_at DATETIME NOT NULL
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
]

ORG_SCHEMA_MIGRATION_STATEMENTS = [
    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS priority_score DECIMAL(5,2) DEFAULT NULL",
    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS risk_score DECIMAL(5,2) DEFAULT NULL",
    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS has_poc BOOLEAN DEFAULT FALSE",
    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS has_public_exploit BOOLEAN DEFAULT FALSE",
    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS exploit_maturity VARCHAR(50) DEFAULT NULL",
    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS score_reason TEXT DEFAULT NULL",
    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS scored_at DATETIME DEFAULT NULL",
    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS asset_criticality VARCHAR(50) DEFAULT 'normal'",
    "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS environment VARCHAR(50) DEFAULT 'production'",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS schedule_id INT DEFAULT NULL",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS requested_stop_at DATETIME DEFAULT NULL",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS stopped_at DATETIME DEFAULT NULL",
    "ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS start_at DATETIME DEFAULT NULL",
    "ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS end_at DATETIME DEFAULT NULL",
    "ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS preferred_node_id VARCHAR(64) DEFAULT NULL",
    "ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS display_name VARCHAR(255) DEFAULT NULL",
    "ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS os_build VARCHAR(128) DEFAULT NULL",
    "ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS metadata_json LONGTEXT DEFAULT NULL",
    "ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS revoked_at DATETIME DEFAULT NULL",
    "ALTER TABLE endpoint_software ADD COLUMN IF NOT EXISTS package_type VARCHAR(64) DEFAULT NULL",
    "ALTER TABLE endpoint_vulnerabilities ADD COLUMN IF NOT EXISTS fixed_version VARCHAR(255) DEFAULT NULL",
]


def normalize_org_name(org_name: str) -> str:
    """Normalize a user-provided organization name into a safe DB identifier."""
    if not org_name:
        raise ValueError("Organization name is required")

    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", org_name.strip().lower())
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    normalized = f"org_{normalized}" if not normalized.startswith("org_") else normalized

    if not ORG_IDENTIFIER_RE.match(normalized):
        raise ValueError("Organization name must map to 3-64 characters: a-z, 0-9 or _")

    return normalized


def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hash a password with PBKDF2 and return (salt, hash)."""
    if not password:
        raise ValueError("Password is required")

    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 300_000
    ).hex()
    return salt, digest


def _verify_password(password: str, salt: str, password_hash: str) -> bool:
    """Verify password hash using constant-time comparison."""
    _, digest = _hash_password(password=password, salt=salt)
    return secrets.compare_digest(digest, password_hash)


def _use_org_database(cursor, org_name: str):
    """Switch active database to a validated organization schema."""
    org_db = normalize_org_name(org_name)
    cursor.execute(f"USE `{org_db}`")
    return org_db


def _apply_org_schema(cursor):
    """Apply the current organization schema and additive migrations."""
    for statement in ORG_SCHEMA_STATEMENTS:
        cursor.execute(statement)
    for statement in ORG_SCHEMA_MIGRATION_STATEMENTS:
        cursor.execute(statement)


def _ensure_endpoint_network_schema(cursor):
    """Create network-mapping tables for existing tenant schemas on demand."""
    for statement in ORG_SCHEMA_STATEMENTS[-3:]:
        cursor.execute(statement)


def _ensure_organizations_registry(cursor):
    """Ensure the global organizations registry has the current columns."""
    cursor.execute(
        """
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
        )
        """
    )
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS role VARCHAR(32) NOT NULL DEFAULT 'tenant_admin'")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT FALSE")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_required BOOLEAN NOT NULL DEFAULT FALSE")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(64) DEFAULT NULL")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_enabled BOOLEAN NOT NULL DEFAULT FALSE")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_issuer VARCHAR(512) DEFAULT NULL")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_client_id VARCHAR(255) DEFAULT NULL")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_client_secret TEXT DEFAULT NULL")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_allowed_domain VARCHAR(255) DEFAULT NULL")
    cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS last_login_at DATETIME DEFAULT NULL")
    cursor.execute(
        """
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
        )
        """
    )
    cursor.execute(
        """
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
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scanner_jobs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            org_db_name VARCHAR(64) NOT NULL,
            scan_id INT NOT NULL,
            scan_name VARCHAR(255) NOT NULL,
            scan_mode VARCHAR(50) DEFAULT NULL,
            scanner VARCHAR(100) DEFAULT NULL,
            preferred_node_id VARCHAR(64) DEFAULT NULL,
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
        )
        """
    )
    cursor.execute("ALTER TABLE scanner_nodes ADD COLUMN IF NOT EXISTS max_parallel_jobs INT NOT NULL DEFAULT 1")
    cursor.execute("ALTER TABLE scanner_nodes ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'registered'")
    cursor.execute("ALTER TABLE scanner_nodes ADD COLUMN IF NOT EXISTS revoked_at DATETIME DEFAULT NULL")
    cursor.execute("ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS scanner VARCHAR(100) DEFAULT NULL")
    cursor.execute("ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS preferred_node_id VARCHAR(64) DEFAULT NULL")
    cursor.execute("ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 100")
    cursor.execute("ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0")
    cursor.execute("ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS lease_until DATETIME DEFAULT NULL")
    cursor.execute("ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS schedule_id INT DEFAULT NULL")
    cursor.execute(
        """
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
        )
        """
    )
    cursor.execute(
        """
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
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS platform_auth_settings (
            id INT PRIMARY KEY DEFAULT 1,
            mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
            updated_at DATETIME NOT NULL
        )
        """
    )
    cursor.execute(
        """
        INSERT IGNORE INTO platform_auth_settings (id, mfa_required, updated_at)
        VALUES (1, FALSE, %s)
        """,
        (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),),
    )


def ensure_organization(org_name: str, password: str) -> tuple[str, bool]:
    """
    Ensure organization record and per-org database exist.

    Returns:
        tuple[str, bool]: (normalized_org_db_name, created_now)
    """
    org_db = normalize_org_name(org_name)
    created_now = False
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    metadata_payload = dict(metadata or {})
    metadata_payload.setdefault("os", os_info or {})
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)

        _ensure_organizations_registry(cursor)

        cursor.execute(
            "SELECT org_db_name, password_salt, password_hash, role FROM organizations WHERE org_name = %s",
            (org_name,),
        )
        row = cursor.fetchone()
        default_admin_org = os.environ.get("PLATFORM_ADMIN_ORG", "platform_admin")
        role = "platform_admin" if org_name.strip().lower() == default_admin_org.lower() else "tenant_admin"

        if row:
            if not _verify_password(password, row["password_salt"], row["password_hash"]):
                raise ValueError("Invalid organization credentials")
            org_db = row["org_db_name"]
            if role == "platform_admin" and row.get("role") != "platform_admin":
                cursor.execute(
                    "UPDATE organizations SET role = %s, last_login_at = %s WHERE org_name = %s",
                    (role, created_at, org_name),
                )
            else:
                cursor.execute(
                    "UPDATE organizations SET last_login_at = %s WHERE org_name = %s",
                    (created_at, org_name),
                )
        else:
            salt, digest = _hash_password(password)
            cursor.execute(
                "INSERT INTO organizations (org_name, org_db_name, password_salt, password_hash, role, last_login_at, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (org_name, org_db, salt, digest, role, created_at, created_at),
            )
            created_now = True

        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{org_db}`")
        cursor.execute(f"USE `{org_db}`")
        _apply_org_schema(cursor)

        connection.commit()
        cursor.close()

    return org_db, created_now


def _normalize_email(email: str) -> str:
    """Normalize login emails consistently before lookup/storage."""
    normalized = (email or "").strip().lower()
    if "@" not in normalized or len(normalized) > 255:
        raise ValueError("A valid email address is required")
    return normalized


def _validate_role(role: str) -> str:
    """Return a valid role or raise a clear validation error."""
    normalized = (role or "viewer").strip().lower()
    if normalized not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}")
    return normalized


def _public_user(row: dict | None) -> dict | None:
    """Strip password and MFA secrets from a user row."""
    if not row:
        return None
    return {
        "id": row.get("id"),
        "email": row.get("email"),
        "display_name": row.get("display_name"),
        "mfa_enabled": bool(row.get("mfa_enabled")),
        "last_login_at": row.get("last_login_at"),
        "created_at": row.get("created_at"),
    }


def _ensure_organization_record(cursor, org_name: str, password: str, role: str) -> str:
    """Create a legacy organization registry row and tenant DB when missing."""
    org_db = normalize_org_name(org_name)
    cursor.execute("SELECT org_db_name FROM organizations WHERE org_db_name = %s", (org_db,))
    row = cursor.fetchone()
    if not row:
        salt, digest = _hash_password(password)
        created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            """
            INSERT INTO organizations
                (org_name, org_db_name, password_salt, password_hash, role, last_login_at, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (org_name, org_db, salt, digest, role, created_at, created_at),
        )

    cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{org_db}`")
    cursor.execute(f"USE `{org_db}`")
    _apply_org_schema(cursor)
    cursor.execute(f"USE `{os.environ.get('DB_NAME', 'darkstar')}`")
    return org_db


def _membership_rows(cursor, user_id: int) -> list[dict]:
    """Return all active organization memberships for a user."""
    cursor.execute(
        """
        SELECT
            m.id,
            m.user_id,
            m.org_db_name,
            m.role,
            o.org_name,
            o.mfa_required,
            o.sso_required,
            o.created_at AS org_created_at,
            o.last_login_at
        FROM organization_memberships m
        JOIN organizations o ON o.org_db_name = m.org_db_name
        WHERE m.user_id = %s
        ORDER BY o.org_name ASC
        """,
        (user_id,),
    )
    return cursor.fetchall() or []


def authenticate_user(email: str, password: str) -> dict:
    """
    Authenticate a user by email/password.

    The first ever user bootstraps a platform admin account and a default
    platform-admin organization so fresh installs remain usable.
    """
    email = _normalize_email(email)
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)

        cursor.execute("SELECT COUNT(*) AS total FROM users")
        user_count = int((cursor.fetchone() or {}).get("total") or 0)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user and user_count == 0:
            default_admin_org = os.environ.get("PLATFORM_ADMIN_ORG", "platform_admin")
            org_db = _ensure_organization_record(cursor, default_admin_org, password, "platform_admin")
            salt, digest = _hash_password(password)
            cursor.execute(
                """
                INSERT INTO users (email, display_name, password_salt, password_hash, created_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (email, email.split("@")[0], salt, digest, created_at),
            )
            user_id = cursor.lastrowid
            cursor.execute(
                """
                INSERT INTO organization_memberships (user_id, org_db_name, role, created_at)
                VALUES (%s, %s, %s, %s)
                """,
                (user_id, org_db, "platform_admin", created_at),
            )
            connection.commit()
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

        if not user or not _verify_password(password, user["password_salt"], user["password_hash"]):
            cursor.close()
            raise ValueError("Invalid email or password")

        memberships = _membership_rows(cursor, user["id"])
        cursor.close()

    return {"user": _public_user(user), "memberships": memberships}


def get_user_by_id(user_id: int, include_secrets: bool = False) -> dict | None:
    """Return a user row by ID, optionally including password/MFA secret fields."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        cursor.close()
    if include_secrets:
        return row
    return _public_user(row)


def list_user_memberships(user_id: int) -> list[dict]:
    """Return all memberships for a user."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        rows = _membership_rows(cursor, user_id)
        cursor.close()
        return rows


def get_user_membership(user_id: int, org_db_name: str) -> dict | None:
    """Return one membership for a user and organization database."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT m.id, m.user_id, m.org_db_name, m.role, o.org_name, o.mfa_required, o.sso_required
            FROM organization_memberships m
            JOIN organizations o ON o.org_db_name = m.org_db_name
            WHERE m.user_id = %s AND m.org_db_name = %s
            """,
            (user_id, org_db_name),
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def update_user_mfa_secret(user_id: int, mfa_secret: str | None, enabled: bool) -> dict:
    """Update per-user TOTP MFA settings."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            "UPDATE users SET mfa_secret = %s, mfa_enabled = %s WHERE id = %s",
            (mfa_secret, enabled, user_id),
        )
        connection.commit()
        cursor.close()
    return get_user_by_id(user_id) or {}


def mark_user_login(user_id: int):
    """Update a user's last-login timestamp."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        cursor.execute(
            "UPDATE users SET last_login_at = %s WHERE id = %s",
            (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), user_id),
        )
        connection.commit()
        cursor.close()


def get_platform_auth_settings() -> dict:
    """Return platform-wide authentication policy."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute("SELECT mfa_required, updated_at FROM platform_auth_settings WHERE id = 1")
        row = cursor.fetchone() or {"mfa_required": False}
        cursor.close()
        return row


def update_platform_auth_settings(mfa_required: bool) -> dict:
    """Update platform-wide authentication policy."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            INSERT INTO platform_auth_settings (id, mfa_required, updated_at)
            VALUES (1, %s, %s)
            ON DUPLICATE KEY UPDATE mfa_required = VALUES(mfa_required), updated_at = VALUES(updated_at)
            """,
            (mfa_required, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        )
        connection.commit()
        cursor.close()
    return get_platform_auth_settings()


def update_organization_auth_requirements(org_db_name: str, mfa_required: bool, sso_required: bool) -> dict:
    """Update organization-level authentication enforcement policy."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            "UPDATE organizations SET mfa_required = %s, sso_required = %s WHERE org_db_name = %s",
            (mfa_required, sso_required, org_db_name),
        )
        connection.commit()
        cursor.close()
    return get_organization_auth_settings(org_db_name)


def update_organization_mfa_required(org_db_name: str, mfa_required: bool) -> dict:
    """Update organization-level MFA policy."""
    current = get_organization_auth_settings(org_db_name)
    return update_organization_auth_requirements(org_db_name, mfa_required, bool(current.get("sso_required")))


def is_mfa_required_for_org(org_db_name: str) -> bool:
    """Return true when platform or organization policy requires MFA."""
    platform = get_platform_auth_settings()
    org = get_organization_auth_settings(org_db_name)
    return bool(platform.get("mfa_required") or org.get("mfa_required"))


def list_users() -> list[dict]:
    """Return users and their memberships for platform administration."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT id, email, display_name, mfa_enabled, last_login_at, created_at
            FROM users
            ORDER BY email ASC
            """
        )
        users = cursor.fetchall() or []
        for user in users:
            user["memberships"] = _membership_rows(cursor, user["id"])
        cursor.close()
        return users


def list_users_for_org(org_db_name: str) -> list[dict]:
    """Return users that have a membership in one organization."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT u.id, u.email, u.display_name, u.mfa_enabled, u.last_login_at, u.created_at,
                   m.id AS membership_id, m.role, m.org_db_name, o.org_name
            FROM organization_memberships m
            JOIN users u ON u.id = m.user_id
            JOIN organizations o ON o.org_db_name = m.org_db_name
            WHERE m.org_db_name = %s
            ORDER BY u.email ASC
            """,
            (org_db_name,),
        )
        rows = cursor.fetchall() or []
        cursor.close()
        return rows


def create_or_update_user(
    email: str,
    password: str | None,
    display_name: str | None,
    org_db_name: str,
    role: str,
) -> dict:
    """Create/update a user and upsert their organization membership."""
    email = _normalize_email(email)
    role = _validate_role(role)
    if role == "platform_admin" and org_db_name != normalize_org_name(os.environ.get("PLATFORM_ADMIN_ORG", "platform_admin")):
        # Platform admins are still stored as a membership role, but keeping the
        # default admin org as their home avoids accidental tenant elevation.
        raise ValueError("platform_admin memberships must use the platform admin organization")
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing = cursor.fetchone()
        if existing:
            user_id = existing["id"]
            if password:
                salt, digest = _hash_password(password)
                cursor.execute(
                    """
                    UPDATE users
                    SET display_name = %s, password_salt = %s, password_hash = %s
                    WHERE id = %s
                    """,
                    (display_name or email.split("@")[0], salt, digest, user_id),
                )
            else:
                cursor.execute(
                    "UPDATE users SET display_name = %s WHERE id = %s",
                    (display_name or email.split("@")[0], user_id),
                )
        else:
            if not password:
                raise ValueError("Password is required for new users")
            salt, digest = _hash_password(password)
            cursor.execute(
                """
                INSERT INTO users (email, display_name, password_salt, password_hash, created_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (email, display_name or email.split("@")[0], salt, digest, created_at),
            )
            user_id = cursor.lastrowid

        cursor.execute("SELECT org_db_name FROM organizations WHERE org_db_name = %s", (org_db_name,))
        if not cursor.fetchone():
            raise ValueError("Organization does not exist")

        cursor.execute(
            """
            INSERT INTO organization_memberships (user_id, org_db_name, role, created_at)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE role = VALUES(role)
            """,
            (user_id, org_db_name, role, created_at),
        )
        connection.commit()
        cursor.close()

    return get_user_by_id(user_id) or {}


def remove_user_membership(user_id: int, org_db_name: str) -> bool:
    """Remove one user's membership from an organization."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            "DELETE FROM organization_memberships WHERE user_id = %s AND org_db_name = %s",
            (user_id, org_db_name),
        )
        removed = cursor.rowcount > 0
        cursor.execute("SELECT COUNT(*) AS total FROM organization_memberships WHERE user_id = %s", (user_id,))
        membership_count = int((cursor.fetchone() or {}).get("total") or 0)
        if membership_count == 0:
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        connection.commit()
        cursor.close()
        return removed


def delete_user(user_id: int) -> bool:
    """Delete a user and all memberships."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        removed = cursor.rowcount > 0
        connection.commit()
        cursor.close()
        return removed


def ensure_org_database_schema(org_name: str):
    """Apply current org schema to an existing organization database."""
    org_db = normalize_org_name(org_name)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{org_db}`")
        cursor.execute(f"USE `{org_db}`")
        _apply_org_schema(cursor)
        connection.commit()
        cursor.close()


def create_scan_record(org_name: str, scan_name: str, scan_mode: str | None, targets: str) -> int:
    """Create a scan tracking record in the organization database."""
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            INSERT INTO scans (scan_name, scan_mode, targets, status, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (scan_name, scan_mode, targets, "queued", created_at),
        )
        scan_id = cursor.lastrowid
        connection.commit()
        cursor.close()
        return int(scan_id)


def update_scan_status(org_name: str, scan_id: int, status: str, error_message: str | None = None):
    """Update scan runtime status and timestamps."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)

        if status == "running":
            started_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "UPDATE scans SET status = %s, started_at = %s, error_message = NULL WHERE id = %s",
                (status, started_at, scan_id),
            )
        elif status in {"completed", "failed"}:
            finished_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "UPDATE scans SET status = %s, finished_at = %s, error_message = %s WHERE id = %s",
                (status, finished_at, error_message, scan_id),
            )
        elif status == "stopping":
            requested_stop_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "UPDATE scans SET status = %s, requested_stop_at = %s, error_message = %s WHERE id = %s",
                (status, requested_stop_at, error_message, scan_id),
            )
        elif status == "stopped":
            stopped_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "UPDATE scans SET status = %s, finished_at = %s, stopped_at = %s, error_message = %s WHERE id = %s",
                (status, stopped_at, stopped_at, error_message, scan_id),
            )
        else:
            cursor.execute(
                "UPDATE scans SET status = %s, error_message = %s WHERE id = %s",
                (status, error_message, scan_id),
            )

        connection.commit()
        cursor.close()


def mark_interrupted_scans(org_name: str, reason: str) -> int:
    """Mark queued/running scans as failed after a web process restart."""
    finished_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            UPDATE scans
            SET status = 'failed', finished_at = %s, error_message = %s
            WHERE status IN ('queued', 'running', 'stopping')
            """,
            (finished_at, reason),
        )
        count = cursor.rowcount
        connection.commit()
        cursor.close()
        return int(count or 0)


def mark_orphaned_scans_without_queue(org_name: str, reason: str) -> int:
    """Mark active tenant scans without a central queue job as failed."""
    org_db = normalize_org_name(org_name)
    base_db = os.environ.get("DB_NAME", "darkstar")
    finished_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT s.id
            FROM `{org_db}`.scans s
            LEFT JOIN `{base_db}`.scanner_jobs j
                ON j.org_db_name = %s AND j.scan_id = s.id
            WHERE s.status IN ('queued', 'running', 'stopping')
              AND j.id IS NULL
            """,
            (org_db,),
        )
        rows = cursor.fetchall() or []
        scan_ids = [int(row["id"]) for row in rows]
        if not scan_ids:
            cursor.close()
            return 0

        placeholders = ", ".join(["%s"] * len(scan_ids))
        cursor.execute(
            f"""
            UPDATE `{org_db}`.scans
            SET status = 'failed', finished_at = %s, error_message = %s
            WHERE id IN ({placeholders})
            """,
            (finished_at, reason, *scan_ids),
        )
        cursor.executemany(
            f"""
            INSERT INTO `{org_db}`.scan_logs (scan_id, log_level, message, created_at)
            VALUES (%s, 'warning', %s, %s)
            """,
            [(scan_id, reason, finished_at) for scan_id in scan_ids],
        )
        connection.commit()
        cursor.close()
        return len(scan_ids)


def get_scan_record(org_name: str, scan_id: int) -> dict | None:
    """Return a single scan record for an organization."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, scan_name, scan_mode, targets, status, error_message, schedule_id,
                   created_at, started_at, finished_at, requested_stop_at, stopped_at
            FROM scans
            WHERE id = %s
            """,
            (scan_id,),
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def get_latest_vulnerabilities(org_name: str, limit: int = 200) -> list[dict]:
    """Return latest vulnerabilities from organization database."""
    limit = max(1, min(limit, 1000))
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, cve, title, affected_item, tool, confidence, severity, host,
                   cvss, epss, summary, cwe, capec, solution, impact, age, kev,
                   priority_score, risk_score, has_poc, has_public_exploit,
                   exploit_maturity, score_reason, asset_criticality, environment
            FROM vulnerability
            ORDER BY COALESCE(priority_score, 0) DESC, id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "baseline": 1,
    "info": 1,
    "unknown": 0,
}


def _normalize_severity(value: str | None) -> str:
    return str(value or "unknown").strip().lower()


def _max_severity(values: list[str | None]) -> str:
    severities = [_normalize_severity(value) for value in values if value]
    if not severities:
        return "unknown"
    return max(severities, key=lambda severity: SEVERITY_RANK.get(severity, 0))


def get_scan_history(org_name: str, limit: int = 50) -> list[dict]:
    """Return latest scan jobs for an organization."""
    limit = max(1, min(limit, 500))
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, scan_name, scan_mode, targets, status, error_message, schedule_id,
                   created_at, started_at, finished_at, requested_stop_at, stopped_at
            FROM scans
            ORDER BY id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


def _float_or_none(value):
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def calculate_vulnerability_score(row: dict) -> tuple[float, str, bool, bool, str]:
    """Calculate a pragmatic 0-100 priority score for one vulnerability row."""
    severity_weights = {
        "critical": 90.0,
        "high": 72.0,
        "medium": 45.0,
        "low": 18.0,
        "info": 5.0,
        "unknown": 10.0,
    }
    severity = str(row.get("severity") or "unknown").lower()
    cvss = _float_or_none(row.get("cvss"))
    epss = _float_or_none(row.get("epss"))
    confidence = _float_or_none(row.get("confidence")) or 0
    pocs = str(row.get("pocs") or "").strip()
    kev = bool(row.get("kev"))

    base = cvss * 10 if cvss is not None else severity_weights.get(severity, 10.0)
    score = base
    reasons = [f"base={round(base, 1)}"]

    if epss is not None:
        normalized_epss = epss if epss <= 1 else epss / 100
        epss_boost = max(0.0, min(normalized_epss, 1.0)) * 15
        score += epss_boost
        reasons.append(f"epss+{round(epss_boost, 1)}")

    if kev:
        score += 20
        reasons.append("kev+20")

    has_poc = bool(pocs)
    has_public_exploit = kev or has_poc or (epss is not None and epss >= 0.65)
    if has_poc:
        score += 10
        reasons.append("poc+10")
    if confidence:
        confidence_boost = min(confidence, 100) / 20
        score += confidence_boost
        reasons.append(f"confidence+{round(confidence_boost, 1)}")

    score = round(min(score, 100.0), 2)
    exploit_maturity = "known_exploited" if kev else "public_poc" if has_poc else "likely" if has_public_exploit else "none"
    return score, ", ".join(reasons), has_poc, has_public_exploit, exploit_maturity


def recalculate_vulnerability_scores(org_name: str) -> int:
    """Refresh stored vulnerability scoring fields for an organization."""
    scored_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, severity, cvss, epss, confidence, kev, pocs
            FROM vulnerability
            """
        )
        rows = cursor.fetchall() or []
        updates = []
        for row in rows:
            score, reason, has_poc, has_public_exploit, exploit_maturity = calculate_vulnerability_score(row)
            updates.append((score, score, has_poc, has_public_exploit, exploit_maturity, reason, scored_at, row["id"]))

        if updates:
            cursor.executemany(
                """
                UPDATE vulnerability
                SET priority_score = %s,
                    risk_score = %s,
                    has_poc = %s,
                    has_public_exploit = %s,
                    exploit_maturity = %s,
                    score_reason = %s,
                    scored_at = %s
                WHERE id = %s
                """,
                updates,
            )
        connection.commit()
        cursor.close()
        return len(updates)


def get_scoring_overview(
    org_name: str,
    asset_search: str | None = None,
    asset_limit: int = 25,
    asset_offset: int = 0,
    vuln_severity: str | None = None,
    vuln_host: str | None = None,
    vuln_limit: int = 25,
    vuln_offset: int = 0,
) -> dict:
    """Return summary scoring views for dashboard widgets."""
    recalculate_vulnerability_scores(org_name)
    asset_limit = max(1, min(asset_limit, 200))
    asset_offset = max(0, asset_offset)
    vuln_limit = max(1, min(vuln_limit, 200))
    vuln_offset = max(0, vuln_offset)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                ROUND(AVG(COALESCE(priority_score, 0)), 2) AS average_priority,
                MAX(COALESCE(priority_score, 0)) AS max_priority,
                SUM(CASE WHEN kev THEN 1 ELSE 0 END) AS kev_count,
                SUM(CASE WHEN has_public_exploit THEN 1 ELSE 0 END) AS exploitable_count
            FROM vulnerability
            """
        )
        summary = cursor.fetchone() or {}

        asset_where = "host IS NOT NULL AND host != ''"
        asset_params = []
        if asset_search:
            asset_where += " AND host LIKE %s"
            asset_params.append(f"%{asset_search}%")

        cursor.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM (
                SELECT host
                FROM vulnerability
                WHERE {asset_where}
                GROUP BY host
            ) assets
            """,
            asset_params,
        )
        asset_total_row = cursor.fetchone() or {}
        asset_total = asset_total_row.get("total") or 0
        cursor.execute(
            f"""
            SELECT host,
                   COUNT(*) AS vulnerability_count,
                   ROUND(AVG(COALESCE(priority_score, 0)), 2) AS average_priority,
                   MAX(COALESCE(priority_score, 0)) AS max_priority,
                   SUM(CASE WHEN LOWER(COALESCE(severity, 'unknown')) = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                   SUM(CASE WHEN LOWER(COALESCE(severity, 'unknown')) = 'high' THEN 1 ELSE 0 END) AS high_count,
                   SUM(CASE WHEN has_public_exploit THEN 1 ELSE 0 END) AS exploitable_count
            FROM vulnerability
            WHERE {asset_where}
            GROUP BY host
            ORDER BY max_priority DESC, vulnerability_count DESC
            LIMIT %s OFFSET %s
            """,
            asset_params + [asset_limit, asset_offset],
        )
        assets = cursor.fetchall() or []

        vuln_where = "1=1"
        vuln_params = []
        if vuln_severity:
            vuln_where += " AND LOWER(severity) = %s"
            vuln_params.append(vuln_severity.lower())
        if vuln_host:
            vuln_where += " AND host LIKE %s"
            vuln_params.append(f"%{vuln_host}%")

        cursor.execute(
            f"SELECT COUNT(*) AS total FROM vulnerability WHERE {vuln_where}",
            vuln_params,
        )
        vuln_total_row = cursor.fetchone() or {}
        vuln_total = vuln_total_row.get("total") or 0
        cursor.execute(
            f"""
            SELECT id, cve, title, host, severity, cvss, epss, kev, has_poc,
                   has_public_exploit, priority_score, score_reason
            FROM vulnerability
            WHERE {vuln_where}
            ORDER BY COALESCE(priority_score, 0) DESC, id DESC
            LIMIT %s OFFSET %s
            """,
            vuln_params + [vuln_limit, vuln_offset],
        )
        top_vulnerabilities = cursor.fetchall() or []
        cursor.close()
        return {
            "summary": summary,
            "assets": assets,
            "asset_total": asset_total,
            "asset_limit": asset_limit,
            "asset_offset": asset_offset,
            "top_vulnerabilities": top_vulnerabilities,
            "vulnerability_total": vuln_total,
            "vulnerability_limit": vuln_limit,
            "vulnerability_offset": vuln_offset,
        }


def get_vulnerability_stats(org_name: str) -> dict:
    """Return dashboard aggregate stats for vulnerabilities and scans."""
    total_vulns = 0
    running_scans = 0
    total_scans = 0
    scheduled_scans = 0
    severity_breakdown = {}

    try:
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor(dictionary=True)
            _use_org_database(cursor, org_name)

            cursor.execute("SELECT COUNT(*) AS total FROM vulnerability")
            row = cursor.fetchone()
            total_vulns = row["total"] if row else 0

            cursor.execute(
                """
                SELECT LOWER(COALESCE(severity, 'unknown')) AS severity, COUNT(*) AS count
                FROM vulnerability
                GROUP BY LOWER(COALESCE(severity, 'unknown'))
                """
            )
            severity_rows = cursor.fetchall() or []
            severity_breakdown = {row["severity"]: row["count"] for row in severity_rows}

            cursor.execute(
                "SELECT COUNT(*) AS running FROM scans WHERE status IN ('queued', 'running', 'stopping')"
            )
            row = cursor.fetchone()
            running_scans = row["running"] if row else 0

            cursor.execute("SELECT COUNT(*) AS total FROM scans")
            row = cursor.fetchone()
            total_scans = row["total"] if row else 0

            try:
                cursor.execute("SELECT COUNT(*) AS total FROM scan_schedules WHERE enabled = TRUE")
                row = cursor.fetchone()
                scheduled_scans = row["total"] if row else 0
            except Exception:
                scheduled_scans = 0

            cursor.close()
    except Exception:
        logger.warning("Error getting vulnerability stats for organization")
        # Return empty stats on error - will be retried on next poll
        pass

    return {
        "total_vulnerabilities": total_vulns,
        "running_scans": running_scans,
        "total_scans": total_scans,
        "scheduled_scans": scheduled_scans,
        "severity_breakdown": severity_breakdown,
    }


class DatabaseConnectionManager:
    """
    Context manager for handling database connections.

    This class ensures that the database connection is properly opened and closed.
    """

    def __init__(self):
        self.db_config = {
            "user": os.environ.get("DB_USER"),
            "password": os.environ.get("DB_PASSWORD"),
            "host": os.environ.get("DB_HOST"),
            "database": os.environ.get("DB_NAME"),
        }

        if not all(self.db_config.values()):
            logger.error(
                "Database configuration is incomplete. Please check environment variables."
            )
            raise ValueError("Incomplete database configuration.")

        self.connection = None

    def __enter__(self):
        try:
            self.connection = mysql.connector.connect(**self.db_config)
            if not self.connection.is_connected():
                raise RuntimeError("Database connection could not be established")
            logger.debug("Connected to the database")
            return self.connection
        except mysql.connector.Error as e:
            logger.error(f"Error connecting to MySQL: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error while connecting to database: {e}")
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logger.debug("Database connection closed.")
        if exc_type:
            logger.error(f"An error occurred: {exc_value}")
            return False


def sanitize_string(value):
    """
    Remove ANSI escape codes, trim string and escape HTML characters.

    Args:
        value: Value to sanitize, expected to be a string

    Returns:
        Sanitized string or original value if not a string
    """

    if isinstance(value, str):
        return escape(
            re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", value).strip()
        )
    return value


def flatten_list(value):
    """
    Convert a list to a comma-separated string.

    Args:
        value: Value to flatten, expected to be a list

    Returns:
        str: Comma-separated string or original value if not a list
    """
    logger.debug(f"Value: {value}")
    if isinstance(value, list):
        new = ", ".join(map(str, value))
        logger.debug(f"New: {new}, type: {type(new)}")
        return new
    return value


def convert_to_json(value):
    """
    Convert a dictionary to a JSON string.

    Args:
        value: Value to convert, expected to be a dictionary

    Returns:
        str: JSON string or original value if not a dictionary
    """
    if isinstance(value, dict):
        return json.dumps(value)
    return value


def prepare_cve_data(vuln):
    """
    Clean and prepare CVE data for database insertion.

    Args:
        vuln (Vulnerability): Vulnerability object with CVE information

    Returns:
        tuple: Tuple of values ready for database insertion
    """
    title = sanitize_string(vuln.title).strip("[]")  # Sanitize title
    references = flatten_list(vuln.cve.references)  # Flatten references list
    pocs = flatten_list(vuln.cve.pocs)  # Flatten PoCs list
    impact = convert_to_json(vuln.cve.impact)  # Convert impact dict to JSON
    access = convert_to_json(vuln.cve.access)  # Convert access dict to JSON

    cve_data = (
        sanitize_string(vuln.cve.cve),  # Field 0
        title,  # Field 1 (Sanitized)
        sanitize_string(vuln.affected_item),  # Field 2
        sanitize_string(vuln.tool),  # Field 3
        vuln.confidence,  # Field 4
        sanitize_string(vuln.severity),  # Field 5
        sanitize_string(vuln.host),  # Field 6
        vuln.cve.cvss,  # Field 7
        vuln.cve.epss,  # Field 8 (Flattened)
        sanitize_string(vuln.cve.summary),  # Field 9
        sanitize_string(vuln.cve.cwe),  # Field 10
        references,  # Field 11 (Flattened)
        sanitize_string(vuln.cve.capec),  # Field 12
        sanitize_string(vuln.cve.solution),  # Field 13
        impact,  # Field 14 (JSON)
        access,  # Field 15 (JSON)
        vuln.cve.age,  # Field 16
        pocs,  # Field 17 (Flattened)
        vuln.cve.kev,  # Field 18
    )

    # Debugging log: Ensure no lists remain
    logger.debug("CVE Data Types and Values:")
    for i, field in enumerate(cve_data):
        logger.debug(f"Field {i}: Type = {type(field)}, Value = {field}")

    return cve_data


def prepare_non_cve_data(vuln):
    """
    Clean and prepare non-CVE vulnerability data for database insertion.

    Args:
        vuln (Vulnerability): Vulnerability object without CVE information

    Returns:
        tuple: Tuple of values ready for database insertion
    """
    references = flatten_list(vuln.references)
    poc = flatten_list(vuln.poc)

    non_cve_data = (
        None,  # No CVE
        sanitize_string(vuln.title),
        sanitize_string(vuln.affected_item),
        sanitize_string(vuln.tool),
        vuln.confidence,
        sanitize_string(vuln.severity),
        sanitize_string(vuln.host),
        vuln.cvss,
        vuln.epss,
        sanitize_string(vuln.summary),
        sanitize_string(vuln.cwe),
        references,
        sanitize_string(vuln.capec),
        sanitize_string(vuln.solution),
        sanitize_string(vuln.impact),
        None,  # No access for non-CVE
        None,  # No age for non-CVE
        poc,
        None,  # Non-CVE entries are not part of KEV
    )

    # Debugging log: Ensure no lists remain
    logger.debug("Non-CVE Data Types and Values:")
    for i, field in enumerate(non_cve_data):
        logger.debug(f"Field {i}: Type = {type(field)}, Value = {field}")

    return non_cve_data


def insert_vulnerability_to_database(vuln: Vulnerability, org_name: str) -> bool:
    """
    Insert a vulnerability record into the database.

    Args:
        vuln: Dictionary containing vulnerability data
        org_name: Organization name for database selection

    Returns:
        bool: True if successful, False otherwise
    """
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        insert_query = """
        INSERT INTO vulnerability (
            cve, title, affected_item, tool, confidence, severity, host,
            cvss, epss, summary, cwe, `references`, capec, solution, impact,
            access, age, pocs, kev
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        try:
            if (
                getattr(vuln, "tool", "") == "MailSecurityScanner"
                and str(getattr(vuln, "severity", "") or "").lower() == "baseline"
            ):
                vuln.severity = "info"
            if hasattr(vuln, "cve") and vuln.cve is not None:
                cursor.execute(insert_query, prepare_cve_data(vuln))
            else:
                cursor.execute(insert_query, prepare_non_cve_data(vuln))

            connection.commit()
            cursor.close()
            return True
        except Exception as exc:
            logger.warning(f"Failed to insert vulnerability for org {org_name}: {exc}")
            connection.rollback()
            cursor.close()
            return False


def insert_bbot_to_db(dataframe: pd.DataFrame, org_name: str) -> bool:
    """
    Insert bbot scan results into the database.

    Processes each row in the DataFrame and inserts it into the
    asmevents table in the organization-specific database.

    Args:
        dataframe (DataFrame): DataFrame containing bbot scan results
        org_name (str): Organization name/database name

    Returns:
        bool: True if successful, False otherwise
    """
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)  # ? Select the database for the organisation

        total_rows = len(dataframe)
        logger.info(f"Processing {total_rows} records for insertion")

        insert_query = """
        INSERT INTO asmevents (event_type, event_data, ip_address, source_module, scope_distance, event_tags, time)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        records = []
        # ? Iterate over DataFrame rows and prepare batched inserts
        for index, row in dataframe.iterrows():
            if index % 50 == 0:
                logger.info(f"Progress: {index}/{total_rows} records processed")

            try:
                event_type = json.dumps(json.loads(row["Event type"].replace("'", '"')))
            except (json.JSONDecodeError, AttributeError):
                event_type = row["Event type"]

            try:
                event_data = json.dumps(json.loads(row["Event data"].replace("'", '"')))
            except (json.JSONDecodeError, AttributeError):
                event_data = row["Event data"]

            try:
                ip_address = json.dumps(json.loads(row["IP Address"].replace("'", '"')))
            except (json.JSONDecodeError, AttributeError):
                ip_address = row["IP Address"]

            try:
                source_module = json.dumps(
                    json.loads(row["Source Module"].replace("'", '"'))
                )
            except (json.JSONDecodeError, AttributeError):
                source_module = row["Source Module"]

            try:
                scope_distance = json.dumps(
                    json.loads(row["Scope Distance"].replace("'", '"'))
                )
            except (json.JSONDecodeError, AttributeError):
                scope_distance = row["Scope Distance"]

            try:
                event_tags = json.dumps(json.loads(row["Event Tags"].replace("'", '"')))
            except (json.JSONDecodeError, AttributeError):
                event_tags = row["Event Tags"]

            # Handle the edge case with single quotes in nested JSON
            if (
                isinstance(event_data, str)
                and event_data.startswith("{")
                and event_data.endswith("}")
            ):
                event_data = event_data.replace("'", '"')

            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            records.append(
                (
                    event_type,
                    event_data,
                    ip_address,
                    source_module,
                    scope_distance,
                    event_tags,
                    current_time,
                )
            )

        if records:
            cursor.executemany(insert_query, records)

        # ? Commit the transaction
        connection.commit()
        logger.info(f"Successfully inserted {total_rows} records")
        cursor.close()
        return True
    return False


def insert_email_data(emails: list, org_name: str) -> bool:
    """
    Insert discovered email addresses into the database.

    Args:
        emails (list): List of email addresses to insert
        org_name (str): Organization name/database name

    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Inserting {len(emails)} email addresses for {org_name}")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)

        values = []
        for i, email in enumerate(emails, 1):
            if i % 10 == 0:
                logger.info(f"Progress: {i}/{len(emails)} emails processed")
            email = email.strip()
            if email:
                values.append((email,))

        if values:
            sql_query = "INSERT INTO email_input (email) VALUES (%s)"
            cursor.executemany(sql_query, values)

        connection.commit()
        logger.info(f"Successfully inserted {len(emails)} email addresses")
        cursor.close()
        return True
    return False


def insert_breached_email_data(email_breaches: list, org_name: str) -> bool:
    """
    Insert breached email information into the database.

    Args:
        email_breaches (list): List of breach data for emails
        org_name (str): Organization name/database name

    Returns:
        bool: True if successful, False otherwise
    """
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        values = [
            (email_breach[0], email_breach[1], email_breach[2], email_breach[3])
            for email_breach in email_breaches
        ]
        if values:
            sql_query = "INSERT INTO email_leaks (email, breach_name, breach_date, domain) VALUES (%s, %s, %s, %s)"
            cursor.executemany(sql_query, values)
            connection.commit()
        cursor.close()
        return True
    return False


def insert_password_data(passwords: list, org_name: str) -> bool:
    """
    Insert leaked password information into the database.

    Args:
        passwords (list): List of password data for emails
        org_name (str): Organization name/database nam

    Returns:
        bool: True if successful, False otherwise
    """
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        values = [(password[0], password[1]) for password in passwords]
        if values:
            sql_query = "INSERT INTO password_leaks (email, password) VALUES (%s, %s)"
            cursor.executemany(sql_query, values)
            connection.commit()
        cursor.close()
        return True
    return False


def insert_scan_log(org_name: str, scan_id: int, message: str, log_level: str = "info"):
    """Insert a log entry for a scan execution."""
    try:
        created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor()
            _use_org_database(cursor, org_name)
            cursor.execute(
                """
                INSERT INTO scan_logs (scan_id, log_level, message, created_at)
                VALUES (%s, %s, %s, %s)
                """,
                (scan_id, log_level, message[:16000], created_at),
            )
            connection.commit()
            cursor.close()
    except Exception as e:
        logger.warning(f"Failed to insert scan log for scan {scan_id}: {e}")


def insert_scan_logs_batch(org_name: str, scan_id: int, messages: list[str], log_level: str = "info"):
    """Insert multiple log entries for a scan in a single transaction."""
    if not messages:
        return

    try:
        created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor()
            _use_org_database(cursor, org_name)
            cursor.executemany(
                """
                INSERT INTO scan_logs (scan_id, log_level, message, created_at)
                VALUES (%s, %s, %s, %s)
                """,
                [(scan_id, log_level, (msg or "")[:16000], created_at) for msg in messages],
            )
            connection.commit()
            cursor.close()
    except Exception as e:
        logger.warning(f"Failed to insert scan log batch for scan {scan_id}: {e}")


def get_scan_logs(org_name: str, scan_id: int, limit: int = 500) -> list[dict]:
    """Retrieve scan execution logs."""
    limit = max(1, min(limit, 1000))
    try:
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor(dictionary=True)
            _use_org_database(cursor, org_name)
            cursor.execute(
                """
                SELECT id, scan_id, log_level, message, created_at
                FROM scan_logs
                WHERE scan_id = %s
                ORDER BY id ASC
                LIMIT %s
                """,
                (scan_id, limit),
            )
            rows = cursor.fetchall()
            cursor.close()
            return rows
    except Exception as e:
        logger.warning(f"Failed to get scan logs for scan {scan_id}: {e}")
        return []


def get_vulnerabilities_filtered(
    org_name: str,
    severity: str | None = None,
    host: str | None = None,
    tool: str | None = None,
    limit: int = 200,
    offset: int = 0,
    dedupe: bool = False,
) -> tuple[list[dict], int]:
    """
    Retrieve vulnerabilities with optional filtering.

    Returns: (items, total_count)
    """
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    try:
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor(dictionary=True)
            _use_org_database(cursor, org_name)

            where_clauses = []
            params = []

            if severity:
                where_clauses.append("LOWER(severity) = %s")
                params.append(severity.lower())

            if host:
                where_clauses.append("host LIKE %s")
                params.append(f"%{host}%")

            if tool:
                where_clauses.append("LOWER(tool) = %s")
                params.append(tool.lower())

            where_clause = " AND ".join(where_clauses) if where_clauses else "1=1"

            select_columns = [
                "id", "cve", "title", "affected_item", "tool", "confidence",
                "severity", "host", "cvss", "epss", "summary", "cwe", "capec",
                "solution", "impact", "age", "kev", "priority_score",
                "risk_score", "has_poc", "has_public_exploit",
                "exploit_maturity", "score_reason", "asset_criticality",
                "environment",
            ]
            select_sql = ", ".join(select_columns)
            select_sql_prefixed = ", ".join(f"v.{column}" for column in select_columns)

            if dedupe:
                dedupe_expr = """
                    LOWER(CONCAT_WS('|',
                        COALESCE(NULLIF(host, ''), 'unknown-host'),
                        COALESCE(NULLIF(cve, ''), NULLIF(title, ''), 'unknown-vulnerability'),
                        COALESCE(NULLIF(tool, ''), 'unknown-tool'),
                        COALESCE(NULLIF(affected_item, ''), 'unknown-item')
                    ))
                """
                cursor.execute(
                    f"""
                    SELECT COUNT(*) AS total
                    FROM (
                        SELECT 1
                        FROM vulnerability
                        WHERE {where_clause}
                        GROUP BY {dedupe_expr}
                    ) grouped
                    """,
                    params,
                )
                total_row = cursor.fetchone()
                total = total_row["total"] if total_row else 0
                cursor.execute(
                    f"""
                    SELECT {select_sql_prefixed},
                           grouped.duplicate_count
                    FROM vulnerability v
                    JOIN (
                        SELECT MAX(id) AS representative_id,
                               COUNT(*) AS duplicate_count
                        FROM vulnerability
                        WHERE {where_clause}
                        GROUP BY {dedupe_expr}
                    ) grouped ON grouped.representative_id = v.id
                    ORDER BY COALESCE(v.priority_score, 0) DESC, v.id DESC
                    LIMIT %s OFFSET %s
                    """,
                    params + [limit, offset],
                )
            else:
                cursor.execute(f"SELECT COUNT(*) AS total FROM vulnerability WHERE {where_clause}", params)
                total_row = cursor.fetchone()
                total = total_row["total"] if total_row else 0
                cursor.execute(
                    f"""
                    SELECT {select_sql}, 1 AS duplicate_count
                    FROM vulnerability
                    WHERE {where_clause}
                    ORDER BY COALESCE(priority_score, 0) DESC, id DESC
                    LIMIT %s OFFSET %s
                    """,
                    params + [limit, offset],
                )
            rows = cursor.fetchall()
            cursor.close()
            return rows, total
    except Exception as e:
        logger.warning(f"Failed to get filtered vulnerabilities: {e}")
        return [], 0


def get_vulnerability_detail(org_name: str, vulnerability_id: int) -> dict | None:
    """Return a detailed vulnerability record, including PoC/reference fields."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, cve, title, affected_item, tool, confidence, severity, host,
                   cvss, epss, summary, cwe, `references`, capec, solution, impact,
                   access, age, pocs, kev, priority_score, risk_score, has_poc,
                   has_public_exploit, exploit_maturity, score_reason,
                   asset_criticality, environment, scored_at
            FROM vulnerability
            WHERE id = %s
            """,
            (vulnerability_id,),
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def get_vulnerability_export_rows(
    org_name: str,
    severity: str | None = None,
    host: str | None = None,
    tool: str | None = None,
    limit: int = 5000,
) -> list[dict]:
    """Return vulnerability rows suitable for CSV/PDF export."""
    items, _ = get_vulnerabilities_filtered(
        org_name=org_name,
        severity=severity,
        host=host,
        tool=tool,
        limit=min(limit, 5000),
        offset=0,
    )
    return items


def get_grouped_vulnerabilities(org_name: str, group_by: str = "asset") -> list[dict]:
    """Return server-side grouping by asset or vulnerability definition."""
    group_by = group_by if group_by in {"asset", "vulnerability"} else "asset"
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        if group_by == "vulnerability":
            cursor.execute(
                """
                SELECT COALESCE(NULLIF(cve, ''), title, 'Unknown vulnerability') AS group_key,
                       COUNT(*) AS count,
                       MAX(COALESCE(priority_score, 0)) AS max_priority,
                       GROUP_CONCAT(DISTINCT host ORDER BY host SEPARATOR ', ') AS hosts
                FROM vulnerability
                GROUP BY COALESCE(NULLIF(cve, ''), title, 'Unknown vulnerability')
                ORDER BY max_priority DESC, count DESC
                LIMIT 100
                """
            )
        else:
            cursor.execute(
                """
                SELECT COALESCE(NULLIF(host, ''), 'Unknown asset') AS group_key,
                       COUNT(*) AS count,
                       MAX(COALESCE(priority_score, 0)) AS max_priority,
                       GROUP_CONCAT(DISTINCT COALESCE(NULLIF(cve, ''), title) ORDER BY priority_score DESC SEPARATOR ', ') AS vulnerabilities
                FROM vulnerability
                GROUP BY COALESCE(NULLIF(host, ''), 'Unknown asset')
                ORDER BY max_priority DESC, count DESC
                LIMIT 100
                """
            )
        rows = cursor.fetchall() or []
        cursor.close()
        return rows


def get_unique_hosts(org_name: str) -> list[str]:
    """Get list of unique hosts from vulnerabilities."""
    try:
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor()
            _use_org_database(cursor, org_name)
            cursor.execute("SELECT DISTINCT host FROM vulnerability WHERE host IS NOT NULL ORDER BY host")
            rows = cursor.fetchall()
            cursor.close()
            return [row[0] for row in rows]
    except Exception as e:
        logger.warning(f"Failed to get unique hosts: {e}")
        return []


def get_unique_tools(org_name: str) -> list[str]:
    """Get list of unique scanning tools."""
    try:
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor()
            _use_org_database(cursor, org_name)
            cursor.execute("SELECT DISTINCT tool FROM vulnerability WHERE tool IS NOT NULL ORDER BY tool")
            rows = cursor.fetchall()
            cursor.close()
            return [row[0] for row in rows]
    except Exception as e:
        logger.warning(f"Failed to get unique tools: {e}")
        return []


def _parse_event_payload(value):
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def _asm_asset(assets: dict, key: str) -> dict:
    if key not in assets:
        assets[key] = {
            "host": key,
            "ips": set(),
            "domains": set(),
            "urls": set(),
            "ports": {},
            "sources": set(),
            "tags": set(),
            "vulnerability_count": 0,
            "max_severity": "unknown",
            "max_priority": 0,
            "exploitable_count": 0,
            "last_seen": None,
        }
    return assets[key]


def _asm_asset_key(value: str | None) -> tuple[str, str | None]:
    """Return a stable ASM asset key and optional URL from a host/url value."""
    raw = str(value or "").strip()
    if not raw:
        return "", None
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = (parsed.hostname or raw).strip().lower()
        return host, raw
    return raw.split("/", 1)[0].strip().lower(), None


def _add_asm_port(asset: dict, port: str | int, service: str | None = None):
    port_text = str(port).strip()
    if not port_text:
        return
    service_text = str(service or "unknown").strip() or "unknown"
    asset["ports"][port_text] = service_text


def get_attack_surface_overview(
    org_name: str,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Return an ASM-oriented asset summary from findings, BBot events and scan logs."""
    search_text = (search or "").strip().lower()
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    assets: dict[str, dict] = {}

    try:
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor(dictionary=True)
            _use_org_database(cursor, org_name)

            cursor.execute(
                """
                SELECT host, affected_item, tool, severity, priority_score,
                       has_public_exploit, kev, id
                FROM vulnerability
                WHERE host IS NOT NULL AND host != ''
                """
            )
            for row in cursor.fetchall() or []:
                host, host_url = _asm_asset_key(row.get("host"))
                if not host:
                    continue
                asset = _asm_asset(assets, host)
                if host_url:
                    asset["urls"].add(host_url)
                affected_key, affected_url = _asm_asset_key(row.get("affected_item"))
                if affected_url and affected_key == host:
                    asset["urls"].add(affected_url)
                if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", host, re.IGNORECASE):
                    asset["domains"].add(host)
                asset["vulnerability_count"] += 1
                asset["sources"].add(str(row.get("tool") or "vulnerability"))
                asset["max_severity"] = _max_severity([asset["max_severity"], row.get("severity")])
                asset["max_priority"] = max(
                    asset["max_priority"],
                    float(row.get("priority_score") or 0),
                )
                if row.get("has_public_exploit") or row.get("kev"):
                    asset["exploitable_count"] += 1

            cursor.execute(
                """
                SELECT event_type, event_data, ip_address, source_module, event_tags, time
                FROM asmevents
                ORDER BY id DESC
                LIMIT 5000
                """
            )
            for row in cursor.fetchall() or []:
                event_type = str(row.get("event_type") or "").strip()
                event_data = _parse_event_payload(row.get("event_data"))
                ip_address = str(row.get("ip_address") or "").strip()
                source = str(row.get("source_module") or "asm").strip()
                tags = [
                    tag.strip()
                    for tag in str(row.get("event_tags") or "").split(",")
                    if tag.strip()
                ]

                host = None
                url = None
                if isinstance(event_data, dict):
                    host = event_data.get("host") or event_data.get("name")
                    url = event_data.get("url")
                elif isinstance(event_data, str):
                    if event_type in {"DNS_NAME", "URL", "URL_UNVERIFIED"}:
                        url = event_data if event_data.startswith(("http://", "https://")) else None
                        host = event_data if not url else re.sub(r"^https?://", "", event_data).split("/", 1)[0]

                host, host_url = _asm_asset_key(host or ip_address)
                if not host:
                    continue
                asset = _asm_asset(assets, host)
                if ip_address:
                    asset["ips"].add(ip_address)
                if event_type == "DNS_NAME":
                    asset["domains"].add(host)
                if url:
                    asset["urls"].add(url)
                if host_url:
                    asset["urls"].add(host_url)
                if source:
                    asset["sources"].add(source)
                asset["tags"].update(tags)
                if row.get("time"):
                    asset["last_seen"] = max(
                        [value for value in [asset["last_seen"], row.get("time")] if value],
                        default=row.get("time"),
                    )

            cursor.execute(
                """
                SELECT message
                FROM scan_logs
                WHERE message LIKE 'Found open ports on %'
                   OR message REGEXP '^Open .+:[0-9]+'
                ORDER BY id DESC
                LIMIT 5000
                """
            )
            for row in cursor.fetchall() or []:
                message = str(row.get("message") or "").strip()
                found_match = re.search(r"Found open ports on\s+([^:]+):\s+(.+)$", message)
                open_match = re.search(r"^Open\s+(.+):(\d+)$", message)
                if found_match:
                    host = found_match.group(1).strip()
                    asset = _asm_asset(assets, host)
                    asset["ips"].add(host)
                    asset["sources"].add("RustScan")
                    for item in found_match.group(2).split(","):
                        item = item.strip()
                        if not item:
                            continue
                        port, _, service = item.partition("/")
                        _add_asm_port(asset, port, service or "unknown")
                elif open_match:
                    host = open_match.group(1).strip()
                    asset = _asm_asset(assets, host)
                    asset["ips"].add(host)
                    asset["sources"].add("RustScan")
                    _add_asm_port(asset, open_match.group(2), "unknown")

            cursor.close()
    except Exception as e:
        logger.warning(f"Failed to build attack surface overview: {e}")

    # RustScan logs are IP-centric, while ASM events often hold the domain to IP
    # relationship. Fold IP-only port observations into the matching domain asset.
    ip_to_assets: dict[str, list[str]] = {}
    for key, asset in assets.items():
        if key in asset["ips"] and (asset["domains"] or asset["urls"] or asset["vulnerability_count"]):
            continue
        for ip in asset["ips"]:
            ip_to_assets.setdefault(ip, []).append(key)

    keys_to_drop = set()
    for key, asset in list(assets.items()):
        if not asset["ports"]:
            continue
        try:
            is_ip_asset = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", key))
        except Exception:
            is_ip_asset = False
        if not is_ip_asset:
            continue
        parent_keys = [
            parent_key
            for parent_key in ip_to_assets.get(key, [])
            if parent_key != key and assets.get(parent_key)
        ]
        for parent_key in parent_keys:
            parent = assets[parent_key]
            parent["ports"].update(asset["ports"])
            parent["sources"].update(asset["sources"])
            parent["tags"].update(asset["tags"])
        if parent_keys and asset["vulnerability_count"] == 0:
            keys_to_drop.add(key)

    for key in keys_to_drop:
        assets.pop(key, None)

    normalized_assets = []
    for asset in assets.values():
        if search_text:
            port_terms = [
                f"{port}/{service}"
                for port, service in asset["ports"].items()
            ]
            haystack = " ".join(
                [
                    asset["host"],
                    " ".join(asset["ips"]),
                    " ".join(asset["domains"]),
                    " ".join(asset["urls"]),
                    " ".join(port_terms),
                    " ".join(asset["sources"]),
                    " ".join(asset["tags"]),
                ]
            ).lower()
            if search_text not in haystack:
                continue
        ports = [
            {"port": port, "service": service}
            for port, service in sorted(asset["ports"].items(), key=lambda item: int(item[0]) if item[0].isdigit() else 999999)
        ]
        normalized_assets.append(
            {
                "host": asset["host"],
                "ips": sorted(asset["ips"]),
                "domains": sorted(asset["domains"]),
                "urls": sorted(asset["urls"])[:10],
                "ports": ports,
                "sources": sorted(asset["sources"]),
                "tags": sorted(asset["tags"])[:20],
                "vulnerability_count": asset["vulnerability_count"],
                "max_severity": asset["max_severity"],
                "max_priority": round(asset["max_priority"], 2),
                "exploitable_count": asset["exploitable_count"],
                "last_seen": asset["last_seen"],
            }
        )

    normalized_assets.sort(
        key=lambda asset: (
            SEVERITY_RANK.get(asset["max_severity"], 0),
            asset["max_priority"],
            asset["vulnerability_count"],
            len(asset["ports"]),
        ),
        reverse=True,
    )
    total = len(normalized_assets)
    page = normalized_assets[offset: offset + limit]
    all_ports = {
        f"{asset['host']}:{port['port']}"
        for asset in normalized_assets
        for port in asset["ports"]
    }
    summary = {
        "asset_count": total,
        "exposed_ports": len(all_ports),
        "service_count": sum(len(asset["ports"]) for asset in normalized_assets),
        "critical_assets": sum(1 for asset in normalized_assets if asset["max_severity"] == "critical"),
        "exploitable_assets": sum(1 for asset in normalized_assets if asset["exploitable_count"] > 0),
    }
    return {
        "summary": summary,
        "items": page,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def get_bbot_potential_targets(
    org_name: str,
    search: str | None = None,
    parent_domain: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Return BBot-discovered DNS/URL events as scan-ready potential targets."""
    search_text = (search or "").strip().lower()
    parent_filter = (parent_domain or "").strip().lower().lstrip(".")
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    targets: dict[str, dict] = {}
    parent_domains: set[str] = set()

    def add_parent_domain(value: str | None):
        host, _ = _asm_asset_key(value)
        if host:
            parent_domains.add(host.lower())

    def target_parent(host: str) -> str:
        host_l = (host or "").lower().strip(".")
        matches = [domain for domain in parent_domains if host_l == domain or host_l.endswith(f".{domain}")]
        if matches:
            return max(matches, key=len)
        parts = host_l.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host_l

    try:
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor(dictionary=True)
            _use_org_database(cursor, org_name)
            cursor.execute(
                """
                SELECT event_data
                FROM asmevents
                WHERE event_type = 'SCAN'
                ORDER BY id DESC
                LIMIT 500
                """
            )
            for row in cursor.fetchall() or []:
                event_data = _parse_event_payload(row.get("event_data"))
                if not isinstance(event_data, dict):
                    continue
                target_info = event_data.get("target") or {}
                for value in (target_info.get("whitelist") or []):
                    add_parent_domain(value)
                for value in (target_info.get("seeds") or []):
                    add_parent_domain(value)

            cursor.execute(
                """
                SELECT event_type, event_data, ip_address, source_module, event_tags, `time`
                FROM asmevents
                WHERE event_type IN ('DNS_NAME', 'URL', 'URL_UNVERIFIED')
                ORDER BY id DESC
                LIMIT 10000
                """
            )
            for row in cursor.fetchall() or []:
                event_type = str(row.get("event_type") or "").strip()
                event_data = _parse_event_payload(row.get("event_data"))
                value = ""
                if isinstance(event_data, dict):
                    value = event_data.get("url") or event_data.get("host") or event_data.get("name") or ""
                elif isinstance(event_data, str):
                    value = event_data
                host, url = _asm_asset_key(value)
                if not host:
                    continue
                if parent_filter and not (host.lower() == parent_filter or host.lower().endswith(f".{parent_filter}")):
                    continue
                parent = parent_filter or target_parent(host)
                if parent:
                    parent_domains.add(parent)
                target = targets.setdefault(
                    host,
                    {
                        "target": host,
                        "parent_domain": parent,
                        "preferred_target": url or host,
                        "urls": set(),
                        "ips": set(),
                        "event_types": set(),
                        "sources": set(),
                        "tags": set(),
                        "last_seen": None,
                    },
                )
                if url:
                    target["urls"].add(url)
                    target["preferred_target"] = url
                if row.get("ip_address"):
                    target["ips"].add(str(row.get("ip_address")))
                if event_type:
                    target["event_types"].add(event_type)
                if row.get("source_module"):
                    target["sources"].add(str(row.get("source_module")))
                tags = [
                    tag.strip()
                    for tag in str(row.get("event_tags") or "").split(",")
                    if tag.strip()
                ]
                target["tags"].update(tags)
                if row.get("time"):
                    target["last_seen"] = max(
                        [value for value in [target["last_seen"], row.get("time")] if value],
                        default=row.get("time"),
                    )
            cursor.close()
    except Exception as exc:
        logger.warning(f"Failed to load BBot potential targets: {exc}")

    items = []
    for target in targets.values():
        haystack = " ".join(
            [
                target["target"],
                target["parent_domain"],
                target["preferred_target"],
                " ".join(target["urls"]),
                " ".join(target["ips"]),
                " ".join(target["event_types"]),
                " ".join(target["sources"]),
                " ".join(target["tags"]),
            ]
        ).lower()
        if search_text and search_text not in haystack:
            continue
        items.append(
            {
                "target": target["target"],
                "parent_domain": target["parent_domain"],
                "preferred_target": target["preferred_target"],
                "urls": sorted(target["urls"])[:10],
                "ips": sorted(target["ips"]),
                "event_types": sorted(target["event_types"]),
                "sources": sorted(target["sources"]),
                "tags": sorted(target["tags"])[:20],
                "last_seen": target["last_seen"],
            }
        )
    items.sort(key=lambda item: (item.get("last_seen") or datetime.min, item["target"]), reverse=True)
    total = len(items)
    return {
        "items": items[offset: offset + limit],
        "total": total,
        "limit": limit,
        "offset": offset,
        "domains": sorted(parent_domains),
    }


def _coerce_schedule_datetime(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        try:
            return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


def create_scan_schedule(
    org_name: str,
    scan_name: str,
    targets: str,
    scan_mode: str | None,
    scanner: str | None,
    interval_minutes: int,
    bruteforce: bool = False,
    bruteforce_timeout: int = 300,
    start_at=None,
    end_at=None,
    preferred_node_id: str | None = None,
) -> int:
    """Create a periodic scan schedule."""
    now = datetime.utcnow()
    interval_minutes = max(10, min(int(interval_minutes), 5256000))
    start_dt = _coerce_schedule_datetime(start_at)
    end_dt = _coerce_schedule_datetime(end_at)
    if start_dt and end_dt and end_dt < start_dt:
        raise ValueError("Schedule end date must be after start date")
    next_run_at = start_dt if start_dt and start_dt > now else now + timedelta(minutes=interval_minutes)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            INSERT INTO scan_schedules (
                scan_name, scan_mode, scanner, targets, bruteforce, bruteforce_timeout, preferred_node_id,
                interval_minutes, enabled, start_at, end_at, next_run_at, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s, %s, %s, %s, %s)
            """,
            (
                scan_name,
                scan_mode,
                scanner,
                targets,
                bruteforce,
                bruteforce_timeout,
                preferred_node_id or None,
                interval_minutes,
                start_dt.strftime("%Y-%m-%d %H:%M:%S") if start_dt else None,
                end_dt.strftime("%Y-%m-%d %H:%M:%S") if end_dt else None,
                next_run_at.strftime("%Y-%m-%d %H:%M:%S"),
                now.strftime("%Y-%m-%d %H:%M:%S"),
                now.strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        schedule_id = cursor.lastrowid
        connection.commit()
        cursor.close()
        return int(schedule_id)


def get_scan_schedules(org_name: str) -> list[dict]:
    """Return scan schedules for an organization."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, scan_name, scan_mode, scanner, targets, bruteforce,
                   bruteforce_timeout, preferred_node_id, interval_minutes, enabled, start_at, end_at, next_run_at,
                   last_run_at, created_at, updated_at
            FROM scan_schedules
            ORDER BY next_run_at ASC
            """
        )
        rows = cursor.fetchall() or []
        cursor.close()
        return rows


def get_scan_schedule(org_name: str, schedule_id: int) -> dict | None:
    """Return one scan schedule."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, scan_name, scan_mode, scanner, targets, bruteforce,
                   bruteforce_timeout, preferred_node_id, interval_minutes, enabled, start_at, end_at, next_run_at,
                   last_run_at, created_at, updated_at
            FROM scan_schedules
            WHERE id = %s
            """,
            (schedule_id,),
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def set_scan_schedule_enabled(org_name: str, schedule_id: int, enabled: bool) -> bool:
    """Enable or disable a schedule."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            "UPDATE scan_schedules SET enabled = %s, updated_at = %s WHERE id = %s",
            (enabled, now, schedule_id),
        )
        changed = cursor.rowcount > 0
        connection.commit()
        cursor.close()
        return changed


def delete_scan_schedule(org_name: str, schedule_id: int) -> bool:
    """Delete a schedule."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute("DELETE FROM scan_schedules WHERE id = %s", (schedule_id,))
        changed = cursor.rowcount > 0
        connection.commit()
        cursor.close()
        return changed


def mark_schedule_run(org_name: str, schedule_id: int):
    """Move a schedule to its next run based on its interval."""
    schedule = get_scan_schedule(org_name, schedule_id)
    if not schedule:
        return
    now = datetime.utcnow()
    interval_minutes = int(schedule.get("interval_minutes") or 1440)
    next_run_at = now + timedelta(minutes=max(10, interval_minutes))
    end_dt = _coerce_schedule_datetime(schedule.get("end_at"))
    enabled = True
    if end_dt and next_run_at > end_dt:
        enabled = False
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            UPDATE scan_schedules
            SET last_run_at = %s, next_run_at = %s, enabled = %s, updated_at = %s
            WHERE id = %s
            """,
            (
                now.strftime("%Y-%m-%d %H:%M:%S"),
                next_run_at.strftime("%Y-%m-%d %H:%M:%S"),
                enabled,
                now.strftime("%Y-%m-%d %H:%M:%S"),
                schedule_id,
            ),
        )
        connection.commit()
        cursor.close()


def get_due_scan_schedules(org_name: str) -> list[dict]:
    """Return enabled schedules due for execution."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, scan_name, scan_mode, scanner, targets, bruteforce,
                   bruteforce_timeout, preferred_node_id, interval_minutes, enabled, start_at, end_at, next_run_at
            FROM scan_schedules
            WHERE enabled = TRUE
              AND next_run_at <= %s
              AND (start_at IS NULL OR start_at <= %s)
              AND (end_at IS NULL OR end_at >= %s)
            ORDER BY next_run_at ASC
            LIMIT 10
            """,
            (now, now, now),
        )
        rows = cursor.fetchall() or []
        cursor.close()
        return rows


def get_notification_settings(org_name: str) -> dict:
    """Return email notification settings for an organization."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute("SELECT * FROM notification_settings WHERE channel = 'email'")
        row = cursor.fetchone()
        if not row:
            cursor.execute(
                """
                INSERT INTO notification_settings (
                    channel, enabled, recipients, min_severity,
                    notify_on_success, notify_on_failure, updated_at
                ) VALUES ('email', FALSE, NULL, 'high', TRUE, TRUE, %s)
                """,
                (now,),
            )
            connection.commit()
            cursor.execute("SELECT * FROM notification_settings WHERE channel = 'email'")
            row = cursor.fetchone()
        cursor.close()
        return row or {}


def update_notification_settings(
    org_name: str,
    enabled: bool,
    recipients: str | None,
    min_severity: str = "high",
    notify_on_success: bool = True,
    notify_on_failure: bool = True,
) -> dict:
    """Upsert organization email notification settings."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            INSERT INTO notification_settings (
                channel, enabled, recipients, min_severity,
                notify_on_success, notify_on_failure, updated_at
            ) VALUES ('email', %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                enabled = VALUES(enabled),
                recipients = VALUES(recipients),
                min_severity = VALUES(min_severity),
                notify_on_success = VALUES(notify_on_success),
                notify_on_failure = VALUES(notify_on_failure),
                updated_at = VALUES(updated_at)
            """,
            (enabled, recipients, min_severity, notify_on_success, notify_on_failure, now),
        )
        connection.commit()
        cursor.close()
    return get_notification_settings(org_name)


def list_organizations() -> list[dict]:
    """Return known organizations from the global registry."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT org_name, org_db_name, role, mfa_required, sso_required, created_at, last_login_at
            FROM organizations
            ORDER BY org_name ASC
            """
        )
        rows = cursor.fetchall() or []
        cursor.close()
        return rows


def get_organization_role(org_db_name: str) -> str:
    """Return the global role for an organization database name."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            "SELECT role FROM organizations WHERE org_db_name = %s",
            (org_db_name,),
        )
        row = cursor.fetchone()
        cursor.close()
        return (row or {}).get("role") or "tenant_admin"


def get_organization_auth_settings(org_db_name: str, include_secrets: bool = False) -> dict:
    """Return MFA and SSO settings for an organization."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT org_name, org_db_name, role, mfa_required, sso_required, mfa_secret, mfa_enabled,
                   sso_enabled, sso_issuer, sso_client_id, sso_client_secret, sso_allowed_domain
            FROM organizations
            WHERE org_db_name = %s
            """,
            (org_db_name,),
        )
        row = cursor.fetchone() or {}
        cursor.close()

    if not include_secrets:
        row.pop("mfa_secret", None)
        row["sso_client_secret_configured"] = bool(row.get("sso_client_secret"))
        row.pop("sso_client_secret", None)
    return row


def get_sso_settings_by_org_name(org_name: str, include_secret: bool = False) -> dict | None:
    """Return OIDC SSO settings for a login organization name."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT org_name, org_db_name, role, sso_enabled, sso_issuer,
                   sso_client_id, sso_client_secret, sso_allowed_domain
            FROM organizations
            WHERE org_name = %s
            """,
            (org_name,),
        )
        row = cursor.fetchone()
        cursor.close()

    if row and not include_secret:
        row["sso_client_secret_configured"] = bool(row.get("sso_client_secret"))
        row.pop("sso_client_secret", None)
    return row


def update_mfa_secret(org_db_name: str, mfa_secret: str | None, enabled: bool) -> dict:
    """Update TOTP MFA settings for an organization."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            UPDATE organizations
            SET mfa_secret = %s, mfa_enabled = %s
            WHERE org_db_name = %s
            """,
            (mfa_secret, enabled, org_db_name),
        )
        connection.commit()
        cursor.close()
    return get_organization_auth_settings(org_db_name)


def update_sso_settings(
    org_db_name: str,
    enabled: bool,
    issuer: str | None,
    client_id: str | None,
    client_secret: str | None,
    allowed_domain: str | None,
) -> dict:
    """Update OIDC SSO settings for an organization."""
    current = get_organization_auth_settings(org_db_name, include_secrets=True)
    secret_to_store = current.get("sso_client_secret") if client_secret == "********" else client_secret
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            UPDATE organizations
            SET sso_enabled = %s,
                sso_issuer = %s,
                sso_client_id = %s,
                sso_client_secret = %s,
                sso_allowed_domain = %s
            WHERE org_db_name = %s
            """,
            (
                enabled,
                (issuer or "").rstrip("/") or None,
                client_id or None,
                secret_to_store or None,
                allowed_domain or None,
                org_db_name,
            ),
        )
        connection.commit()
        cursor.close()
    return get_organization_auth_settings(org_db_name)


def mark_organization_login(org_db_name: str):
    """Update last login time after completed local, MFA or SSO login."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        cursor.execute(
            "UPDATE organizations SET last_login_at = %s WHERE org_db_name = %s",
            (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), org_db_name),
        )
        connection.commit()
        cursor.close()


def _hash_api_key(api_key: str) -> str:
    """Return a slow keyed digest for API-style bearer tokens before storage."""
    secret = (
        os.environ.get("DARKSTAR_TOKEN_HASH_SECRET")
        or os.environ.get("WEB_SESSION_SECRET")
        or os.environ.get("DB_PASSWORD")
        or "darkstar-dev-token-hash-secret"
    )
    return hashlib.pbkdf2_hmac(
        "sha256",
        api_key.encode("utf-8"),
        secret.encode("utf-8"),
        210_000,
    ).hex()


def create_api_key(org_db_name: str, name: str, role: str = "tenant_admin") -> dict:
    """Create a one-time visible API key for REST API access."""
    api_key = f"dstar_{secrets.token_urlsafe(32)}"
    key_prefix = api_key[:14]
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            INSERT INTO api_keys (org_db_name, name, key_prefix, key_hash, role, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (org_db_name, name, key_prefix, _hash_api_key(api_key), role, created_at),
        )
        key_id = cursor.lastrowid
        connection.commit()
        cursor.close()
    return {"id": key_id, "name": name, "key": api_key, "key_prefix": key_prefix, "role": role, "created_at": created_at}


def list_api_keys(org_db_name: str) -> list[dict]:
    """List non-revoked API keys without exposing their secret value."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT id, name, key_prefix, role, last_used_at, created_at
            FROM api_keys
            WHERE org_db_name = %s AND revoked_at IS NULL
            ORDER BY created_at DESC
            """,
            (org_db_name,),
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


def revoke_api_key(org_db_name: str, key_id: int) -> bool:
    """Revoke an API key for the current organization."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            UPDATE api_keys
            SET revoked_at = %s
            WHERE id = %s AND org_db_name = %s AND revoked_at IS NULL
            """,
            (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), key_id, org_db_name),
        )
        changed = cursor.rowcount > 0
        connection.commit()
        cursor.close()
        return changed


def authenticate_api_key(api_key: str) -> dict | None:
    """Return organization auth context for a valid REST API key."""
    if not api_key:
        return None
    digest = _hash_api_key(api_key)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT k.id, k.org_db_name, k.role, k.key_hash, o.org_name
            FROM api_keys k
            JOIN organizations o ON o.org_db_name = k.org_db_name
            WHERE (k.key_hash = %s OR k.key_hash = SHA2(%s, 256))
              AND k.revoked_at IS NULL
            """,
            (digest, api_key),
        )
        row = cursor.fetchone()
        if row:
            cursor.execute(
                "UPDATE api_keys SET last_used_at = %s, key_hash = %s WHERE id = %s",
                (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), digest, row["id"]),
            )
            connection.commit()
            row.pop("key_hash", None)
        cursor.close()
        return row


def _endpoint_token() -> str:
    return f"dendp_{secrets.token_urlsafe(32)}"


def _software_key(item: dict) -> str:
    """Build a stable key without relying on display name alone."""
    purl = str(item.get("purl") or "").strip().lower()
    if purl:
        return hashlib.sha256(f"purl:{purl}".encode("utf-8")).hexdigest()[:40]
    cpe = str(item.get("cpe") or "").strip().lower()
    if cpe:
        return hashlib.sha256(f"cpe:{cpe}".encode("utf-8")).hexdigest()[:40]
    identity = "|".join(
        str(item.get(field) or "").strip().lower()
        for field in ("ecosystem", "source", "name", "version", "architecture", "install_location")
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:40]


def _normalize_software_item(item: dict) -> dict:
    normalized = dict(item or {})
    normalized["name"] = str(normalized.get("name") or "").strip()
    normalized["version"] = str(normalized.get("version") or "").strip() or None
    normalized["vendor"] = str(normalized.get("vendor") or "").strip() or None
    normalized["ecosystem"] = str(normalized.get("ecosystem") or normalized.get("type") or "unknown").strip().lower()
    normalized["purl"] = str(normalized.get("purl") or "").strip() or None
    normalized["cpe"] = str(normalized.get("cpe") or "").strip() or None
    normalized["architecture"] = str(normalized.get("architecture") or normalized.get("arch") or "").strip() or None
    normalized["install_location"] = str(normalized.get("install_location") or normalized.get("path") or "").strip() or None
    normalized["source"] = str(normalized.get("source") or "").strip() or None
    normalized["package_type"] = str(normalized.get("package_type") or normalized.get("type") or "").strip() or None
    normalized["source_package"] = str(normalized.get("source_package") or "").strip() or None
    normalized["source_version"] = str(normalized.get("source_version") or "").strip() or None
    normalized["software_key"] = str(normalized.get("software_key") or "").strip() or _software_key(normalized)
    return normalized


def create_endpoint_enrollment_token(
    org_name: str,
    name: str,
    expires_days: int | None = 30,
) -> dict:
    """Create a one-time visible endpoint enrollment token for one tenant."""
    token = _endpoint_token()
    token_prefix = token[:18]
    now = datetime.utcnow()
    expires_at = None
    if expires_days:
        expires_at = now + timedelta(days=max(1, min(int(expires_days), 3650)))
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            INSERT INTO endpoint_enrollment_tokens
                (name, token_prefix, token_hash, expires_at, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                name.strip() or "Endpoint enrollment",
                token_prefix,
                _hash_api_key(token),
                expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None,
                now.strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        token_id = cursor.lastrowid
        connection.commit()
        cursor.close()
    return {
        "id": token_id,
        "name": name,
        "token": token,
        "token_prefix": token_prefix,
        "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None,
        "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
    }


def list_endpoint_enrollment_tokens(org_name: str) -> list[dict]:
    """List endpoint enrollment tokens without exposing secrets."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, name, token_prefix, expires_at, revoked_at, last_used_at, created_at
            FROM endpoint_enrollment_tokens
            ORDER BY created_at DESC
            """
        )
        rows = cursor.fetchall() or []
        cursor.close()
    return rows


def revoke_endpoint_enrollment_token(org_name: str, token_id: int) -> bool:
    """Revoke one endpoint enrollment token."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            UPDATE endpoint_enrollment_tokens
            SET revoked_at = %s
            WHERE id = %s AND revoked_at IS NULL
            """,
            (_utcnow(), token_id),
        )
        changed = cursor.rowcount > 0
        connection.commit()
        cursor.close()
    return bool(changed)


def _endpoint_stale_minutes() -> int:
    try:
        return max(15, int(os.environ.get("ENDPOINT_AGENT_STALE_MINUTES", "90")))
    except ValueError:
        return 90


def mark_stale_endpoint_agents(org_name: str, stale_minutes: int | None = None) -> int:
    """Mark online endpoint agents offline when they have not checked in recently."""
    threshold = datetime.utcnow() - timedelta(minutes=stale_minutes or _endpoint_stale_minutes())
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            UPDATE endpoint_agents
            SET status = 'offline'
            WHERE status = 'online'
              AND revoked_at IS NULL
              AND last_seen_at < %s
            """,
            (threshold.strftime("%Y-%m-%d %H:%M:%S"),),
        )
        changed = cursor.rowcount
        connection.commit()
        cursor.close()
    return int(changed or 0)


def revoke_endpoint_agent(org_name: str, agent_id: str) -> bool:
    """Revoke one endpoint agent token without deleting its historical inventory."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            UPDATE endpoint_agents
            SET status = 'revoked', revoked_at = %s
            WHERE agent_id = %s AND revoked_at IS NULL
            """,
            (_utcnow(), agent_id),
        )
        changed = cursor.rowcount > 0
        connection.commit()
        cursor.close()
    return bool(changed)


def delete_endpoint_agent(org_name: str, agent_id: str) -> bool:
    """Delete one endpoint agent and its locally stored inventory/vulnerabilities."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        _ensure_endpoint_network_schema(cursor)
        cursor.execute("SELECT id FROM endpoint_agents WHERE agent_id = %s", (agent_id,))
        if not cursor.fetchone():
            cursor.close()
            return False
        cursor.execute("DELETE FROM endpoint_network_peer_checks WHERE source_agent_id = %s OR target_agent_id = %s", (agent_id, agent_id))
        cursor.execute("DELETE FROM endpoint_network_observations WHERE agent_id = %s", (agent_id,))
        cursor.execute("DELETE FROM endpoint_network_segments WHERE agent_id = %s", (agent_id,))
        cursor.execute("DELETE FROM endpoint_vulnerabilities WHERE agent_id = %s", (agent_id,))
        cursor.execute("DELETE FROM endpoint_software WHERE agent_id = %s", (agent_id,))
        cursor.execute("DELETE FROM endpoint_agents WHERE agent_id = %s", (agent_id,))
        connection.commit()
        cursor.close()
    return True


def _get_valid_endpoint_enrollment(cursor, token: str) -> dict | None:
    now = _utcnow()
    digest = _hash_api_key(token)
    cursor.execute(
        """
        SELECT id, name, token_hash
        FROM endpoint_enrollment_tokens
        WHERE (token_hash = %s OR token_hash = SHA2(%s, 256))
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at >= %s)
        """,
        (digest, token, now),
    )
    row = cursor.fetchone()
    if row and row.get("token_hash") != digest:
        cursor.execute(
            "UPDATE endpoint_enrollment_tokens SET token_hash = %s WHERE id = %s",
            (digest, row["id"]),
        )
    if row:
        row.pop("token_hash", None)
    return row


def register_endpoint_agent(
    org_name: str,
    enrollment_token: str,
    hostname: str,
    os_info: dict | None = None,
    agent_version: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Register an endpoint agent and return its long-lived agent token."""
    os_info = os_info or {}
    now = _utcnow()
    agent_token = _endpoint_token()
    agent_id = f"endp_{secrets.token_hex(10)}"
    hostname = (hostname or os_info.get("hostname") or "unknown").strip()[:255]
    metadata_payload = dict(metadata or {})
    if os_info:
        metadata_payload.setdefault("os", os_info)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        enrollment = _get_valid_endpoint_enrollment(cursor, enrollment_token)
        if not enrollment:
            cursor.close()
            raise ValueError("Invalid or expired endpoint enrollment token")
        cursor.execute(
            """
            INSERT INTO endpoint_agents (
                agent_id, hostname, display_name, os_platform, os_name, os_version,
                os_arch, os_build, agent_version, status, token_prefix, token_hash,
                enrollment_token_id, metadata_json, first_seen_at, last_seen_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'online', %s, %s, %s, %s, %s, %s)
            """,
            (
                agent_id,
                hostname,
                (metadata or {}).get("display_name"),
                os_info.get("platform"),
                os_info.get("name"),
                os_info.get("version"),
                os_info.get("arch"),
                os_info.get("build"),
                agent_version,
                agent_token[:18],
                _hash_api_key(agent_token),
                enrollment["id"],
                json.dumps(metadata_payload),
                now,
                now,
            ),
        )
        cursor.execute(
            "UPDATE endpoint_enrollment_tokens SET last_used_at = %s WHERE id = %s",
            (now, enrollment["id"]),
        )
        connection.commit()
        cursor.close()
    return {
        "agent_id": agent_id,
        "agent_token": agent_token,
        "hostname": hostname,
        "org_db": normalize_org_name(org_name),
    }


def authenticate_endpoint_agent(agent_token: str) -> dict | None:
    """Resolve an endpoint agent bearer token across tenant schemas."""
    if not agent_token:
        return None
    digest = _hash_api_key(agent_token)
    for organization in list_organizations():
        org_db = organization["org_db_name"]
        try:
            with DatabaseConnectionManager() as connection:
                cursor = connection.cursor(dictionary=True)
                _use_org_database(cursor, org_db)
                cursor.execute(
                    """
                    SELECT agent_id, hostname, status, token_hash
                    FROM endpoint_agents
                    WHERE (token_hash = %s OR token_hash = SHA2(%s, 256))
                      AND revoked_at IS NULL
                      AND status <> 'revoked'
                    """,
                    (digest, agent_token),
                )
                row = cursor.fetchone()
                if row:
                    cursor.execute(
                        """
                        UPDATE endpoint_agents
                        SET last_seen_at = %s,
                            status = 'online',
                            token_hash = %s
                        WHERE agent_id = %s
                        """,
                        (_utcnow(), digest, row["agent_id"]),
                    )
                    connection.commit()
                    cursor.close()
                    row.pop("token_hash", None)
                    row["org_db"] = org_db
                    return row
                cursor.close()
        except Exception as exc:
            logger.debug("Endpoint agent auth skipped for %s: %s", org_db, exc)
    return None


def upsert_endpoint_inventory(
    org_name: str,
    agent_id: str,
    os_info: dict | None,
    software: list[dict],
    ip_addresses: list[str] | None = None,
    mac_addresses: list[str] | None = None,
    metadata: dict | None = None,
    network_probe: dict | None = None,
) -> dict:
    """Store one full endpoint inventory snapshot."""
    now = _utcnow()
    normalized_items = [
        _normalize_software_item(item)
        for item in (software or [])
        if str((item or {}).get("name") or "").strip()
    ]
    metadata_payload = dict(metadata or {})
    if os_info:
        metadata_payload.setdefault("os", os_info)
    reported_agent_version = str(
        metadata_payload.get("collector_version")
        or metadata_payload.get("agent_version")
        or ""
    ).strip()[:64] or None
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            UPDATE endpoint_agents
            SET hostname = COALESCE(%s, hostname),
                os_platform = %s,
                os_name = %s,
                os_version = %s,
                os_arch = %s,
                os_build = %s,
                ip_addresses = %s,
                mac_addresses = %s,
                agent_version = COALESCE(%s, agent_version),
                metadata_json = %s,
                status = 'online',
                last_seen_at = %s,
                last_inventory_at = %s
            WHERE agent_id = %s
            """,
            (
                (metadata or {}).get("hostname") or (os_info or {}).get("hostname"),
                (os_info or {}).get("platform"),
                (os_info or {}).get("name"),
                (os_info or {}).get("version"),
                (os_info or {}).get("arch"),
                (os_info or {}).get("build"),
                json.dumps(ip_addresses or []),
                json.dumps(mac_addresses or []),
                reported_agent_version,
                json.dumps(metadata_payload),
                now,
                now,
                agent_id,
            ),
        )
        cursor.execute("UPDATE endpoint_software SET present = FALSE WHERE agent_id = %s", (agent_id,))
        for item in normalized_items:
            cursor.execute(
                """
                INSERT INTO endpoint_software (
                    agent_id, software_key, name, version, vendor, ecosystem, purl, cpe,
                    architecture, install_location, source, package_type, raw_json,
                    present, first_seen_at, last_seen_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s, %s)
                ON DUPLICATE KEY UPDATE
                    name = VALUES(name),
                    version = VALUES(version),
                    vendor = VALUES(vendor),
                    ecosystem = VALUES(ecosystem),
                    purl = VALUES(purl),
                    cpe = VALUES(cpe),
                    architecture = VALUES(architecture),
                    install_location = VALUES(install_location),
                    source = VALUES(source),
                    package_type = VALUES(package_type),
                    raw_json = VALUES(raw_json),
                    present = TRUE,
                    last_seen_at = VALUES(last_seen_at)
                """,
                (
                    agent_id,
                    item["software_key"],
                    item["name"],
                    item.get("version"),
                    item.get("vendor"),
                    item["ecosystem"],
                    item.get("purl"),
                    item.get("cpe"),
                    item.get("architecture"),
                    item.get("install_location"),
                    item.get("source"),
                    item.get("package_type"),
                    json.dumps(item),
                    now,
                    now,
                ),
            )
        connection.commit()
        cursor.close()
    if network_probe:
        upsert_endpoint_network_probe(org_name, agent_id, network_probe)
    return {"software_count": len(normalized_items), "software": normalized_items}


CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def _json_loads(value, fallback=None):
    if value is None or value == "":
        return fallback
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _json_dumps(value) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, default=str)


def _network_hash_key(prefix: str, *parts) -> str:
    payload = "|".join(str(part or "").strip().lower() for part in parts)
    digest = hashlib.blake2b(
        payload.encode("utf-8"),
        digest_size=16,
        person=b"darkstar-net-key",
    ).hexdigest()
    return f"{prefix}_{digest}"


def _clean_ip(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text.split("%", 1)[0]))
    except ValueError:
        return text[:64]


def _is_internal_endpoint_ip(value: str | None) -> bool:
    ip_text = _clean_ip(value)
    if not ip_text:
        return False
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    return bool(
        ip.is_private
        or ip in CGNAT_NETWORK
    ) and not bool(ip.is_loopback or ip.is_multicast or ip.is_unspecified)


def _endpoint_peer_ip_priority(value: str | None) -> int:
    ip_text = _clean_ip(value)
    try:
        ip = ipaddress.ip_address(ip_text or "")
    except ValueError:
        return 50
    if ip in CGNAT_NETWORK:
        return 0
    if ip.is_private:
        return 10
    return 40


def _bounded_list(value, limit: int = 32) -> list:
    if isinstance(value, list):
        return value[:limit]
    if value in (None, ""):
        return []
    return [value]


def _int_or_none(value) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _boolish(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "reachable", "open"}


def upsert_endpoint_network_probe(org_name: str, agent_id: str, network_probe: dict | None) -> dict:
    """Store one agent network probe snapshot for internal attack-surface mapping."""
    if not isinstance(network_probe, dict) or not network_probe:
        return {"segments": 0, "observations": 0, "peer_checks": 0}

    now = _utcnow()
    public_ip = _clean_ip(network_probe.get("public_ip"))
    interfaces = _bounded_list(network_probe.get("interfaces"), 128)
    neighbors = _bounded_list(network_probe.get("neighbors") or network_probe.get("observations"), 512)
    peer_checks = _bounded_list(network_probe.get("peer_checks"), 256)

    segments_changed = 0
    observations_changed = 0
    peer_checks_changed = 0

    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        _ensure_endpoint_network_schema(cursor)

        cursor.execute("UPDATE endpoint_network_segments SET present = FALSE WHERE agent_id = %s", (agent_id,))
        cursor.execute("UPDATE endpoint_network_observations SET present = FALSE WHERE agent_id = %s", (agent_id,))
        cursor.execute("UPDATE endpoint_network_peer_checks SET present = FALSE WHERE source_agent_id = %s", (agent_id,))

        for item in interfaces:
            if not isinstance(item, dict):
                continue
            cidr = str(item.get("cidr") or item.get("network_cidr") or "").strip()[:128] or None
            ip_address = _clean_ip(item.get("ip") or item.get("ip_address") or item.get("address"))
            interface_name = str(item.get("name") or item.get("interface") or item.get("interface_name") or "").strip()[:255] or None
            mac_address = str(item.get("mac") or item.get("mac_address") or "").strip()[:64] or None
            gateway = _clean_ip(item.get("gateway") or item.get("default_gateway"))
            if not cidr and not ip_address:
                continue
            segment_key = _network_hash_key("seg", cidr, interface_name, ip_address)
            cursor.execute(
                """
                INSERT INTO endpoint_network_segments (
                    agent_id, segment_key, cidr, interface_name, ip_address,
                    mac_address, gateway, public_ip, raw_json, present, first_seen_at, last_seen_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s, %s)
                ON DUPLICATE KEY UPDATE
                    cidr = VALUES(cidr),
                    interface_name = VALUES(interface_name),
                    ip_address = VALUES(ip_address),
                    mac_address = VALUES(mac_address),
                    gateway = VALUES(gateway),
                    public_ip = VALUES(public_ip),
                    raw_json = VALUES(raw_json),
                    present = TRUE,
                    last_seen_at = VALUES(last_seen_at)
                """,
                (
                    agent_id,
                    segment_key,
                    cidr,
                    interface_name,
                    ip_address,
                    mac_address,
                    gateway,
                    public_ip,
                    _json_dumps(item),
                    now,
                    now,
                ),
            )
            segments_changed += 1

        for item in neighbors:
            if not isinstance(item, dict):
                continue
            ip_address = _clean_ip(item.get("ip") or item.get("ip_address") or item.get("address"))
            mac_address = str(item.get("mac") or item.get("mac_address") or "").strip()[:64] or None
            hostname = str(item.get("hostname") or item.get("name") or "").strip()[:255] or None
            network_cidr = str(item.get("network_cidr") or item.get("cidr") or "").strip()[:128] or None
            interface_name = str(item.get("interface") or item.get("interface_name") or "").strip()[:255] or None
            source = str(item.get("source") or "neighbor").strip()[:64] or "neighbor"
            if not ip_address and not mac_address and not hostname:
                continue
            observation_key = _network_hash_key("obs", source, ip_address, mac_address, hostname)
            open_ports = _bounded_list(item.get("open_ports"), 64)
            protocols = _bounded_list(item.get("protocols"), 64)
            cursor.execute(
                """
                INSERT INTO endpoint_network_observations (
                    agent_id, observation_key, ip_address, hostname, mac_address,
                    vendor_hint, device_type, os_family, confidence, reachability,
                    open_ports, protocols, source, network_cidr, interface_name,
                    public_ip, raw_json, present, first_seen_at, last_seen_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s, %s)
                ON DUPLICATE KEY UPDATE
                    ip_address = VALUES(ip_address),
                    hostname = VALUES(hostname),
                    mac_address = VALUES(mac_address),
                    vendor_hint = VALUES(vendor_hint),
                    device_type = VALUES(device_type),
                    os_family = VALUES(os_family),
                    confidence = VALUES(confidence),
                    reachability = VALUES(reachability),
                    open_ports = VALUES(open_ports),
                    protocols = VALUES(protocols),
                    source = VALUES(source),
                    network_cidr = VALUES(network_cidr),
                    interface_name = VALUES(interface_name),
                    public_ip = VALUES(public_ip),
                    raw_json = VALUES(raw_json),
                    present = TRUE,
                    last_seen_at = VALUES(last_seen_at)
                """,
                (
                    agent_id,
                    observation_key,
                    ip_address,
                    hostname,
                    mac_address,
                    str(item.get("vendor_hint") or item.get("vendor") or "").strip()[:255] or None,
                    str(item.get("device_type") or "unknown").strip()[:64] or "unknown",
                    str(item.get("os_family") or item.get("os") or "").strip()[:64] or None,
                    _int_or_none(item.get("confidence")),
                    str(item.get("reachability") or item.get("state") or "").strip()[:64] or None,
                    _json_dumps(open_ports),
                    _json_dumps(protocols),
                    source,
                    network_cidr,
                    interface_name,
                    public_ip,
                    _json_dumps(item),
                    now,
                    now,
                ),
            )
            observations_changed += 1

        for item in peer_checks:
            if not isinstance(item, dict):
                continue
            target_agent_id = str(item.get("agent_id") or item.get("target_agent_id") or "").strip()[:64]
            target_ip = _clean_ip(item.get("ip") or item.get("target_ip") or item.get("address"))
            if not target_agent_id or not target_ip:
                continue
            cursor.execute(
                """
                INSERT INTO endpoint_network_peer_checks (
                    source_agent_id, target_agent_id, target_ip, reachable,
                    method, latency_ms, open_ports, raw_json, present,
                    first_seen_at, last_seen_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s, %s)
                ON DUPLICATE KEY UPDATE
                    reachable = VALUES(reachable),
                    method = VALUES(method),
                    latency_ms = VALUES(latency_ms),
                    open_ports = VALUES(open_ports),
                    raw_json = VALUES(raw_json),
                    present = TRUE,
                    last_seen_at = VALUES(last_seen_at)
                """,
                (
                    agent_id,
                    target_agent_id,
                    target_ip,
                    _boolish(item.get("reachable")),
                    str(item.get("method") or "").strip()[:64] or None,
                    _int_or_none(item.get("latency_ms")),
                    _json_dumps(_bounded_list(item.get("open_ports"), 64)),
                    _json_dumps(item),
                    now,
                    now,
                ),
            )
            peer_checks_changed += 1

        connection.commit()
        cursor.close()

    return {
        "segments": segments_changed,
        "observations": observations_changed,
        "peer_checks": peer_checks_changed,
    }


def get_endpoint_network_probe_targets(org_name: str, agent_id: str, limit: int = 64) -> list[dict]:
    """Return peer endpoint IPs the agent should lightly test on its next run."""
    limit = max(1, min(int(limit or 64), 256))
    targets: list[dict] = []
    seen: set[tuple[str, str]] = set()
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT agent_id, hostname, os_platform, ip_addresses
            FROM endpoint_agents
            WHERE agent_id <> %s
              AND revoked_at IS NULL
              AND status <> 'revoked'
            ORDER BY last_seen_at DESC
            LIMIT 500
            """,
            (agent_id,),
        )
        rows = cursor.fetchall() or []
        cursor.close()
    for row in rows:
        for ip in _json_loads(row.get("ip_addresses"), []) or []:
            ip_text = _clean_ip(ip)
            if not _is_internal_endpoint_ip(ip_text):
                continue
            key = (row["agent_id"], ip_text)
            if key in seen:
                continue
            seen.add(key)
            targets.append({
                "agent_id": row["agent_id"],
                "hostname": row.get("hostname"),
                "ip": ip_text,
                "os_platform": row.get("os_platform"),
                "source": "endpoint_agent",
            })
    targets.sort(key=lambda item: (_endpoint_peer_ip_priority(item.get("ip")), item.get("hostname") or "", item.get("ip") or ""))
    return targets[:limit]


def get_endpoint_network_map(org_name: str) -> dict:
    """Build a tenant network map from the latest endpoint network probes."""
    mark_stale_endpoint_agents(org_name)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        _ensure_endpoint_network_schema(cursor)
        cursor.execute(
            """
            SELECT a.id, a.agent_id, a.hostname, a.display_name, a.os_platform,
                   a.os_name, a.os_version, a.ip_addresses, a.mac_addresses,
                   a.status, a.last_seen_at, a.last_inventory_at,
                   COALESCE(v_counts.vulnerability_count, 0) AS vulnerability_count
            FROM endpoint_agents a
            LEFT JOIN (
                SELECT agent_id, COUNT(*) AS vulnerability_count
                FROM endpoint_vulnerabilities
                WHERE present = TRUE
                GROUP BY agent_id
            ) v_counts ON v_counts.agent_id = a.agent_id
            ORDER BY a.last_seen_at DESC
            """
        )
        agents = cursor.fetchall() or []
        cursor.execute(
            """
            SELECT s.*, a.hostname
            FROM endpoint_network_segments s
            LEFT JOIN endpoint_agents a ON a.agent_id = s.agent_id
            WHERE s.present = TRUE
            ORDER BY s.last_seen_at DESC
            LIMIT 2000
            """
        )
        segments = cursor.fetchall() or []
        cursor.execute(
            """
            SELECT o.*, a.hostname AS agent_hostname
            FROM endpoint_network_observations o
            LEFT JOIN endpoint_agents a ON a.agent_id = o.agent_id
            WHERE o.present = TRUE
            ORDER BY o.last_seen_at DESC
            LIMIT 5000
            """
        )
        observations = cursor.fetchall() or []
        cursor.execute(
            """
            SELECT p.*, source.hostname AS source_hostname, target.hostname AS target_hostname
            FROM endpoint_network_peer_checks p
            LEFT JOIN endpoint_agents source ON source.agent_id = p.source_agent_id
            LEFT JOIN endpoint_agents target ON target.agent_id = p.target_agent_id
            WHERE p.present = TRUE
            ORDER BY p.last_seen_at DESC
            LIMIT 2000
            """
        )
        peer_checks = cursor.fetchall() or []
        cursor.close()

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    segment_rollup: dict[str, dict] = {}
    public_ip_agents: dict[str, set[str]] = {}

    for agent in agents:
        node_id = f"agent:{agent['agent_id']}"
        ips = _json_loads(agent.get("ip_addresses"), []) or []
        nodes[node_id] = {
            "id": node_id,
            "type": "agent",
            "agent_id": agent["agent_id"],
            "label": agent.get("hostname") or agent["agent_id"],
            "hostname": agent.get("hostname"),
            "status": agent.get("status"),
            "os": " ".join(part for part in [agent.get("os_name"), agent.get("os_version")] if part),
            "ip_addresses": ips,
            "risk": int(agent.get("vulnerability_count") or 0),
            "last_seen_at": agent.get("last_seen_at"),
        }

    for segment in segments:
        public_ip = segment.get("public_ip")
        if public_ip:
            public_ip_agents.setdefault(public_ip, set()).add(segment.get("agent_id"))
        cidr = segment.get("cidr") or "unknown"
        net_key = f"{cidr}|{public_ip or ''}"
        node_id = f"net:{_network_hash_key('n', net_key)}"
        rollup = segment_rollup.setdefault(node_id, {
            "id": node_id,
            "cidr": cidr,
            "public_ip": public_ip,
            "agents": [],
            "gateways": set(),
            "device_count": 0,
            "firewall_count": 0,
            "last_seen_at": segment.get("last_seen_at"),
        })
        if segment.get("agent_id") not in rollup["agents"]:
            rollup["agents"].append(segment.get("agent_id"))
        if segment.get("gateway"):
            rollup["gateways"].add(segment.get("gateway"))
        nodes.setdefault(node_id, {
            "id": node_id,
            "type": "network",
            "label": cidr,
            "cidr": cidr,
            "public_ip": public_ip,
        })
        source_id = f"agent:{segment.get('agent_id')}"
        if source_id in nodes:
            edges.append({"source": source_id, "target": node_id, "type": "member", "label": segment.get("interface_name") or ""})

    for observation in observations:
        ip_address = observation.get("ip_address")
        device_basis = ip_address or observation.get("mac_address") or observation.get("observation_key")
        device_id = f"device:{_network_hash_key('d', device_basis)}"
        raw = _json_loads(observation.get("raw_json"), {}) or {}
        open_ports = _json_loads(observation.get("open_ports"), []) or []
        device_type = observation.get("device_type") or "unknown"
        nodes[device_id] = {
            "id": device_id,
            "type": "device",
            "label": observation.get("hostname") or ip_address or observation.get("mac_address") or "device",
            "ip_address": ip_address,
            "hostname": observation.get("hostname"),
            "mac_address": observation.get("mac_address"),
            "device_type": device_type,
            "os_family": observation.get("os_family"),
            "open_ports": open_ports,
            "confidence": observation.get("confidence"),
            "agent_id": observation.get("agent_id"),
            "last_seen_at": observation.get("last_seen_at"),
        }
        network_node_id = None
        cidr = observation.get("network_cidr")
        public_ip = observation.get("public_ip")
        if cidr:
            observation_net_key = f"{cidr}|{public_ip or ''}"
            network_node_id = f"net:{_network_hash_key('n', observation_net_key)}"
        source_id = network_node_id if network_node_id in nodes else f"agent:{observation.get('agent_id')}"
        if source_id in nodes:
            edges.append({"source": source_id, "target": device_id, "type": "observed", "label": ",".join(str(port) for port in open_ports[:4])})
        if network_node_id in segment_rollup:
            segment_rollup[network_node_id]["device_count"] += 1
            if device_type in {"firewall", "router", "network_device"}:
                segment_rollup[network_node_id]["firewall_count"] += 1

    for peer in peer_checks:
        source_id = f"agent:{peer.get('source_agent_id')}"
        target_id = f"agent:{peer.get('target_agent_id')}"
        if source_id in nodes and target_id in nodes:
            edges.append({
                "source": source_id,
                "target": target_id,
                "type": "peer_reachable" if peer.get("reachable") else "peer_unreachable",
                "label": peer.get("target_ip"),
                "reachable": bool(peer.get("reachable")),
            })

    public_ip_groups = [
        {
            "public_ip": public_ip,
            "agent_count": len(agent_ids),
            "agents": sorted(agent_ids),
            "shared": len(agent_ids) > 1,
        }
        for public_ip, agent_ids in public_ip_agents.items()
    ]
    firewall_candidates = sum(1 for row in observations if (row.get("device_type") or "") in {"firewall", "router", "network_device"})
    summary = {
        "agents": len(agents),
        "online_agents": sum(1 for row in agents if row.get("status") == "online"),
        "networks": len(segment_rollup),
        "observed_devices": len(observations),
        "firewall_candidates": firewall_candidates,
        "peer_links": sum(1 for row in peer_checks if row.get("reachable")),
        "public_ip_groups": len(public_ip_groups),
    }
    rendered_segments = []
    for segment in segment_rollup.values():
        rendered = dict(segment)
        rendered["gateways"] = sorted(segment["gateways"])
        rendered_segments.append(rendered)

    return {
        "summary": summary,
        "nodes": list(nodes.values()),
        "edges": edges,
        "segments": rendered_segments,
        "observations": observations,
        "peer_checks": peer_checks,
        "public_ip_groups": public_ip_groups,
    }


def replace_endpoint_vulnerabilities(org_name: str, agent_id: str, findings: list[dict]) -> int:
    """Replace current endpoint vuln state with strict matcher output."""
    now = _utcnow()
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute("UPDATE endpoint_vulnerabilities SET present = FALSE WHERE agent_id = %s", (agent_id,))
        for finding in findings or []:
            cursor.execute(
                """
                INSERT INTO endpoint_vulnerabilities (
                    agent_id, software_key, cve, source, severity, cvss, summary,
                    fixed_version, affected_version, purl, confidence, evidence_json,
                    present, first_seen_at, last_seen_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s, %s)
                ON DUPLICATE KEY UPDATE
                    severity = VALUES(severity),
                    cvss = VALUES(cvss),
                    summary = VALUES(summary),
                    fixed_version = VALUES(fixed_version),
                    affected_version = VALUES(affected_version),
                    purl = VALUES(purl),
                    confidence = VALUES(confidence),
                    evidence_json = VALUES(evidence_json),
                    present = TRUE,
                    last_seen_at = VALUES(last_seen_at)
                """,
                (
                    agent_id,
                    finding.get("software_key"),
                    finding.get("cve") or finding.get("id"),
                    finding.get("source") or "OSV",
                    finding.get("severity"),
                    finding.get("cvss"),
                    finding.get("summary"),
                    finding.get("fixed_version"),
                    finding.get("affected_version"),
                    finding.get("purl"),
                    int(finding.get("confidence") or 95),
                    json.dumps(finding.get("evidence") or finding),
                    now,
                    now,
                ),
            )
        connection.commit()
        cursor.close()
    return len(findings or [])


def _endpoint_vuln_cache_id(query: dict) -> str:
    return f"{query.get('source') or 'OSV'}:{query.get('package_hash')}:{query.get('version')}"


def _endpoint_vuln_cache_ttl_hours() -> int:
    try:
        return max(1, min(int(os.environ.get("ENDPOINT_VULN_CACHE_TTL_HOURS", "24")), 720))
    except ValueError:
        return 24


def get_endpoint_vuln_cache_entries(org_name: str, queries: list[dict]) -> dict[str, list[dict]]:
    """Return fresh endpoint vulnerability cache entries keyed by source/hash/version."""
    unique = {}
    for query in queries or []:
        if query.get("package_hash") and query.get("version"):
            unique[_endpoint_vuln_cache_id(query)] = query
    if not unique:
        return {}

    now = _utcnow()
    found: dict[str, list[dict]] = {}
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        for cache_id, query in unique.items():
            cursor.execute(
                """
                SELECT findings_json
                FROM endpoint_vuln_cache
                WHERE package_hash = %s
                  AND version = %s
                  AND source = %s
                  AND expires_at >= %s
                """,
                (
                    query["package_hash"],
                    str(query["version"]),
                    query.get("source") or "OSV",
                    now,
                ),
            )
            row = cursor.fetchone()
            if not row:
                continue
            try:
                payload = json.loads(row.get("findings_json") or "[]")
                found[cache_id] = payload if isinstance(payload, list) else []
            except Exception:
                found[cache_id] = []
        cursor.close()
    return found


def upsert_endpoint_vuln_cache_entries(
    org_name: str,
    entries: list[dict],
    ttl_hours: int | None = None,
) -> int:
    """Store endpoint vulnerability matcher results in the tenant-local cache."""
    if not entries:
        return 0
    now_dt = datetime.utcnow()
    expires_dt = now_dt + timedelta(hours=ttl_hours or _endpoint_vuln_cache_ttl_hours())
    now = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    expires_at = expires_dt.strftime("%Y-%m-%d %H:%M:%S")
    changed = 0
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        for entry in entries:
            query = entry.get("query") or entry
            if not query.get("package_identity") or not query.get("package_hash") or not query.get("version"):
                continue
            cursor.execute(
                """
                INSERT INTO endpoint_vuln_cache (
                    package_identity, package_hash, version, source,
                    findings_json, last_checked_at, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    package_identity = VALUES(package_identity),
                    findings_json = VALUES(findings_json),
                    last_checked_at = VALUES(last_checked_at),
                    expires_at = VALUES(expires_at)
                """,
                (
                    query["package_identity"],
                    query["package_hash"],
                    str(query["version"]),
                    query.get("source") or "OSV",
                    json.dumps(entry.get("findings") or []),
                    now,
                    expires_at,
                ),
            )
            changed += 1
        connection.commit()
        cursor.close()
    return changed


def get_endpoint_overview(org_name: str) -> dict:
    """Return endpoint inventory summary."""
    mark_stale_endpoint_agents(org_name)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute("SELECT COUNT(*) AS total FROM endpoint_agents")
        agents_total = (cursor.fetchone() or {}).get("total") or 0
        cursor.execute("SELECT COUNT(*) AS total FROM endpoint_agents WHERE status = 'online' AND revoked_at IS NULL")
        online_total = (cursor.fetchone() or {}).get("total") or 0
        cursor.execute("SELECT COUNT(*) AS total FROM endpoint_agents WHERE status = 'offline' AND revoked_at IS NULL")
        offline_total = (cursor.fetchone() or {}).get("total") or 0
        cursor.execute("SELECT COUNT(*) AS total FROM endpoint_agents WHERE revoked_at IS NOT NULL OR status = 'revoked'")
        revoked_total = (cursor.fetchone() or {}).get("total") or 0
        cursor.execute("SELECT COUNT(*) AS total FROM endpoint_software WHERE present = TRUE")
        software_total = (cursor.fetchone() or {}).get("total") or 0
        cursor.execute("SELECT COUNT(*) AS total FROM endpoint_vulnerabilities WHERE present = TRUE")
        vuln_total = (cursor.fetchone() or {}).get("total") or 0
        cursor.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM endpoint_vulnerabilities
            WHERE present = TRUE
            GROUP BY severity
            """
        )
        severity = {row["severity"] or "unknown": row["count"] for row in cursor.fetchall() or []}
        cursor.close()
    return {
        "agents": agents_total,
        "online_agents": online_total,
        "offline_agents": offline_total,
        "revoked_agents": revoked_total,
        "software": software_total,
        "vulnerabilities": vuln_total,
        "severity": severity,
    }


def list_endpoint_agents(
    org_name: str,
    search: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """List endpoint agents with software and vulnerability counts."""
    mark_stale_endpoint_agents(org_name)
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    clauses = ["1 = 1"]
    params: list = []
    if status:
        clauses.append("LOWER(a.status) = %s")
        params.append(status.lower())
    if search:
        clauses.append(
            "(a.hostname LIKE %s OR a.display_name LIKE %s OR a.os_name LIKE %s OR a.ip_addresses LIKE %s OR a.agent_id LIKE %s)"
        )
        needle = f"%{search}%"
        params.extend([needle, needle, needle, needle, needle])
    where = " AND ".join(clauses)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(f"SELECT COUNT(*) AS total FROM endpoint_agents a WHERE {where}", params)
        total = (cursor.fetchone() or {}).get("total") or 0
        cursor.execute(
            f"""
            SELECT a.id, a.agent_id, a.hostname, a.display_name, a.os_platform,
                   a.os_name, a.os_version, a.os_arch, a.os_build,
                   a.ip_addresses, a.mac_addresses, a.agent_version, a.status,
                   a.token_prefix, a.enrollment_token_id, a.metadata_json,
                   a.revoked_at, a.first_seen_at, a.last_seen_at, a.last_inventory_at,
                   COALESCE(s_counts.software_count, 0) AS software_count,
                   COALESCE(v_counts.vulnerability_count, 0) AS vulnerability_count
            FROM endpoint_agents a
            LEFT JOIN (
                SELECT agent_id, COUNT(*) AS software_count
                FROM endpoint_software
                WHERE present = TRUE
                GROUP BY agent_id
            ) s_counts ON s_counts.agent_id = a.agent_id
            LEFT JOIN (
                SELECT agent_id, COUNT(*) AS vulnerability_count
                FROM endpoint_vulnerabilities
                WHERE present = TRUE
                GROUP BY agent_id
            ) v_counts ON v_counts.agent_id = a.agent_id
            WHERE {where}
            ORDER BY a.last_seen_at DESC
            LIMIT %s OFFSET %s
            """
            ,
            (*params, limit, offset),
        )
        rows = cursor.fetchall() or []
        cursor.close()
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def get_endpoint_agent(org_name: str, agent_id: str) -> dict | None:
    """Return one endpoint agent."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, agent_id, hostname, display_name, os_platform, os_name,
                   os_version, os_arch, os_build, ip_addresses, mac_addresses,
                   agent_version, status, token_prefix, enrollment_token_id,
                   metadata_json, revoked_at, first_seen_at, last_seen_at, last_inventory_at
            FROM endpoint_agents
            WHERE agent_id = %s
            """,
            (agent_id,),
        )
        row = cursor.fetchone()
        cursor.close()
    return row


def list_endpoint_software(
    org_name: str,
    agent_id: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """List present endpoint software."""
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    clauses = ["s.present = TRUE"]
    params: list = []
    if agent_id:
        clauses.append("s.agent_id = %s")
        params.append(agent_id)
    if search:
        clauses.append(
            "(s.name LIKE %s OR s.version LIKE %s OR s.vendor LIKE %s OR s.purl LIKE %s OR a.hostname LIKE %s)"
        )
        needle = f"%{search}%"
        params.extend([needle, needle, needle, needle, needle])
    where = " AND ".join(clauses)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM endpoint_software s
            LEFT JOIN endpoint_agents a ON a.agent_id = s.agent_id
            WHERE {where}
            """,
            params,
        )
        total = (cursor.fetchone() or {}).get("total") or 0
        cursor.execute(
            f"""
            SELECT s.*, a.hostname, a.display_name
            FROM endpoint_software s
            LEFT JOIN endpoint_agents a ON a.agent_id = s.agent_id
            WHERE {where}
            ORDER BY s.last_seen_at DESC, s.name ASC
            LIMIT %s OFFSET %s
            """,
            (*params, limit, offset),
        )
        rows = cursor.fetchall() or []
        cursor.close()
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def list_endpoint_vulnerabilities(
    org_name: str,
    agent_id: str | None = None,
    search: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """List current endpoint vulnerability findings."""
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    clauses = ["v.present = TRUE"]
    params: list = []
    if agent_id:
        clauses.append("v.agent_id = %s")
        params.append(agent_id)
    if severity:
        clauses.append("LOWER(v.severity) = %s")
        params.append(severity.lower())
    if search:
        clauses.append("(v.cve LIKE %s OR v.summary LIKE %s OR s.name LIKE %s OR a.hostname LIKE %s)")
        needle = f"%{search}%"
        params.extend([needle, needle, needle, needle])
    where = " AND ".join(clauses)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM endpoint_vulnerabilities v
            LEFT JOIN endpoint_software s ON s.agent_id = v.agent_id AND s.software_key = v.software_key
            LEFT JOIN endpoint_agents a ON a.agent_id = v.agent_id
            WHERE {where}
            """,
            params,
        )
        total = (cursor.fetchone() or {}).get("total") or 0
        cursor.execute(
            f"""
            SELECT v.*, s.name AS software_name, s.version AS software_version,
                   s.ecosystem, a.hostname
            FROM endpoint_vulnerabilities v
            LEFT JOIN endpoint_software s ON s.agent_id = v.agent_id AND s.software_key = v.software_key
            LEFT JOIN endpoint_agents a ON a.agent_id = v.agent_id
            WHERE {where}
            ORDER BY
                     CASE
                         WHEN LOWER(v.severity) = 'critical' THEN 1
                         WHEN LOWER(v.severity) = 'high' THEN 2
                         WHEN LOWER(v.severity) = 'medium' THEN 3
                         WHEN LOWER(v.severity) = 'low' THEN 4
                         WHEN LOWER(v.severity) = 'info' THEN 5
                         ELSE 6
                     END,
                     v.last_seen_at DESC
            LIMIT %s OFFSET %s
            """,
            (*params, limit, offset),
        )
        rows = cursor.fetchall() or []
        cursor.close()
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def get_endpoint_vulnerability(org_name: str, finding_id: int) -> dict | None:
    """Return one endpoint vulnerability with package and agent context."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT v.*, s.name AS software_name, s.version AS software_version,
                   s.vendor AS software_vendor, s.ecosystem, s.package_type,
                   s.purl AS software_purl, s.cpe AS software_cpe,
                   a.hostname, a.display_name, a.os_name, a.os_version, a.os_arch,
                   a.ip_addresses, a.last_inventory_at
            FROM endpoint_vulnerabilities v
            LEFT JOIN endpoint_software s ON s.agent_id = v.agent_id AND s.software_key = v.software_key
            LEFT JOIN endpoint_agents a ON a.agent_id = v.agent_id
            WHERE v.id = %s
            """,
            (finding_id,),
        )
        row = cursor.fetchone()
        cursor.close()
    return row


def _utcnow() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _scanner_token() -> str:
    return f"dscan_{secrets.token_urlsafe(32)}"


def _normalize_capabilities(capabilities: list[str] | str | None) -> list[str]:
    if capabilities is None:
        return ["*"]
    if isinstance(capabilities, str):
        try:
            decoded = json.loads(capabilities)
            if isinstance(decoded, list):
                capabilities = decoded
            else:
                capabilities = [capabilities]
        except json.JSONDecodeError:
            capabilities = [item.strip() for item in capabilities.split(",")]
    normalized = sorted({str(item).strip().lower() for item in capabilities if str(item).strip()})
    return normalized or ["*"]


def _job_capability(scan_mode: str | None, scanner: str | None = None) -> str:
    value = str(scanner or scan_mode or "").strip().lower()
    return value or "unknown"


def _node_can_run_job(capabilities: list[str], scan_mode: str | None, scanner: str | None) -> bool:
    normalized = _normalize_capabilities(capabilities)
    if "*" in normalized or "all" in normalized:
        return True
    job_kind = _job_capability(scan_mode, scanner)
    return job_kind in normalized or f"mode:{job_kind}" in normalized or f"scanner:{job_kind}" in normalized


def create_scanner_node(
    name: str,
    capabilities: list[str] | None = None,
    max_parallel_jobs: int = 1,
) -> dict:
    """Create a scanner node attach token. The token is visible only once."""
    token = _scanner_token()
    token_prefix = token[:16]
    node_id = f"node_{secrets.token_hex(8)}"
    created_at = _utcnow()
    capability_list = _normalize_capabilities(capabilities)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            INSERT INTO scanner_nodes
                (node_id, name, token_prefix, token_hash, capabilities, max_parallel_jobs, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, 'registered', %s)
            """,
            (
                node_id,
                name.strip() or node_id,
                token_prefix,
                _hash_api_key(token),
                json.dumps(capability_list),
                max(1, min(int(max_parallel_jobs or 1), 32)),
                created_at,
            ),
        )
        connection.commit()
        cursor.close()
    return {
        "node_id": node_id,
        "name": name,
        "token": token,
        "token_prefix": token_prefix,
        "capabilities": capability_list,
        "max_parallel_jobs": max(1, min(int(max_parallel_jobs or 1), 32)),
        "created_at": created_at,
    }


def list_scanner_nodes() -> list[dict]:
    """List scanner nodes without exposing tokens."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT
                n.id,
                n.node_id,
                n.name,
                n.token_prefix,
                n.capabilities,
                n.max_parallel_jobs,
                n.status,
                n.last_seen_at,
                n.revoked_at,
                n.created_at,
                COUNT(j.id) AS running_jobs
            FROM scanner_nodes n
            LEFT JOIN scanner_jobs j
                ON j.locked_by_node_id = n.node_id
                AND j.status IN ('claimed', 'running', 'stopping')
            GROUP BY n.id
            ORDER BY n.created_at DESC
            """
        )
        rows = cursor.fetchall() or []
        cursor.close()
    for row in rows:
        row["capabilities"] = _normalize_capabilities(row.get("capabilities"))
    return rows


def list_available_scanner_nodes() -> list[dict]:
    """List non-revoked scanner nodes that can be selected for new jobs."""
    return [row for row in list_scanner_nodes() if not row.get("revoked_at")]


def get_scanner_node_record(node_id: str) -> dict | None:
    """Return one scanner node record without exposing its token hash."""
    if not node_id:
        return None
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT id, node_id, name, token_prefix, capabilities, max_parallel_jobs,
                   status, last_seen_at, revoked_at, created_at
            FROM scanner_nodes
            WHERE node_id = %s
            """,
            (node_id,),
        )
        row = cursor.fetchone()
        cursor.close()
    if row:
        row["capabilities"] = _normalize_capabilities(row.get("capabilities"))
    return row


def revoke_scanner_node(node_id: str) -> bool:
    """Revoke a scanner node token."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            UPDATE scanner_nodes
            SET revoked_at = %s, status = 'revoked'
            WHERE node_id = %s AND revoked_at IS NULL
            """,
            (_utcnow(), node_id),
        )
        changed = cursor.rowcount > 0
        if changed:
            cursor.execute(
                """
                UPDATE scanner_jobs
                SET preferred_node_id = NULL,
                    updated_at = %s,
                    error_message = 'Preferred scanner was revoked; job returned to auto assignment'
                WHERE preferred_node_id = %s
                  AND status = 'queued'
                """,
                (_utcnow(), node_id),
            )
        connection.commit()
        cursor.close()
    return bool(changed)


def delete_revoked_scanner_node(node_id: str) -> bool:
    """Remove a revoked scanner node from the orchestrator registry."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            DELETE FROM scanner_nodes
            WHERE node_id = %s
              AND revoked_at IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM scanner_jobs
                  WHERE locked_by_node_id = scanner_nodes.node_id
                    AND status IN ('claimed', 'running', 'stopping')
              )
            """,
            (node_id,),
        )
        changed = cursor.rowcount > 0
        connection.commit()
        cursor.close()
    return bool(changed)


def authenticate_scanner_node(token: str) -> dict | None:
    """Return scanner node context for a valid worker token."""
    if not token:
        return None
    digest = _hash_api_key(token)
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        connection.commit()
        cursor.execute(
            """
            SELECT id, node_id, name, capabilities, max_parallel_jobs, status, token_hash
            FROM scanner_nodes
            WHERE (token_hash = %s OR token_hash = SHA2(%s, 256))
              AND revoked_at IS NULL
            """,
            (digest, token),
        )
        row = cursor.fetchone()
        if row and row.get("token_hash") != digest:
            cursor.execute(
                "UPDATE scanner_nodes SET token_hash = %s WHERE id = %s",
                (digest, row["id"]),
            )
            connection.commit()
        cursor.close()
    if row:
        row.pop("token_hash", None)
        row["capabilities"] = _normalize_capabilities(row.get("capabilities"))
    return row


def heartbeat_scanner_node(
    node_id: str,
    capabilities: list[str] | None = None,
    status: str = "online",
) -> None:
    """Update worker liveness and optional capabilities."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        if capabilities is None:
            cursor.execute(
                "UPDATE scanner_nodes SET status = %s, last_seen_at = %s WHERE node_id = %s AND revoked_at IS NULL",
                (status, _utcnow(), node_id),
            )
        else:
            cursor.execute(
                """
                UPDATE scanner_nodes
                SET status = %s, last_seen_at = %s, capabilities = %s
                WHERE node_id = %s AND revoked_at IS NULL
                """,
                (status, _utcnow(), json.dumps(_normalize_capabilities(capabilities)), node_id),
            )
        connection.commit()
        cursor.close()


def enqueue_scanner_job(
    org_db_name: str,
    scan_id: int,
    scan_name: str,
    scan_mode: str | None,
    targets: str,
    payload: dict,
    scanner: str | None = None,
    schedule_id: int | None = None,
    preferred_node_id: str | None = None,
    priority: int = 100,
) -> int:
    """Insert a scan into the central worker queue."""
    now = _utcnow()
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            INSERT INTO scanner_jobs
                (org_db_name, scan_id, scan_name, scan_mode, scanner, preferred_node_id, targets, payload_json,
                 status, priority, schedule_id, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'queued', %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                scan_name = VALUES(scan_name),
                scan_mode = VALUES(scan_mode),
                scanner = VALUES(scanner),
                preferred_node_id = VALUES(preferred_node_id),
                targets = VALUES(targets),
                payload_json = VALUES(payload_json),
                status = 'queued',
                priority = VALUES(priority),
                locked_by_node_id = NULL,
                locked_at = NULL,
                lease_until = NULL,
                error_message = NULL,
                updated_at = VALUES(updated_at)
            """,
            (
                org_db_name,
                scan_id,
                scan_name,
                str(scan_mode) if scan_mode is not None else None,
                scanner,
                preferred_node_id or None,
                targets,
                json.dumps(payload),
                int(priority),
                schedule_id,
                now,
                now,
            ),
        )
        job_id = cursor.lastrowid
        if not job_id:
            cursor.execute(
                "SELECT id FROM scanner_jobs WHERE org_db_name = %s AND scan_id = %s",
                (org_db_name, scan_id),
            )
            row = cursor.fetchone()
            job_id = row[0] if row else 0
        connection.commit()
        cursor.close()
    return int(job_id)


def _decode_scanner_job(row: dict | None) -> dict | None:
    if not row:
        return None
    try:
        row["payload"] = json.loads(row.get("payload_json") or "{}")
    except json.JSONDecodeError:
        row["payload"] = {}
    row.pop("payload_json", None)
    return row


def claim_next_scanner_job(
    node_id: str,
    capabilities: list[str] | None = None,
    lease_seconds: int = 900,
) -> dict | None:
    """Atomically claim the next compatible queued job for one worker."""
    now_dt = datetime.utcnow()
    now = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    lease_until = (now_dt + timedelta(seconds=max(60, lease_seconds))).strftime("%Y-%m-%d %H:%M:%S")
    capability_list = _normalize_capabilities(capabilities)

    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            "SELECT max_parallel_jobs FROM scanner_nodes WHERE node_id = %s AND revoked_at IS NULL",
            (node_id,),
        )
        node_row = cursor.fetchone()
        if not node_row:
            connection.commit()
            cursor.close()
            return None
        cursor.execute(
            """
            UPDATE scanner_jobs
            SET status = 'queued',
                locked_by_node_id = NULL,
                locked_at = NULL,
                lease_until = NULL,
                updated_at = %s,
                error_message = 'Worker lease expired; job requeued'
            WHERE status IN ('claimed', 'running')
              AND lease_until IS NOT NULL
              AND lease_until < %s
            """,
            (now, now),
        )
        cursor.execute(
            """
            SELECT COUNT(*) AS running
            FROM scanner_jobs
            WHERE locked_by_node_id = %s
              AND status IN ('claimed', 'running', 'stopping')
            """,
            (node_id,),
        )
        running_row = cursor.fetchone() or {}
        if int(running_row.get("running") or 0) >= int(node_row.get("max_parallel_jobs") or 1):
            connection.commit()
            cursor.close()
            return None
        cursor.execute(
            """
            SELECT *
            FROM scanner_jobs
            WHERE status = 'queued'
              AND (preferred_node_id IS NULL OR preferred_node_id = %s)
            ORDER BY priority DESC, id ASC
            LIMIT 50
            FOR UPDATE
            """
            ,
            (node_id,),
        )
        candidates = cursor.fetchall() or []
        selected = None
        for row in candidates:
            if row.get("preferred_node_id") and row.get("preferred_node_id") != node_id:
                continue
            if _node_can_run_job(capability_list, row.get("scan_mode"), row.get("scanner")):
                selected = row
                break

        if not selected:
            connection.commit()
            cursor.close()
            return None

        cursor.execute(
            """
            UPDATE scanner_jobs
            SET status = 'running',
                locked_by_node_id = %s,
                locked_at = %s,
                lease_until = %s,
                started_at = COALESCE(started_at, %s),
                attempts = attempts + 1,
                updated_at = %s,
                error_message = NULL
            WHERE id = %s
            """,
            (node_id, now, lease_until, now, now, selected["id"]),
        )
        connection.commit()
        cursor.close()

    update_scan_status(selected["org_db_name"], selected["scan_id"], "running")
    claim_label = f"Claimed by scanner node {node_id}"
    if selected.get("preferred_node_id"):
        claim_label = f"Claimed by selected scanner appliance {node_id}"
    insert_scan_log(selected["org_db_name"], selected["scan_id"], claim_label, "info")
    heartbeat_scanner_node(node_id, capability_list, status="busy")
    selected["status"] = "running"
    selected["locked_by_node_id"] = node_id
    return _decode_scanner_job(selected)


def requeue_expired_scanner_jobs() -> int:
    """Requeue jobs whose worker lease expired and mirror scan status."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            SELECT id, org_db_name, scan_id, locked_by_node_id
            FROM scanner_jobs
            WHERE status IN ('claimed', 'running')
              AND lease_until IS NOT NULL
              AND lease_until < %s
            """,
            (now,),
        )
        jobs = cursor.fetchall() or []
        if not jobs:
            cursor.close()
            return 0
        job_ids = [int(job["id"]) for job in jobs]
        placeholders = ", ".join(["%s"] * len(job_ids))
        cursor.execute(
            f"""
            UPDATE scanner_jobs
            SET status = 'queued',
                locked_by_node_id = NULL,
                locked_at = NULL,
                lease_until = NULL,
                updated_at = %s,
                error_message = 'Worker lease expired; job requeued'
            WHERE id IN ({placeholders})
            """,
            (now, *job_ids),
        )
        connection.commit()
        cursor.close()

    for job in jobs:
        update_scan_status(job["org_db_name"], job["scan_id"], "queued", error_message="Worker lease expired; job requeued")
        insert_scan_log(
            job["org_db_name"],
            job["scan_id"],
            f"Worker lease expired for scanner node {job.get('locked_by_node_id')}; job requeued",
            "warning",
        )
    return len(jobs)


def extend_scanner_job_lease(job_id: int, node_id: str, lease_seconds: int = 900) -> dict | None:
    """Extend a running job lease and return stop state."""
    lease_until = (datetime.utcnow() + timedelta(seconds=max(60, lease_seconds))).strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            UPDATE scanner_jobs
            SET lease_until = %s, updated_at = %s
            WHERE id = %s AND locked_by_node_id = %s AND status IN ('running', 'stopping')
            """,
            (lease_until, _utcnow(), job_id, node_id),
        )
        cursor.execute(
            "SELECT id, org_db_name, scan_id, status FROM scanner_jobs WHERE id = %s AND locked_by_node_id = %s",
            (job_id, node_id),
        )
        row = cursor.fetchone()
        connection.commit()
        cursor.close()
    return row


def request_scanner_job_stop(org_db_name: str, scan_id: int) -> None:
    """Mark a queued/running scanner job as stopping."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            UPDATE scanner_jobs
            SET status = 'stopping', updated_at = %s, error_message = 'Stop requested by user'
            WHERE org_db_name = %s AND scan_id = %s AND status IN ('queued', 'running', 'claimed')
            """,
            (_utcnow(), org_db_name, scan_id),
        )
        connection.commit()
        cursor.close()


def cancel_queued_scanner_job(org_db_name: str, scan_id: int, reason: str = "Scan stopped before worker claim") -> bool:
    """Cancel a queued scanner job that has not been claimed yet."""
    now = _utcnow()
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _ensure_organizations_registry(cursor)
        cursor.execute(
            """
            UPDATE scanner_jobs
            SET status = 'stopped',
                finished_at = %s,
                error_message = %s,
                updated_at = %s
            WHERE org_db_name = %s
              AND scan_id = %s
              AND locked_by_node_id IS NULL
              AND status IN ('queued', 'stopping')
            """,
            (now, reason, now, org_db_name, scan_id),
        )
        changed = cursor.rowcount > 0
        connection.commit()
        cursor.close()
    if changed:
        update_scan_status(org_db_name, scan_id, "stopped", error_message=reason)
    return bool(changed)


def complete_scanner_job(
    job_id: int,
    node_id: str,
    status: str,
    error_message: str | None = None,
) -> dict | None:
    """Complete a worker job and mirror status to the tenant scan record."""
    final_status = status if status in {"completed", "failed", "stopped"} else "failed"
    now = _utcnow()
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            "SELECT * FROM scanner_jobs WHERE id = %s AND locked_by_node_id = %s",
            (job_id, node_id),
        )
        job = cursor.fetchone()
        if not job:
            cursor.close()
            return None
        cursor.execute(
            """
            UPDATE scanner_jobs
            SET status = %s,
                finished_at = %s,
                lease_until = NULL,
                error_message = %s,
                updated_at = %s
            WHERE id = %s
            """,
            (final_status, now, error_message, now, job_id),
        )
        connection.commit()
        cursor.close()

    update_scan_status(job["org_db_name"], job["scan_id"], final_status, error_message=error_message)
    heartbeat_scanner_node(node_id, status="online")
    return _decode_scanner_job(job)


def get_scanner_job_for_scan(org_db_name: str, scan_id: int) -> dict | None:
    """Return queue metadata for a scan."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _ensure_organizations_registry(cursor)
        cursor.execute(
            "SELECT * FROM scanner_jobs WHERE org_db_name = %s AND scan_id = %s",
            (org_db_name, scan_id),
        )
        row = cursor.fetchone()
        cursor.close()
    return _decode_scanner_job(row)


def get_oversight_summary() -> dict:
    """Aggregate high-level dashboard metrics across all tenant databases."""
    organizations = list_organizations()
    tenant_summaries = []
    totals = {
        "organizations": len(organizations),
        "vulnerabilities": 0,
        "running_scans": 0,
        "critical": 0,
        "high": 0,
        "exploitable": 0,
    }
    for organization in organizations:
        org_db = organization["org_db_name"]
        stats = get_vulnerability_stats(org_db)
        scoring = get_scoring_overview(org_db)
        summary = scoring.get("summary", {})
        severity = stats.get("severity_breakdown", {})
        total_vulns = int(stats.get("total_vulnerabilities") or 0)
        running = int(stats.get("running_scans") or 0)
        tenant_summaries.append(
            {
                "organization": organization["org_name"],
                "org_db": org_db,
                "role": organization.get("role"),
                "total_vulnerabilities": total_vulns,
                "running_scans": running,
                "critical": int(severity.get("critical") or 0),
                "high": int(severity.get("high") or 0),
                "average_priority": summary.get("average_priority") or 0,
                "max_priority": summary.get("max_priority") or 0,
                "exploitable_count": summary.get("exploitable_count") or 0,
            }
        )
        totals["vulnerabilities"] += total_vulns
        totals["running_scans"] += running
        totals["critical"] += int(severity.get("critical") or 0)
        totals["high"] += int(severity.get("high") or 0)
        totals["exploitable"] += int(summary.get("exploitable_count") or 0)

    return {"totals": totals, "tenants": tenant_summaries}


def get_m365_graph_settings(org_name: str, include_secret: bool = False) -> dict:
    """Return Microsoft Graph connector settings for an organization."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute("SELECT * FROM m365_graph_settings WHERE id = 1")
        row = cursor.fetchone()
        if not row:
            cursor.execute(
                """
                INSERT INTO m365_graph_settings (id, enabled, updated_at)
                VALUES (1, FALSE, %s)
                """,
                (now,),
            )
            connection.commit()
            cursor.execute("SELECT * FROM m365_graph_settings WHERE id = 1")
            row = cursor.fetchone()
        cursor.close()

    settings = row or {}
    if not include_secret and settings.get("client_secret"):
        settings["client_secret"] = "********"
    return settings


def update_m365_graph_settings(
    org_name: str,
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
    enabled: bool,
) -> dict:
    """Upsert Microsoft Graph connector settings."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    existing = get_m365_graph_settings(org_name, include_secret=True)
    secret_to_store = existing.get("client_secret") if client_secret == "********" else client_secret
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            INSERT INTO m365_graph_settings (
                id, tenant_id, client_id, client_secret, enabled, updated_at
            ) VALUES (1, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                tenant_id = VALUES(tenant_id),
                client_id = VALUES(client_id),
                client_secret = VALUES(client_secret),
                enabled = VALUES(enabled),
                updated_at = VALUES(updated_at)
            """,
            (tenant_id, client_id, secret_to_store, enabled, now),
        )
        connection.commit()
        cursor.close()
    return get_m365_graph_settings(org_name)


def upsert_m365_secure_score_data(org_name: str, summary: dict, items: list[dict]) -> int:
    """Persist Microsoft 365 Secure Score summary and control profiles."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            INSERT INTO m365_secure_score_summary (
                id, current_score, max_score, active_user_count, licensed_user_count,
                created_date_time, raw_json, last_synced_at
            ) VALUES (1, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                current_score = VALUES(current_score),
                max_score = VALUES(max_score),
                active_user_count = VALUES(active_user_count),
                licensed_user_count = VALUES(licensed_user_count),
                created_date_time = VALUES(created_date_time),
                raw_json = VALUES(raw_json),
                last_synced_at = VALUES(last_synced_at)
            """,
            (
                summary.get("currentScore"),
                summary.get("maxScore"),
                summary.get("activeUserCount"),
                summary.get("licensedUserCount"),
                summary.get("createdDateTime"),
                json.dumps(summary),
                now,
            ),
        )

        records = []
        for item in items:
            control_name = item.get("controlName") or item.get("id")
            if not control_name:
                continue
            records.append(
                (
                    control_name,
                    item.get("title"),
                    item.get("category"),
                    item.get("actionType"),
                    item.get("implementationStatus"),
                    item.get("service"),
                    item.get("userImpact"),
                    json.dumps(item.get("threats")) if item.get("threats") is not None else None,
                    item.get("currentScore"),
                    item.get("maxScore"),
                    item.get("scoreImpact"),
                    item.get("rank"),
                    json.dumps(item),
                    now,
                )
            )
        if records:
            cursor.executemany(
                """
                INSERT INTO m365_secure_score_items (
                    control_name, title, category, action_type, implementation_status,
                    service, user_impact, threats, current_score, max_score,
                    score_impact, rank, raw_json, last_synced_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    title = VALUES(title),
                    category = VALUES(category),
                    action_type = VALUES(action_type),
                    implementation_status = VALUES(implementation_status),
                    service = VALUES(service),
                    user_impact = VALUES(user_impact),
                    threats = VALUES(threats),
                    current_score = VALUES(current_score),
                    max_score = VALUES(max_score),
                    score_impact = VALUES(score_impact),
                    rank = VALUES(rank),
                    raw_json = VALUES(raw_json),
                    last_synced_at = VALUES(last_synced_at)
                """,
                records,
            )
        connection.commit()
        cursor.close()
        return len(records)


def get_m365_secure_score(org_name: str) -> dict:
    """Return stored Microsoft 365 Secure Score summary and controls."""
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute("SELECT * FROM m365_secure_score_summary WHERE id = 1")
        summary = cursor.fetchone() or {}
        cursor.execute(
            """
            SELECT id, control_name, title, category, action_type, implementation_status,
                   service, user_impact, threats, current_score, max_score, score_impact,
                   rank, last_synced_at
            FROM m365_secure_score_items
            ORDER BY COALESCE(max_score, 0) DESC, control_name ASC
            LIMIT 500
            """
        )
        items = cursor.fetchall() or []
        cursor.close()
        return {"summary": summary, "items": items}
