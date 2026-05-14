-- Manual migration for DarkStar organization authentication hardening.
-- Run this against the global database configured by DB_NAME.
-- Do not run automatically from the agent.

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(64) DEFAULT NULL;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_issuer VARCHAR(512) DEFAULT NULL;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_client_id VARCHAR(255) DEFAULT NULL;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_client_secret TEXT DEFAULT NULL;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_allowed_domain VARCHAR(255) DEFAULT NULL;

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
