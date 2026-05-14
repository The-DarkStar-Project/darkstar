-- Manual migration for user-based authentication, organization memberships,
-- per-membership roles and MFA policy.
-- Do not run automatically; execute manually against the global DarkStar DB.

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS sso_required BOOLEAN NOT NULL DEFAULT FALSE;

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
    CONSTRAINT fk_membership_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS platform_auth_settings (
    id INT PRIMARY KEY DEFAULT 1,
    mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at DATETIME NOT NULL
);

INSERT IGNORE INTO platform_auth_settings (id, mfa_required, updated_at)
VALUES (1, FALSE, UTC_TIMESTAMP());

-- Existing organization/password logins are preserved as a legacy fallback.
-- After deploying this migration, create the first user by logging in with
-- email + password. The first user is bootstrapped as platform_admin.
