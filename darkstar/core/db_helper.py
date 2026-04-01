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
from html import escape
import pandas as pd
from datetime import datetime

from .models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


ORG_IDENTIFIER_RE = re.compile(r"^[a-z0-9_]{3,64}$")


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
        created_at DATETIME NOT NULL,
        started_at DATETIME DEFAULT NULL,
        finished_at DATETIME DEFAULT NULL
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


def ensure_organization(org_name: str, password: str) -> tuple[str, bool]:
    """
    Ensure organization record and per-org database exist.

    Returns:
        tuple[str, bool]: (normalized_org_db_name, created_now)
    """
    org_db = normalize_org_name(org_name)
    created_now = False
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS organizations (
                id INT AUTO_INCREMENT PRIMARY KEY,
                org_name VARCHAR(255) NOT NULL UNIQUE,
                org_db_name VARCHAR(64) NOT NULL UNIQUE,
                password_salt VARCHAR(64) NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                created_at DATETIME NOT NULL
            )
            """
        )

        cursor.execute(
            "SELECT org_db_name, password_salt, password_hash FROM organizations WHERE org_name = %s",
            (org_name,),
        )
        row = cursor.fetchone()

        if row:
            if not _verify_password(password, row["password_salt"], row["password_hash"]):
                raise ValueError("Invalid organization credentials")
            org_db = row["org_db_name"]
        else:
            salt, digest = _hash_password(password)
            cursor.execute(
                "INSERT INTO organizations (org_name, org_db_name, password_salt, password_hash, created_at) VALUES (%s, %s, %s, %s, %s)",
                (org_name, org_db, salt, digest, created_at),
            )
            created_now = True

        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{org_db}`")
        cursor.execute(f"USE `{org_db}`")
        for statement in ORG_SCHEMA_STATEMENTS:
            cursor.execute(statement)

        connection.commit()
        cursor.close()

    return org_db, created_now


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
        else:
            cursor.execute(
                "UPDATE scans SET status = %s, error_message = %s WHERE id = %s",
                (status, error_message, scan_id),
            )

        connection.commit()
        cursor.close()


def get_latest_vulnerabilities(org_name: str, limit: int = 200) -> list[dict]:
    """Return latest vulnerabilities from organization database."""
    limit = max(1, min(limit, 1000))
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, cve, title, affected_item, tool, confidence, severity, host, cvss, epss, summary, cwe, capec, solution, impact, age, kev
            FROM vulnerability
            ORDER BY id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


def get_scan_history(org_name: str, limit: int = 50) -> list[dict]:
    """Return latest scan jobs for an organization."""
    limit = max(1, min(limit, 500))
    with DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _use_org_database(cursor, org_name)
        cursor.execute(
            """
            SELECT id, scan_name, scan_mode, targets, status, error_message, created_at, started_at, finished_at
            FROM scans
            ORDER BY id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


def get_vulnerability_stats(org_name: str) -> dict:
    """Return dashboard aggregate stats for vulnerabilities and scans."""
    total_vulns = 0
    running_scans = 0
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
                "SELECT COUNT(*) AS running FROM scans WHERE status IN ('queued', 'running')"
            )
            row = cursor.fetchone()
            running_scans = row["running"] if row else 0

            cursor.close()
    except Exception as e:
        logger.warning(f"Error getting stats for org {org_name}: {e}")
        # Return empty stats on error - will be retried on next poll
        pass
    
    return {
        "total_vulnerabilities": total_vulns,
        "running_scans": running_scans,
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
            
            # Get total count
            cursor.execute(f"SELECT COUNT(*) AS total FROM vulnerability WHERE {where_clause}", params)
            total_row = cursor.fetchone()
            total = total_row["total"] if total_row else 0
            
            # Get paginated results
            cursor.execute(
                f"""
                SELECT id, cve, title, affected_item, tool, confidence, severity, host, cvss, epss, summary, cwe, capec, solution, impact, age, kev
                FROM vulnerability
                WHERE {where_clause}
                ORDER BY id DESC
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
