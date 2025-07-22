"""
Database helper functions for the Darkstar security framework.

This module provides centralized database operations for storing
vulnerability data and scan results.
"""

import logging
from typing import Dict, Any, Optional
import mysql.connector
import os
import json
import re
from html import escape
import pandas as pd
from datetime import datetime

from core.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

class DatabaseConnectionManager:
    """
    Context manager for handling database connections.
    
    This class ensures that the database connection is properly opened and closed.
    """
    
    def __init__(self):
        self.db_config = {
            'user': os.environ.get('DB_USER'),
            'password': os.environ.get('DB_PASSWORD'),
            'host': os.environ.get('DB_HOST'),
            'database': os.environ.get('DB_NAME'),
        }

        if not all(self.db_config.values()):
            logger.error("Database configuration is incomplete. Please check environment variables.")
            raise ValueError("Incomplete database configuration.")
        
        self.connection = None

    def __enter__(self):
        try:
            self.connection = mysql.connector.connect(**self.db_config)
            if self.connection.is_connected():
                logger.debug(f"Connected to the database")
                return self.connection
            else:
                logger.error("Failed to connect to the database.")
                return None
        except mysql.connector.Error as e:
            logger.error(f"Error connecting to MySQL: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error while connecting to database: {e}")
            return None

    def __exit__(self, exc_type, exc_value, traceback):
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logger.debug("Database connection closed.")
        if exc_type:
            logger.error(f"An error occurred: {exc_value}")
            return True  # Suppress exception propagation


def sanitize_string(value):
    """
    Remove ANSI escape codes, trim string and escape HTML characters.

    Args:
        value: Value to sanitize, expected to be a string
        
    Returns:
        Sanitized string or original value if not a string
    """
    
    if isinstance(value, str):
        return escape(re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', value).strip())
    return value

def flatten_list(value):
    """
    Convert a list to a comma-separated string.
    
    Args:
        value: Value to flatten, expected to be a list
        
    Returns:
        str: Comma-separated string or original value if not a list
    """
    print(f"Value: {value}")
    if isinstance(value, list):
        new = ', '.join(map(str, value))
        print(f"New: {new}, type: {type(new)}")
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
        title,                          # Field 1 (Sanitized)
        sanitize_string(vuln.affected_item),  # Field 2
        sanitize_string(vuln.tool),          # Field 3
        vuln.confidence,                     # Field 4
        sanitize_string(vuln.severity),      # Field 5
        sanitize_string(vuln.host),          # Field 6
        vuln.cve.cvss,                       # Field 7
        vuln.cve.epss,                       # Field 8 (Flattened)
        sanitize_string(vuln.cve.summary),   # Field 9
        sanitize_string(vuln.cve.cwe),       # Field 10
        references,                          # Field 11 (Flattened)
        sanitize_string(vuln.cve.capec),     # Field 12
        sanitize_string(vuln.cve.solution),  # Field 13
        impact,                              # Field 14 (JSON)
        access,                              # Field 15 (JSON)
        vuln.cve.age,                        # Field 16
        pocs,                                # Field 17 (Flattened)
        vuln.cve.kev                         # Field 18
    )
    
    # Debugging log: Ensure no lists remain
    print("CVE Data Types and Values:")
    for i, field in enumerate(cve_data):
        print(f"Field {i}: Type = {type(field)}, Value = {field}")
    
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
        None   # Non-CVE entries are not part of KEV
    )
    
    # Debugging log: Ensure no lists remain
    print("Non-CVE Data Types and Values:")
    for i, field in enumerate(non_cve_data):
        print(f"Field {i}: Type = {type(field)}, Value = {field}")

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
        cursor.execute(f"USE {org_name}")
        # Define the INSERT query
        insert_query = """
        INSERT INTO vulnerability (
            cve, title, affected_item, tool, confidence, severity, host,
            cvss, epss, summary, cwe, `references`, capec, solution, impact,
            access, age, pocs, kev
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        # Check if the vulnerability has a CVE
        if hasattr(vuln, 'cve') and vuln.cve is not None:
            # Prepare CVE-based data
            cve_data = prepare_cve_data(vuln)
            cursor.execute(insert_query, cve_data)
        else:
            # Prepare non-CVE-based data
            non_cve_data = prepare_non_cve_data(vuln)
            cursor.execute(insert_query, non_cve_data)

        # Commit the transaction
        connection.commit()
        cursor.close()
        return True
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
        cursor.execute(f"USE {org_name}") #? Select the database for the organisation
        
        total_rows = len(dataframe)
        logger.info(f"Processing {total_rows} records for insertion")
        
        #? Iterate over DataFrame rows and insert into MySQL table
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
                source_module = json.dumps(json.loads(row["Source Module"].replace("'", '"')))
            except (json.JSONDecodeError, AttributeError):
                source_module = row["Source Module"]

            try:
                scope_distance = json.dumps(json.loads(row["Scope Distance"].replace("'", '"')))
            except (json.JSONDecodeError, AttributeError):
                scope_distance = row["Scope Distance"]

            try:
                event_tags = json.dumps(json.loads(row["Event Tags"].replace("'", '"')))
            except (json.JSONDecodeError, AttributeError):
                event_tags = row["Event Tags"]

            # Handle the edge case with single quotes in nested JSON
            if isinstance(event_data, str) and event_data.startswith("{") and event_data.endswith("}"):
                event_data = event_data.replace("'", '"')

            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            insert_query = """
            INSERT INTO asmevents (event_type, event_data, ip_address, source_module, scope_distance, event_tags, time)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (event_type, event_data, ip_address, source_module, scope_distance, event_tags, current_time))

        #? Commit the transaction
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
        cursor.execute(f"USE {org_name}")
        
        for i, email in enumerate(emails, 1):
            if i % 10 == 0:
                logger.info(f"Progress: {i}/{len(emails)} emails processed")
            email = email.strip()
            sql_query = "INSERT INTO email_input (email) VALUES (%s)"
            cursor.execute(sql_query, (email,))
            
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
        cursor.execute(f"USE {org_name}")
        for email_breach in email_breaches:
            sql_query = "INSERT INTO email_leaks (email, breach_name, breach_date, domain) VALUES (%s, %s, %s, %s)"
            val = (email_breach[0], email_breach[1], email_breach[2], email_breach[3])
            cursor.execute(sql_query, val)
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
        cursor.execute(f"USE {org_name}")
        for password in passwords:
            sql_query = "INSERT INTO password_leaks (email, password) VALUES (%s, %s)"
            val = (password[0], password[1])
            cursor.execute(sql_query, val)
            connection.commit()
        cursor.close()
        return True
    return False
