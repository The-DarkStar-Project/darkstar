"""
BBOT (Black Box Operations Tool) scanner integration for Darkstar.

This module provides a wrapper for the bbot scanner, allowing for passive and
aggressive reconnaissance, and processing the results for database insertion.
"""

import hashlib
import logging
import os
import subprocess

import pandas as pd

from core.db_helper import insert_vulnerability_to_database, insert_bbot_to_db
from core.models.vulnerability import Vulnerability
from tools.hibp.HIBPwned import HIBPwned

logger = logging.getLogger(__name__)


class BBotScanner:
    """
    Wrapper for the bbot (Black Box Operations Tool) scanner.

    Provides methods for passive and aggressive reconnaissance using bbot,
    and processes the results to insert findings into the database.

    Attributes:
        target (str): The target to scan (domain, IP, CIDR, etc.)
        org_name (str): Organization name for database storage
        folder (str): Output folder for bbot results
        foldername (str): Unique folder name for the current scan
    """

    def __init__(self, target: str, org_name: str):
        self.target = target
        self.folder = "/app/bbot_output"
        self.foldername = hashlib.md5(os.urandom(10)).hexdigest()
        self.org_name = org_name

        # Create a directory for bbot output if not exists
        if not os.path.exists(self.folder):
            os.makedirs(self.folder, exist_ok=True)

    def vulns_to_db(self, df: pd.DataFrame) -> None:
        """
        Process vulnerability findings from bbot output and insert into database.

        Args:
            df: DataFrame containing bbot scan results
        """
        vuln_count = sum(
            1
            for _, row in df.iterrows()
            if row["Event type"] == "VULNERABILITY" or row["Event type"] == "FINDING"
        )

        if vuln_count == 0:
            logger.info("No vulnerabilities or findings detected in bbot scan")
            return

        logger.info(f"Processing {vuln_count} vulnerabilities found by bbot")

        for _, row in df.iterrows():
            if row["Event type"] == "VULNERABILITY" or row["Event type"] == "FINDING":
                # Get the object and store into the database as a vulnerability
                try:
                    item = eval(row["Event data"])
                    if isinstance(item, str):
                        item = eval(item)
                    severity = (
                        "info"
                        if row["Event type"] == "FINDING"
                        else item.get("severity", None)
                    )
                    finding_object = Vulnerability(
                        title="asm finding",
                        affected_item=item.get("url", None),
                        tool="bbot",
                        confidence=90,
                        severity=severity,
                        host=item.get("host", None),
                        poc=item.get("url", None),
                        summary=item.get("description", None),
                    )
                    logger.info(
                        f"Adding to database: {finding_object.title} on {finding_object.host}"
                    )
                    insert_vulnerability_to_database(
                        vulnerability=finding_object, org_name=self.org_name
                    )
                except Exception as e:
                    logger.error(f"Error processing vulnerability: {e}")

    def hibpwned(self) -> None:
        """
        Process discovered emails through Have I Been Pwned API.

        Checks if any emails found during the scan have been involved
        in known data breaches.
        """
        email_file = f"{self.folder}/{self.foldername}/emails.txt"
        logger.info(f"Checking for HaveIBeenPwned data from {email_file}")

        if not os.path.exists(email_file):
            logger.info(f"No emails file found at {email_file}")
            return

        with open(email_file, "r") as file:
            email_count = sum(1 for _ in file)

        if email_count > 0:
            logger.info(f"Found {email_count} emails to check with HaveIBeenPwned")
            hibp = HIBPwned(email_file, self.org_name)
            hibp.run()
        else:
            logger.warning("Email file exists but contains no emails")

    def prep_data(self) -> pd.DataFrame:
        """
        Prepare bbot scan data for database insertion.

        Reads the bbot output CSV file and processes it into a suitable format
        for database insertion.

        Returns:
            DataFrame: The processed scan results
        """
        output_file = f"{self.folder}/{self.foldername}/output.csv"
        if os.path.exists(output_file):
            logger.info(f"Reading bbot output from {output_file}")

            # Read the CSV data
            df = pd.read_csv(output_file)

            logger.info(f"Loaded {len(df)} records from bbot output")

            # Replace NaN with None
            df = df.where(pd.notnull(df), None)

            self.hibpwned()

            # Check if bbot found any vulns write to vulnerability class and insert to db
            self.vulns_to_db(df)

            return df
        else:
            logger.error(
                f"No output file found at {output_file}, something went wrong with bbot scan"
            )
            return pd.DataFrame()

    def attack_surface(self) -> None:
        """
        Run bbot with passive scanning flags.

        Executes a non-intrusive scan using bbot's passive modules,
        focusing on subdomain enumeration and data collection without
        active probing.
        """
        logger.info(f"Starting Passive bbot Scan on {self.target}")

        command = [
            "/root/.local/bin/bbot",
            "-t",
            self.target,
            "-f",
            "safe,passive,subdomain-enum,cloud-enum,email-enum,social-enum,code-enum,web-basic,affiliates",
            "-o",
            self.folder,
            "-n",
            self.foldername,
            "-y",
        ]
        logger.debug(f"Command: {' '.join(command)}")

        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        logger.info("bbot scan in progress...")
        process.wait()
        logger.info("Passive scan completed!")

        # Place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        # Store data from csv into the database
        logger.info("Processing scan results and storing in database...")
        insert_bbot_to_db(self.prep_data(), org_name=self.org_name)
        logger.info("Passive scan data successfully processed")

    def passive(self) -> None:
        """
        Run bbot with passive scanning flags.

        Executes a non-intrusive scan using bbot's passive modules,
        focusing on subdomain enumeration and data collection without
        active probing.
        """
        logger.info(f"Starting Passive bbot Scan on {self.target}")

        command = [
            "/root/.local/bin/bbot",
            "-t",
            self.target,
            "-f",
            "safe,passive,cloud-enum,email-enum,social-enum,code-enum",
            "-o",
            self.folder,
            "-n",
            self.foldername,
            "-y",
            "--strict-scope",
        ]
        logger.debug(f"Command: {' '.join(command)}")

        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        logger.info("bbot scan in progress...")
        process.wait()
        logger.info("Passive scan completed!")

        # Place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        # Store data from csv into the database
        logger.info("Processing scan results and storing in database...")
        insert_bbot_to_db(self.prep_data(), org_name=self.org_name)
        logger.info("Passive scan data successfully processed")

    def normal(self) -> None:
        """
        Run bbot with normal scanning flags.

        Executes a non-intrusive scan using bbot's normal modules,
        focusing on subdomain enumeration and data collection without
        active probing.
        """
        logger.info(f"Starting normal bbot Scan on {self.target}")

        command = [
            "/root/.local/bin/bbot",
            "-t",
            self.target,
            "-f",
            "cloud-enum,email-enum,social-enum,code-enum,web-basic",
            "-o",
            self.folder,
            "-n",
            self.foldername,
            "-y",
            "--strict-scope",
        ]
        logger.debug(f"Command: {' '.join(command)}")

        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        logger.info("bbot scan in progress...")
        process.wait()
        logger.info("normal scan completed!")

        # Place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        # Store data from csv into the database
        logger.info("Processing scan results and storing in database...")
        insert_bbot_to_db(self.prep_data(), org_name=self.org_name)
        logger.info("normal scan data successfully processed")

    def aggressive(self) -> None:
        """
        Run bbot with aggressive scanning flags.

        Executes a comprehensive scan using bbot's active and potentially
        intrusive modules for deeper reconnaissance and vulnerability detection.
        """
        logger.info(f"Starting AGGRESSIVE bbot Scan on {self.target}")
        logger.warning("This is an aggressive scan that may trigger alerts")

        command = [
            "/root/.local/bin/bbot",
            "-t",
            self.target,
            "-f",
            "safe,passive,active,deadly,aggressive,web-thorough,cloud-enum,code-enum,affiliates",
            "-m",
            "nuclei,baddns,baddns_zone,dotnetnuke,ffuf",
            "--allow-deadly",
            "-o",
            self.folder,
            "-n",
            self.foldername,
            "-y",
            "--strict-scope",
        ]

        logger.debug(f"Command: {' '.join(command)}")

        # Execute bbot command
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        logger.info("Aggressive bbot scan in progress...")
        process.wait()
        logger.info("Aggressive scan completed!")

        # Place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        # Store data from csv into the database
        logger.info("Processing aggressive scan results and storing in database...")
        insert_bbot_to_db(self.prep_data(), org_name=self.org_name)
        logger.info("Aggressive scan data successfully processed")

    def run(self, mode: str) -> int:
        """
        Run the appropriate bbot scan based on the mode.

        Args:
            aggressive_mode: If True, runs an aggressive scan, otherwise runs a passive scan
        """
        if mode == "aggressive":
            self.aggressive()
        elif mode == "normal":
            self.normal()
        elif mode == "attack_surface":
            self.attack_surface()
        else:
            self.passive()
        return 0
