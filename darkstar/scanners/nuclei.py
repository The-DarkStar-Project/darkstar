"""
Base functionality for Nuclei scanners in the Darkstar framework.

This module provides common utilities and base classes for all Nuclei-based
vulnerability scanners.
"""

import logging
import threading
import os
import enum
import subprocess
import json
from core.db_helper import insert_vulnerability_to_database
from core.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

class NucleiMode(enum.Enum):
    STANDARD = "standard"
    WORDPRESS = "wordpress"
    NETWORK = "network"

class NucleiScanner():
    """
    Base class for Nuclei vulnerability scanners.

    Provides common functionality for different Nuclei scanner variants.

    Attributes:
        org_name (str): Organization name for database storage
        keywords (list): Severity levels to detect in the output
    """

    def __init__(self, target: str, org_name: str, mode: NucleiMode = NucleiMode.STANDARD):
        self.target = target
        self.org_name = org_name
        self.mode = mode
        self.severities = ["unknown", "low", "medium", "high", "critical"]

        if not os.path.exists(self.target):
            with open("/tmp/targets.txt", "w") as f:
                f.writelines(
                    f"{line.strip()}\n" for line in target.split(",") if line.strip()
                )
            self.target = "/tmp/targets.txt"

        # Count targets for progress tracking
        try:
            with open(self.target, "r") as f:
                self.target_count = sum(1 for _ in f)
        except Exception as e:
            logger.error(f"Error counting targets in {target}: {e}")
            self.target_count = 0

    def scan_nuclei(self) -> None:
        """Execute the Nuclei scan and process results."""
        """
        Execute the Nuclei scan and process results.

        Runs Nuclei against the targets, parses the output to extract
        vulnerability information, and inserts findings into the database.
        """
        logger.info(f"Starting Nuclei scan on targets from {self.target} in {self.mode.value} mode")
        logger.info(f"Scanning {self.target_count} targets for vulnerabilities")

        match self.mode:
            case NucleiMode.STANDARD:
                nuclei_command = f"nuclei -l {self.target} -s low,medium,high,critical,unknown -et github -bs 400 -rl 1000 -j"
            case NucleiMode.WORDPRESS:
                nuclei_command = f"nuclei -l {self.target} -s low,medium,high,critical,unknown -tags wordpress -bs 400 -rl 1000 -j"
            case NucleiMode.NETWORK:
                nuclei_command = f"nuclei -l {self.target} -s low,medium,high,critical,unknown -t network -bs 400 -rl 1000 -j"
                
        logger.debug(f"Command: {nuclei_command}")

        # Track vulnerabilities found for progress tracking
        vulnerabilities_found = []

        process = subprocess.Popen(
            nuclei_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True,
        )

        while True:
            output_line = process.stdout.readline()
            if not output_line and process.poll() is not None:
                break

            if output_line:
                output_obj = json.loads(output_line)
                if any(keyword in output_obj.get("severity") for keyword in self.severities):
                    vulnerabilities_found.append(output_obj)

                    # logger.info(f"[VULN] {output_line.strip()}")

                    # Extract URL and domain
                    # url = self._extract_url_from_output(output_line)
                    url = output_obj.get("url")
                    # domain = self._extract_host_from_url(url)
                    domain = output_obj.get("host")

                    # Extract CVE if present
                    cve_number = None
                    if "cve" in output_obj.get("template-id").lower():
                        cve_number = output_obj.get("template-id")

                    name = output_obj.get("info").get("name")
                    severity = output_obj.get("severity", "unknown")
                    references = output_obj.get("info").get("reference", [])
                    poc = url
                    summary = output_obj.get("info").get("description")
                    cvss = output_obj.get("info").get("classification", {}).get("cvss-score")
                    epss = output_obj.get("info").get("classification", {}).get("epss-score")

                    # Create vulnerability object
                    finding_object = Vulnerability(
                        title=name,
                        affected_item=url,
                        tool="nuclei",
                        confidence=97,
                        severity=severity,
                        host=domain,
                        cve_number=cve_number,
                        summary=summary,
                        references=references,
                        poc=poc,
                        cvss=cvss,
                        epss=epss,
                    )

                    # Add to database
                    logger.info(f"Adding to database: {finding_object}")
                    insert_vulnerability_to_database(
                        vuln=finding_object, org_name=self.org_name
                    )

        vuln_count = len(vulnerabilities_found)
        logger.info(f"Nuclei scan completed! Found {vuln_count} vulnerabilities")

    def run(self) -> None:
        """
        Start the Nuclei scan in a separate thread.

        Creates and starts a new thread to execute the Nuclei scan
        asynchronously, allowing the main program to continue.
        """
        logger.info(f"Launching {self.__class__.__name__} scanner in background thread")
        thread = threading.Thread(target=self.scan_nuclei)
        thread.start()
        logger.info(f"{self.__class__.__name__} scanner thread started")