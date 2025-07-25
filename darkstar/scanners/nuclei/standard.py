"""
Standard Nuclei vulnerability scanner for the Darkstar framework.

This module provides a wrapper for the standard Nuclei scanner to detect
vulnerabilities across a range of target systems.
"""

import logging
import re
import subprocess

from core.db_helper import insert_vulnerability_to_database
from core.models.vulnerability import Vulnerability
from scanners.nuclei.base import BaseNucleiScanner

logger = logging.getLogger(__name__)


class NucleiScanner(BaseNucleiScanner):
    """
    Wrapper for Nuclei vulnerability scanner.

    Provides methods for scanning hosts using Nuclei templates to
    identify security vulnerabilities and misconfigurations.

    Attributes:
        file (str): Path to a file containing targets to scan
        org_name (str): Organization name for database storage
        target_count (int): Number of targets in the file
    """

    def __init__(self, filename: str, org_name: str):
        super().__init__(org_name)
        self.file = filename

        # Count targets for progress tracking
        try:
            with open(self.file, "r") as f:
                self.target_count = sum(1 for _ in f)
        except Exception as e:
            logger.error(f"Error counting targets in {filename}: {e}")
            self.target_count = 0

    def scan_nuclei(self) -> None:
        """
        Execute the Nuclei scan and process results.

        Runs Nuclei against the targets, parses the output to extract
        vulnerability information, and inserts findings into the database.
        """
        logger.info(f"Starting Nuclei scan on targets from {self.file}")
        logger.info(f"Scanning {self.target_count} targets for vulnerabilities")

        nuclei_command = f"nuclei -l {self.file} -s low,medium,high,critical,unknown -et github -bs 400 -rl 1000"
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
                if any(keyword in output_line for keyword in self.keywords):
                    vulnerabilities_found.append(output_line)

                    logger.info(f"[VULN] {output_line.strip()}")

                    # Extract URL and domain
                    url = self.extract_url_from_output(output_line)
                    domain = self.extract_host_from_url(url)

                    # Extract CVE if present
                    cve_match = re.search(r"(?P<cve>CVE-[^\s]+)", output_line)
                    cve_number = None

                    # Get first element of output line (usually contains vulnerability name)
                    vuln = output_line.split(" ")[0]
                    vuln = self.remove_ansi_codes(vuln)

                    if cve_match:
                        cve = cve_match.group("cve")
                        # Cut off at first :
                        cve = cve.split(":")[0]
                        # Cut off at first ]
                        cve = cve.split("]")[0]
                        # Remove colors from cve
                        cve_number = self.remove_ansi_codes(cve)

                    # Determine severity
                    severity = self.extract_severity(output_line)

                    # Create vulnerability object
                    finding_object = Vulnerability(
                        title=vuln,
                        affected_item=url,
                        tool="nuclei",
                        confidence=97,
                        severity=severity,
                        host=domain,
                        cve_number=cve_number,
                    )

                    # Add to database
                    logger.info(f"Adding to database: {finding_object}")
                    insert_vulnerability_to_database(
                        vuln=finding_object, org_name=self.org_name
                    )

        vuln_count = len(vulnerabilities_found)
        logger.info(f"Nuclei scan completed! Found {vuln_count} vulnerabilities")
