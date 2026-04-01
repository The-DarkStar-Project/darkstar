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
import tempfile
from core.db_helper import insert_vulnerability_to_database
from core.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

class NucleiMode(enum.Enum):
    STANDARD = "standard"
    WORDPRESS = "wordpress"
    NETWORK = "network"

class NucleiScanner:
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

        self._temp_target_file = None
        if not os.path.exists(self.target):
            fd, tmp_path = tempfile.mkstemp(prefix="nuclei_targets_", suffix=".txt")
            try:
                with os.fdopen(fd, "w") as f:
                    f.writelines(
                        f"{line.strip()}\n" for line in target.split(",") if line.strip()
                    )
            except Exception:
                os.close(fd)
                raise
            self._temp_target_file = tmp_path
            self.target = tmp_path

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
        
        # Keep templates fresh but never fail scan startup if update has issues.
        logger.info("Updating Nuclei templates...")
        try:
            subprocess.run(
                ["nuclei", "-update-templates", "-silent"],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except Exception as exc:
            logger.warning(f"Skipping template update due to error: {exc}")

        match self.mode:
            case NucleiMode.STANDARD:
                nuclei_command = [
                    "nuclei",
                    "-l",
                    self.target,
                    "-s",
                    "low,medium,high,critical,unknown",
                    "-et",
                    "github",
                    "-bs",
                    "100",
                    "-rl",
                    "300",
                    "-timeout",
                    "10",
                    "-j",
                ]
            case NucleiMode.WORDPRESS:
                nuclei_command = [
                    "nuclei",
                    "-l",
                    self.target,
                    "-s",
                    "low,medium,high,critical,unknown",
                    "-tags",
                    "wordpress",
                    "-bs",
                    "100",
                    "-rl",
                    "300",
                    "-timeout",
                    "10",
                    "-j",
                ]
            case NucleiMode.NETWORK:
                nuclei_command = [
                    "nuclei",
                    "-l",
                    self.target,
                    "-s",
                    "low,medium,high,critical,unknown",
                    "-t",
                    "network",
                    "-bs",
                    "100",
                    "-rl",
                    "300",
                    "-timeout",
                    "10",
                    "-j",
                ]

        logger.debug(f"Command: {' '.join(nuclei_command)}")

        # Track vulnerabilities found for progress tracking
        vulnerabilities_found = []

        process = subprocess.Popen(
            nuclei_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        if not process.stdout:
            logger.error("Nuclei stdout stream unavailable")
            return

        while True:
            output_line = process.stdout.readline()
            if not output_line and process.poll() is not None:
                break

            raw = output_line.strip()
            if not raw:
                continue

            try:
                output_obj = json.loads(raw)
            except json.JSONDecodeError as e:
                logger.debug(f"Skipping non-JSON line from Nuclei: {raw[:100]}")
                continue
            except Exception as e:
                logger.debug(f"Error parsing Nuclei output: {e}")
                continue

            info = output_obj.get("info") or {}
            severity = (output_obj.get("severity") or info.get("severity") or "unknown").lower()
            if severity not in self.severities:
                continue

            vulnerabilities_found.append(output_obj)

            url = output_obj.get("url")
            domain = output_obj.get("host")
            template_id = output_obj.get("template-id") or ""
            cve_number = template_id if "cve" in template_id.lower() else None

            finding_object = Vulnerability(
                title=info.get("name") or "nuclei finding",
                affected_item=url,
                tool="nuclei",
                confidence=97,
                severity=severity,
                host=domain,
                cve_number=cve_number,
                summary=info.get("description"),
                references=info.get("reference", []),
                poc=url,
                cvss=info.get("classification", {}).get("cvss-score"),
                epss=info.get("classification", {}).get("epss-score"),
            )

            logger.info(
                f"Adding Nuclei finding to database: {finding_object.title} ({severity})"
            )
            insert_vulnerability_to_database(vuln=finding_object, org_name=self.org_name)

        stderr_output = process.stderr.read() if process.stderr else ""
        if not isinstance(stderr_output, str):
            stderr_output = str(stderr_output)

        return_code = process.wait()
        if isinstance(return_code, int) and return_code != 0:
            logger.warning(f"Nuclei exited with code {return_code}: {stderr_output[:1000]}")

        vuln_count = len(vulnerabilities_found)
        logger.info(f"Nuclei scan completed! Found {vuln_count} vulnerabilities")

    def run(self) -> None:
        """Run Nuclei scan in a worker thread and wait for completion."""
        logger.info(f"Launching {self.__class__.__name__} scanner in background thread")
        thread = threading.Thread(target=self.scan_nuclei)
        thread.start()
        thread.join()
        logger.info(f"{self.__class__.__name__} scanner thread completed")
        if self._temp_target_file and os.path.exists(self._temp_target_file):
            try:
                os.remove(self._temp_target_file)
            except OSError as e:
                logger.warning(f"Could not remove temp targets file {self._temp_target_file}: {e}")