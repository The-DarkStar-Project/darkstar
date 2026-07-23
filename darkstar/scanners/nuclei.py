"""
Base functionality for Nuclei scanners in the Darkstar framework.

This module provides common utilities and base classes for all Nuclei-based
vulnerability scanners.
"""

import enum
import fcntl
import glob
import json
import logging
import os
from pathlib import Path
import subprocess
import tempfile
import time

from core.db_helper import insert_vulnerabilities_to_database
from core.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


def _env_nonnegative_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


NUCLEI_TEMPLATES_DIR = os.getenv("NUCLEI_TEMPLATES_DIR", "/root/nuclei-templates")
NUCLEI_SEVERITIES = ("info", "unknown", "low", "medium", "high", "critical")
NUCLEI_SEVERITY_FILTER = ",".join(NUCLEI_SEVERITIES)
NUCLEI_TEMPLATE_UPDATE_INTERVAL = _env_nonnegative_int(
    "NUCLEI_TEMPLATE_UPDATE_INTERVAL", 86400
)
NUCLEI_DB_BATCH_SIZE = max(1, _env_nonnegative_int("NUCLEI_DB_BATCH_SIZE", 100))
NUCLEI_UPDATE_MARKER = ".darkstar-template-update"
NUCLEI_UPDATE_LOCK = ".darkstar-template-update.lock"


def _has_nuclei_templates(directory: str) -> bool:
    """Return whether a directory contains at least one YAML template."""
    if not os.path.isdir(directory):
        return False
    for _root, _directories, filenames in os.walk(directory):
        if any(
            filename.lower().endswith((".yaml", ".yml"))
            for filename in filenames
        ):
            return True
    return False


def _select_nuclei_templates_dir(configured_directory: str) -> str:
    """Select a valid tree or a non-existent recovery path for installation."""
    configured_directory = os.path.abspath(configured_directory)
    if not os.path.exists(configured_directory) or _has_nuclei_templates(
        configured_directory
    ):
        return configured_directory

    recovery_prefix = f"{configured_directory}-darkstar"
    for candidate in sorted(glob.glob(f"{recovery_prefix}*")):
        if _has_nuclei_templates(candidate):
            return candidate

    candidate = recovery_prefix
    suffix = 1
    while os.path.exists(candidate):
        candidate = f"{recovery_prefix}-{suffix}"
        suffix += 1

    logger.warning(
        "Configured Nuclei template directory %s contains no YAML; repairing into %s",
        configured_directory,
        candidate,
    )
    return candidate


def _update_nuclei_templates_if_due(
    templates_dir: str,
    *,
    interval: int = NUCLEI_TEMPLATE_UPDATE_INTERVAL,
    now: float | None = None,
) -> bool:
    """Update one shared template tree at most once per configured interval."""
    if interval <= 0:
        logger.info("Runtime Nuclei template updates are disabled")
        return False

    directory = Path(templates_dir)
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / NUCLEI_UPDATE_MARKER
    lock_path = directory / NUCLEI_UPDATE_LOCK
    current_time = time.time() if now is None else now

    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            if marker.exists() and current_time - marker.stat().st_mtime < interval:
                logger.info(
                    "Nuclei templates were updated recently; skipping duplicate update"
                )
                return False

            logger.info("Updating Nuclei templates in %s", templates_dir)
            update_result = subprocess.run(
                [
                    "nuclei",
                    "-update-templates",
                    "-update-template-dir",
                    templates_dir,
                    "-silent",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if update_result.returncode != 0:
                logger.warning(
                    "Nuclei template update exited with code %s: %s",
                    update_result.returncode,
                    (update_result.stderr or "")[:1000],
                )
                return False

            marker.touch()
            return True
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


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

    def __init__(
        self,
        target: str,
        org_name: str,
        mode: NucleiMode = NucleiMode.STANDARD,
    ):
        self.target = target
        self.org_name = org_name
        self.mode = mode
        self.severities = set(NUCLEI_SEVERITIES)

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
        """
        Execute the Nuclei scan and process results.

        Runs Nuclei against the targets, parses the output to extract
        vulnerability information, and inserts findings into the database.
        """
        logger.info(
            "Starting Nuclei scan on targets from %s in %s mode",
            self.target,
            self.mode.value,
        )
        logger.info(f"Scanning {self.target_count} targets for vulnerabilities")

        templates_dir = _select_nuclei_templates_dir(NUCLEI_TEMPLATES_DIR)

        # The image already contains templates. Refresh the shared tree at most
        # once per interval so parallel Nuclei modes do not repeat the update.
        try:
            _update_nuclei_templates_if_due(templates_dir)
        except Exception as exc:
            logger.warning(f"Skipping template update due to error: {exc}")

        if not _has_nuclei_templates(templates_dir):
            raise RuntimeError(
                f"No Nuclei YAML templates found in {templates_dir}; "
                "refusing to report a successful empty scan"
            )

        match self.mode:
            case NucleiMode.STANDARD:
                nuclei_command = [
                    "nuclei",
                    "-l",
                    self.target,
                    "-t",
                    templates_dir,
                    "-s",
                    NUCLEI_SEVERITY_FILTER,
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
                    "-t",
                    templates_dir,
                    "-s",
                    NUCLEI_SEVERITY_FILTER,
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
                network_templates = os.path.join(templates_dir, "network")
                if not _has_nuclei_templates(network_templates):
                    raise RuntimeError(
                        f"Nuclei network templates not found in {network_templates}; "
                        "network scan cannot run"
                    )
                nuclei_command = [
                    "nuclei",
                    "-l",
                    self.target,
                    "-s",
                    NUCLEI_SEVERITY_FILTER,
                    "-t",
                    network_templates,
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
        vulnerabilities_found = 0
        pending_findings = []

        def flush_findings() -> None:
            if not pending_findings:
                return
            batch = list(pending_findings)
            pending_findings.clear()
            inserted = insert_vulnerabilities_to_database(batch, self.org_name)
            if inserted != len(batch):
                logger.warning(
                    "Nuclei persisted %s of %s findings in the current batch",
                    inserted,
                    len(batch),
                )

        process = subprocess.Popen(
            nuclei_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        if not process.stdout:
            process.terminate()
            raise RuntimeError("Nuclei stdout stream unavailable")

        while True:
            output_line = process.stdout.readline()
            if not output_line and process.poll() is not None:
                break

            raw = output_line.strip()
            if not raw:
                continue

            try:
                output_obj = json.loads(raw)
            except json.JSONDecodeError:
                logger.debug(f"Skipping non-JSON line from Nuclei: {raw[:100]}")
                continue
            except Exception as e:
                logger.debug(f"Error parsing Nuclei output: {e}")
                continue

            info = output_obj.get("info") or {}
            severity = (output_obj.get("severity") or info.get("severity") or "unknown").lower()
            if severity not in self.severities:
                continue

            vulnerabilities_found += 1

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

            logger.info("Queued Nuclei finding: %s (%s)", finding_object.title, severity)
            pending_findings.append(finding_object)
            if len(pending_findings) >= NUCLEI_DB_BATCH_SIZE:
                flush_findings()

        stderr_output = process.stderr.read() if process.stderr else ""
        if not isinstance(stderr_output, str):
            stderr_output = str(stderr_output)

        return_code = process.wait()
        if isinstance(return_code, int) and return_code != 0:
            raise RuntimeError(
                f"Nuclei exited with code {return_code}: {stderr_output[:1000]}"
            )

        flush_findings()
        logger.info(f"Nuclei scan completed! Found {vulnerabilities_found} vulnerabilities")

    def run(self) -> None:
        """Run Nuclei synchronously; the async orchestrator owns concurrency."""
        try:
            self.scan_nuclei()
        finally:
            if self._temp_target_file and os.path.exists(self._temp_target_file):
                try:
                    os.remove(self._temp_target_file)
                except OSError as e:
                    logger.warning(
                        "Could not remove temp targets file %s: %s",
                        self._temp_target_file,
                        e,
                    )
