"""
BBOT (Black Box Operations Tool) scanner integration for Darkstar.

This module provides a wrapper for the bbot scanner, allowing for passive and
aggressive reconnaissance, and processing the results for database insertion.
"""

import ast
import hashlib
import logging
import os
import signal
import subprocess
import threading

import pandas as pd

from core.db_helper import insert_vulnerability_to_database, insert_bbot_to_db
from core.models.vulnerability import Vulnerability
from tools.hibp.HIBPwned import HIBPwned

logger = logging.getLogger(__name__)


BBOT_ASM_MODULES = [
    "anubisdb",
    "certspotter",
    "code_repository",
    "crt",
    "dnscommonsrv",
    "dnsdumpster",
    "git",
    "hackertarget",
    "httpx",
    "portscan",
    "rapiddns",
    "robots",
    "securitytxt",
    "sitedossier",
    "social",
    "sslcert",
    "subdomaincenter",
    "urlscan",
    "viewdns",
    "wayback",
]

BBOT_HEAVY_MODULE_EXCLUSIONS = [
    "dnsbrute",
    "dnsbrute_mutations",
    "docker_pull",
    "extractous",
    "filedownload",
    "git_clone",
    "gitdumper",
    "gowitness",
    "jadx",
    "postman_download",
    "trufflehog",
]

BBOT_ASM_PORTS = (
    "80,443,8080,8443,8000,8008,8081,3000,5000,9443,9090,9000,"
    "22,25,53,110,143,587,993,995,3389"
)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


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
        self.ips_file = f"{self.folder}/{self.foldername}/ips.txt"

        # Create a directory for bbot output if not exists
        if not os.path.exists(self.folder):
            os.makedirs(self.folder, exist_ok=True)

    def _descendant_pids(self, pid: int) -> list[int]:
        descendants: list[int] = []
        try:
            proc_entries = [entry for entry in os.listdir("/proc") if entry.isdigit()]
        except OSError:
            return descendants

        children = []
        for entry in proc_entries:
            try:
                with open(f"/proc/{entry}/stat", encoding="utf-8", errors="replace") as stat_file:
                    stat_data = stat_file.read()
                parts = stat_data.rsplit(")", 1)[-1].split()
                if len(parts) > 1 and int(parts[1]) == pid:
                    children.append(int(entry))
            except (OSError, ValueError):
                continue

        for child in children:
            descendants.extend(self._descendant_pids(child))
            descendants.append(child)
        return descendants

    def _signal_process_tree(self, pid: int, sig: signal.Signals, label: str) -> None:
        pids = self._descendant_pids(pid) + [pid]
        logger.warning("Sending %s to BBOT %s process tree: %s", sig.name, label, pids)
        for child_pid in pids:
            try:
                os.kill(child_pid, sig)
            except ProcessLookupError:
                continue

    def _run_bbot_command(
        self,
        command: list[str],
        label: str,
        timeout_seconds: int | None = None,
    ) -> int:
        logger.info("%s bbot scan in progress...", label)
        logger.info("BBOT command: %s", " ".join(command))
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        previous_handlers = {}
        signals_registered = False

        def _handle_stop_signal(signum, _frame):
            logger.warning(
                "BBOT %s scan received signal %s; stopping scanner process tree",
                label,
                signum,
            )
            self._signal_process_tree(process.pid, signal.SIGTERM, label)
            raise SystemExit(128 + signum)

        if threading.current_thread() is threading.main_thread():
            for stop_signal in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[stop_signal] = signal.getsignal(stop_signal)
                signal.signal(stop_signal, _handle_stop_signal)
            signals_registered = True

        try:
            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
                return_code = process.returncode
            except subprocess.TimeoutExpired:
                logger.warning(
                    "BBOT %s scan reached timeout after %s seconds; processing partial output",
                    label,
                    timeout_seconds,
                )
                self._signal_process_tree(process.pid, signal.SIGTERM, label)
                try:
                    stdout, stderr = process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    self._signal_process_tree(process.pid, signal.SIGKILL, label)
                    stdout, stderr = process.communicate()
                return_code = 124
        finally:
            if signals_registered:
                for stop_signal, previous_handler in previous_handlers.items():
                    signal.signal(stop_signal, previous_handler)

        output = "\n".join(
            line
            for line in (stdout or "").splitlines()
            if line.strip()
        )
        errors = "\n".join(
            line
            for line in (stderr or "").splitlines()
            if line.strip()
        )
        if return_code != 0:
            logger.error("BBOT %s scan failed with exit code %s", label, return_code)
            if output:
                logger.error("BBOT stdout tail:\n%s", "\n".join(output.splitlines()[-40:]))
            if errors:
                logger.error("BBOT stderr tail:\n%s", "\n".join(errors.splitlines()[-40:]))
        elif output:
            logger.info("BBOT %s stdout tail:\n%s", label, "\n".join(output.splitlines()[-20:]))
        if errors and return_code == 0:
            logger.warning("BBOT %s stderr tail:\n%s", label, "\n".join(errors.splitlines()[-20:]))
        return return_code

    def _fallback_dataframe_from_text_outputs(self) -> pd.DataFrame:
        rows = []
        subdomains_file = f"{self.folder}/{self.foldername}/subdomains.txt"
        ips_file = f"{self.folder}/{self.foldername}/ips.txt"
        if os.path.exists(subdomains_file):
            with open(subdomains_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    host = line.strip()
                    if not host:
                        continue
                    rows.append(
                        {
                            "Event type": "DNS_NAME",
                            "Event data": host,
                            "IP Address": None,
                            "Source Module": "bbot_subdomains",
                            "Scope Distance": 0,
                            "Event Tags": "in-scope,subdomain",
                        }
                    )
        if os.path.exists(ips_file):
            with open(ips_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    ip = line.strip()
                    if not ip:
                        continue
                    rows.append(
                        {
                            "Event type": "IP_ADDRESS",
                            "Event data": ip,
                            "IP Address": ip,
                            "Source Module": "bbot_ips",
                            "Scope Distance": 0,
                            "Event Tags": "in-scope,ip",
                        }
                    )
        if rows:
            logger.warning(
                "BBOT output.csv was missing; falling back to %d records from text outputs",
                len(rows),
            )
        return pd.DataFrame(rows)

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
                    item = ast.literal_eval(row["Event data"])
                    if isinstance(item, str):
                        item = ast.literal_eval(item)
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
                        vuln=finding_object, org_name=self.org_name
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
    
    def collect_in_scope_ips(self, df) -> None:
        # Grab IPs which contain "in-scope" in their Event Tags
        in_scope_ips = set(df[df["Event Tags"].str.contains("in-scope", na=False)]["IP Address"])

        if in_scope_ips:
            logger.info(f"Found {len(in_scope_ips)} in-scope IP{'s' if len(in_scope_ips) > 1 else ''} in bbot scan results")
            with open(self.ips_file, "w") as f:
                for ip in in_scope_ips:
                    f.write(f"{ip}\n")
        else:
            logger.info("No in-scope IPs found in bbot scan results")

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

            logger.info("Collecting in-scope IPs from bbot scan results")
            self.collect_in_scope_ips(df)

            # Check if bbot found any vulns write to vulnerability class and insert to db
            self.vulns_to_db(df)

            return df
        else:
            logger.error(
                f"No output file found at {output_file}, something went wrong with bbot scan"
            )
            return self._fallback_dataframe_from_text_outputs()

    def attack_surface(self) -> None:
        """
        Run a bounded BBOT attack-surface discovery scan.

        This profile intentionally avoids expensive content workflows such as
        cloning repositories, pulling containers, secret scanning downloaded
        files, DNS brute forcing, and screenshots.
        """
        logger.info(f"Starting Attack Surface bbot Scan on {self.target}")

        command = [
            "/root/.local/bin/bbot",
            "-t",
            self.target,
            "-m",
            *BBOT_ASM_MODULES,
            "-em",
            *BBOT_HEAVY_MODULE_EXCLUSIONS,
            "-ef",
            "slow",
            "download",
            "web-screenshots",
            "aggressive",
            "deadly",
            "-c",
            f"modules.portscan.ports={os.environ.get('BBOT_ASM_PORTS', BBOT_ASM_PORTS)}",
            f"modules.portscan.rate={_env_int('BBOT_ASM_PORTSCAN_RATE', 300)}",
            f"modules.portscan.wait={_env_int('BBOT_ASM_PORTSCAN_WAIT', 3)}",
            f"modules.portscan.module_timeout={_env_int('BBOT_ASM_PORTSCAN_TIMEOUT_SECONDS', 180)}",
            f"modules.httpx.threads={_env_int('BBOT_ASM_HTTPX_THREADS', 25)}",
            f"modules.httpx.max_response_size={_env_int('BBOT_ASM_HTTPX_MAX_RESPONSE_SIZE', 1048576)}",
            "-om",
            "csv",
            "subdomains",
            "txt",
            "-o",
            self.folder,
            "-n",
            self.foldername,
            "-y",
            "--ignore-failed-deps",
        ]
        logger.debug(f"Command: {' '.join(command)}")

        return_code = self._run_bbot_command(
            command,
            "attack_surface",
            timeout_seconds=_env_int("BBOT_ASM_TIMEOUT_SECONDS", 1200),
        )
        logger.info("Attack Surface bbot scan completed with exit code %s", return_code)

        # Place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        # Store data from csv into the database
        logger.info("Processing scan results and storing in database...")
        insert_bbot_to_db(self.prep_data(), org_name=self.org_name)
        logger.info("Attack Surface scan data successfully processed")

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
            "-om",
            "csv",
            "subdomains",
            "txt",
            "-o",
            self.folder,
            "-n",
            self.foldername,
            "-y",
            "--strict-scope",
            "--ignore-failed-deps",
        ]
        logger.debug(f"Command: {' '.join(command)}")

        return_code = self._run_bbot_command(command, "passive")
        logger.info("Passive scan completed with exit code %s", return_code)

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
            "safe,passive,subdomain-enum,cloud-enum,email-enum,social-enum,code-enum,web-basic,affiliates",
            "-om",
            "csv",
            "subdomains",
            "txt",
            "-o",
            self.folder,
            "-n",
            self.foldername,
            "-y",
            "--ignore-failed-deps",
        ]
        logger.debug(f"Command: {' '.join(command)}")

        return_code = self._run_bbot_command(command, "normal")
        logger.info("normal scan completed with exit code %s", return_code)

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
            "safe,passive,subdomain-enum,active,deadly,aggressive,web-thorough,cloud-enum,email-enum,social-enum,code-enum,affiliates",
            "-m",
            "nuclei,baddns,baddns_zone,dotnetnuke,ffuf",
            "-om",
            "csv",
            "subdomains",
            "txt",
            "--allow-deadly",
            "-o",
            self.folder,
            "-n",
            self.foldername,
            "-y",
            "--ignore-failed-deps",
        ]

        logger.debug(f"Command: {' '.join(command)}")

        return_code = self._run_bbot_command(command, "aggressive")
        logger.info("Aggressive scan completed with exit code %s", return_code)

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
