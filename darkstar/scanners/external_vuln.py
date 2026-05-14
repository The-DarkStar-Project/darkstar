"""
External vulnerability scanner integrations for the DarkStar framework.

Provides wrappers for Nikto, Wapiti, OWASP ZAP, Dalfox, and testssl.sh.
Each scanner normalises its output into Vulnerability objects and
persists them via insert_vulnerability_to_database.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import threading
from urllib.parse import urlparse

from core.db_helper import insert_vulnerability_to_database
from core.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_scheme(target: str, scheme: str = "http") -> str:
    """Prepend scheme if the target string has none."""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"{scheme}://{target}"


def _parse_host(url: str) -> str:
    """Return just the hostname (without scheme / port) from a URL or bare host."""
    if "://" in url:
        return urlparse(url).hostname or url
    return url.split(":")[0]


def _severity_from_keyword(text: str) -> str:
    """Derive a DarkStar severity label from free text when no explicit level exists."""
    text_l = text.lower()
    if any(k in text_l for k in ("critical", "remote code", "rce", "sql injection", "sqli")):
        return "high"
    if any(k in text_l for k in ("xss", "csrf", "traversal", "injection", "exposed", "disclosure")):
        return "medium"
    if any(k in text_l for k in ("missing header", "header not set", "cookie", "information", "version")):
        return "low"
    return "info"


def _normalize_wapiti_level(level: int) -> str:
    """Map Wapiti numeric level to DarkStar severity."""
    return {1: "low", 2: "medium", 3: "high"}.get(level, "info")


def _normalize_zap_risk(risk_code: str | int) -> str:
    """Map OWASP ZAP risk code to DarkStar severity."""
    return {0: "info", 1: "low", 2: "medium", 3: "high"}.get(int(risk_code), "info")


def _normalize_testssl_severity(sev: str) -> str:
    """Map testssl.sh severity string to DarkStar severity."""
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "warn": "low",
        "info": "info",
        "ok": "info",
    }.get(sev.lower(), "info")


# ---------------------------------------------------------------------------
# Nikto
# ---------------------------------------------------------------------------

class NiktoScanner:
    """
    Wraps the Nikto web server scanner.

    Runs Nikto against each supplied target, parses its JSON output,
    and inserts findings into the DarkStar database.
    """

    TOOL = "nikto"

    def __init__(self, targets: str, org_name: str):
        self.targets = [t.strip() for t in targets.split(",") if t.strip()]
        self.org_name = org_name

    def _scan_target(self, target: str) -> list[dict]:
        """Run Nikto against a single target and return raw finding dicts."""
        host = _ensure_scheme(target)
        hostname = _parse_host(host)

        # Write JSON output to a temp file so we can parse it reliably.
        with tempfile.NamedTemporaryFile(
            suffix=".json", prefix="nikto_", delete=False
        ) as tf:
            out_path = tf.name

        cmd = [
            "nikto",
            "-h", host,
            "-nointeractive",
            "-maxtime", "180",
            "-Format", "json",
            "-output", out_path,
        ]

        logger.info("Nikto: scanning %s", host)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=240,
            )
            if result.returncode not in (0, 1):
                logger.warning("Nikto exited with code %d: %s", result.returncode, result.stderr[:500])
        except subprocess.TimeoutExpired:
            logger.warning("Nikto timed out for %s", host)
            return []
        except FileNotFoundError:
            logger.error("Nikto not found – install it with: apt-get install nikto")
            return []

        findings: list[dict] = []
        if not os.path.exists(out_path):
            logger.warning("Nikto produced no output file for %s", host)
            return findings

        try:
            with open(out_path) as f:
                raw = json.load(f)

            # Nikto JSON wraps results under host[vulnerabilities] or root[vulnerabilities]
            host_block = raw.get("host") or {}
            vulns = host_block.get("vulnerabilities") or raw.get("vulnerabilities") or []
            for v in vulns:
                msg = v.get("msg") or v.get("message") or ""
                url = v.get("url") or host
                findings.append(
                    {
                        "title": msg[:120] if msg else "Nikto finding",
                        "host": hostname,
                        "affected_item": url,
                        "summary": msg,
                        "severity": _severity_from_keyword(msg),
                        "cve": v.get("references", {}).get("CVE") if isinstance(v.get("references"), dict) else None,
                        "solution": "Review server configuration and apply remediation as indicated.",
                        "references": [],
                    }
                )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("Could not parse Nikto JSON output: %s", exc)
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

        return findings

    def run(self) -> None:
        """Scan all targets and persist findings."""
        total = 0
        for target in self.targets:
            findings = self._scan_target(target)
            for f in findings:
                vuln = Vulnerability(
                    title=f["title"],
                    affected_item=f["affected_item"],
                    tool=self.TOOL,
                    confidence=75,
                    severity=f["severity"],
                    host=f["host"],
                    cve_number=f.get("cve") or "",
                    summary=f.get("summary", ""),
                    solution=f.get("solution", ""),
                    references=f.get("references", []),
                )
                insert_vulnerability_to_database(vuln=vuln, org_name=self.org_name)
                total += 1

        logger.info("Nikto: inserted %d findings for org %s", total, self.org_name)


# ---------------------------------------------------------------------------
# Wapiti
# ---------------------------------------------------------------------------

class WapitiScanner:
    """
    Wraps the Wapiti DAST scanner.

    Crawls and actively scans each target URL, parses Wapiti's JSON
    report, and persists findings.
    """

    TOOL = "wapiti"

    # Wapiti vulnerability type → CWE mapping for common types
    VULN_CWE_MAP = {
        "SQL Injection": "CWE-89",
        "Blind SQL Injection": "CWE-89",
        "Cross Site Scripting": "CWE-79",
        "Stored Cross Site Scripting": "CWE-79",
        "Path Traversal": "CWE-22",
        "Command Execution": "CWE-78",
        "CRLF Injection": "CWE-93",
        "Open Redirect": "CWE-601",
        "SSRF": "CWE-918",
        "XML External Entity": "CWE-611",
        "LDAP Injection": "CWE-90",
        "XPath Injection": "CWE-643",
    }

    def __init__(self, targets: str, org_name: str):
        self.targets = [t.strip() for t in targets.split(",") if t.strip()]
        self.org_name = org_name

    def _scan_target(self, target: str) -> list[dict]:
        """Run Wapiti against a single URL and return normalised finding dicts."""
        url = _ensure_scheme(target)
        hostname = _parse_host(url)

        with tempfile.TemporaryDirectory(prefix="wapiti_") as tmpdir:
            out_path = os.path.join(tmpdir, "report.json")

            cmd = [
                "wapiti",
                "-u", url,
                "--scope", "page",
                "-d", "3",
                "--max-links-per-page", "50",
                "--max-scan-time", "300",
                "--tasks", "4",
                "-f", "json",
                "-o", out_path,
            ]

            logger.info("Wapiti: scanning %s", url)
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=360,
                )
            except subprocess.TimeoutExpired:
                logger.warning("Wapiti timed out for %s", url)
            except FileNotFoundError:
                logger.error("Wapiti not found – install it with: pip3 install wapiti3")
                return []

            if not os.path.exists(out_path):
                logger.warning("Wapiti produced no JSON output for %s", url)
                return []

            findings: list[dict] = []
            try:
                with open(out_path) as f:
                    report = json.load(f)

                # Process active vulnerabilities
                for vuln_type, items in (report.get("vulnerabilities") or {}).items():
                    cwe = self.VULN_CWE_MAP.get(vuln_type, "")
                    for item in items:
                        info = item.get("info") or item.get("description") or ""
                        level = item.get("level") or 2
                        path = item.get("path") or item.get("url") or url
                        findings.append(
                            {
                                "title": vuln_type,
                                "host": hostname,
                                "affected_item": path if path.startswith("http") else f"{url}{path}",
                                "summary": info,
                                "severity": _normalize_wapiti_level(level),
                                "cwe": cwe,
                                "solution": item.get("wstg") or "",
                                "references": [],
                            }
                        )

                # Process anomalies (missing headers, cookie flags, etc.)
                for anom_type, items in (report.get("anomalies") or {}).items():
                    for item in items:
                        info = item.get("info") or item.get("description") or ""
                        path = item.get("path") or item.get("url") or url
                        findings.append(
                            {
                                "title": anom_type,
                                "host": hostname,
                                "affected_item": path if path.startswith("http") else f"{url}{path}",
                                "summary": info,
                                "severity": "low",
                                "cwe": "",
                                "solution": "",
                                "references": [],
                            }
                        )

            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.warning("Could not parse Wapiti JSON: %s", exc)

            return findings

    def run(self) -> None:
        """Scan all targets and persist findings."""
        total = 0
        for target in self.targets:
            findings = self._scan_target(target)
            for f in findings:
                vuln = Vulnerability(
                    title=f["title"],
                    affected_item=f["affected_item"],
                    tool=self.TOOL,
                    confidence=80,
                    severity=f["severity"],
                    host=f["host"],
                    summary=f.get("summary", ""),
                    solution=f.get("solution", ""),
                    cwe=f.get("cwe", ""),
                    references=f.get("references", []),
                )
                insert_vulnerability_to_database(vuln=vuln, org_name=self.org_name)
                total += 1

        logger.info("Wapiti: inserted %d findings for org %s", total, self.org_name)


# ---------------------------------------------------------------------------
# OWASP ZAP (baseline passive + spider)
# ---------------------------------------------------------------------------

class ZAPScanner:
    """
    Wraps the OWASP ZAP security scanner in daemon mode.

    Starts ZAP as a local daemon, performs a spider + passive scan,
    retrieves JSON alerts, then shuts down the daemon.
    """

    TOOL = "zap"
    API_KEY = "darkstar-zap-key"

    def __init__(self, targets: str, org_name: str):
        self.targets = [t.strip() for t in targets.split(",") if t.strip()]
        self.org_name = org_name
        self._port = self._free_port()
        self._zap_process: subprocess.Popen | None = None

    @staticmethod
    def _free_port() -> int:
        """Find a free TCP port for the ZAP daemon."""
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _start_daemon(self) -> bool:
        """Start the ZAP daemon. Returns True when ZAP is ready."""
        zap_sh = None
        for candidate in ("/opt/zaproxy/zap.sh", "/usr/local/bin/zap.sh", "zap.sh"):
            if os.path.isfile(candidate):
                zap_sh = candidate
                break

        if not zap_sh:
            logger.error("ZAP not found. Install ZAP and ensure zap.sh is on PATH.")
            return False

        try:
            version_check = subprocess.run(
                [zap_sh, "-version"],
                capture_output=True,
                text=True,
                timeout=45,
            )
            if version_check.returncode != 0:
                logger.error(
                    "ZAP preflight failed. stdout=%s stderr=%s",
                    version_check.stdout[-1000:],
                    version_check.stderr[-1000:],
                )
                return False
        except Exception as exc:
            logger.error("ZAP preflight failed: %s", exc)
            return False

        cmd = [
            zap_sh,
            "-daemon",
            "-host", "127.0.0.1",
            "-port", str(self._port),
            "-config", f"api.key={self.API_KEY}",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
        ]

        logger.info("ZAP: starting daemon on port %d", self._port)
        self._zap_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # ZAP can be slow to unpack/start the first time in a container.
        import urllib.request
        deadline = time.time() + 240
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{self._port}/JSON/core/view/version/?apikey={self.API_KEY}",
                    timeout=3,
                ):
                    logger.info("ZAP daemon ready on port %d", self._port)
                    return True
            except Exception:
                time.sleep(2)

        logger.error("ZAP daemon did not become ready within 240 seconds")
        return False

    def _stop_daemon(self) -> None:
        """Gracefully shut down the ZAP daemon."""
        try:
            import urllib.request
            urllib.request.urlopen(
                f"http://127.0.0.1:{self._port}/JSON/core/action/shutdown/?apikey={self.API_KEY}",
                timeout=5,
            )
            time.sleep(3)
        except Exception:
            pass

        if self._zap_process:
            try:
                self._zap_process.terminate()
                self._zap_process.wait(timeout=10)
            except Exception:
                try:
                    self._zap_process.kill()
                except Exception:
                    pass

    def _zap_api(self, path: str) -> dict | list | None:
        """Call the ZAP JSON API and return parsed response."""
        import urllib.request
        try:
            separator = "&" if "?" in path else "?"
            url = f"http://127.0.0.1:{self._port}/{path}{separator}apikey={self.API_KEY}"
            with urllib.request.urlopen(url, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except Exception as exc:
            logger.warning("ZAP API call failed (%s): %s", path, exc)
            return None

    def _scan_target(self, target: str) -> list[dict]:
        """Spider and passive-scan one URL via the running ZAP daemon."""
        url = _ensure_scheme(target)
        hostname = _parse_host(url)
        findings: list[dict] = []

        # Spider the target
        logger.info("ZAP: spidering %s", url)
        resp = self._zap_api(f"JSON/spider/action/scan/?url={url}&maxChildren=20&contextName=")
        if not resp:
            return findings
        scan_id = resp.get("scan", "0")

        # Wait for spider to complete
        deadline = time.time() + 300
        while time.time() < deadline:
            prog = self._zap_api(f"JSON/spider/view/status/?scanId={scan_id}")
            if prog and int(prog.get("status", 0)) >= 100:
                break
            time.sleep(3)

        # Wait for passive scan queue to drain
        deadline = time.time() + 240
        while time.time() < deadline:
            queue = self._zap_api("JSON/pscan/view/recordsToScan/")
            if queue and int(queue.get("recordsToScan", 1)) == 0:
                break
            time.sleep(2)

        # Retrieve alerts
        alerts_resp = self._zap_api(f"JSON/core/view/alerts/?baseurl={url}&start=0&count=500")
        alerts = (alerts_resp or {}).get("alerts") or []

        for alert in alerts:
            risk = alert.get("riskcode", "1")
            if int(risk) == 0:
                continue  # skip info-only

            affected = alert.get("url") or url
            cwe_raw = alert.get("cweid") or ""
            cwe = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw != "-1" else ""

            findings.append(
                {
                    "title": alert.get("alert") or alert.get("name") or "ZAP finding",
                    "host": hostname,
                    "affected_item": affected,
                    "summary": alert.get("description") or "",
                    "severity": _normalize_zap_risk(risk),
                    "solution": alert.get("solution") or "",
                    "cwe": cwe,
                    "references": alert.get("reference") or "",
                }
            )

        return findings

    def run(self) -> None:
        """Start ZAP, scan all targets, persist findings, shut down ZAP."""
        if not self._start_daemon():
            logger.error("ZAP scanner could not be started; skipping.")
            return

        total = 0
        try:
            for target in self.targets:
                findings = self._scan_target(target)
                for f in findings:
                    vuln = Vulnerability(
                        title=f["title"],
                        affected_item=f["affected_item"],
                        tool=self.TOOL,
                        confidence=85,
                        severity=f["severity"],
                        host=f["host"],
                        summary=f.get("summary", ""),
                        solution=f.get("solution", ""),
                        cwe=f.get("cwe", ""),
                        references=f.get("references", []) if isinstance(f.get("references"), list) else [],
                    )
                    insert_vulnerability_to_database(vuln=vuln, org_name=self.org_name)
                    total += 1
        finally:
            self._stop_daemon()

        logger.info("ZAP: inserted %d findings for org %s", total, self.org_name)


# ---------------------------------------------------------------------------
# Dalfox
# ---------------------------------------------------------------------------

class DalfoxScanner:
    """
    Wraps Dalfox for focused XSS testing.

    Dalfox output has changed between releases, so parsing accepts JSON arrays,
    JSON objects with common result keys, JSONL, and plain text fallback lines.
    """

    TOOL = "dalfox"

    def __init__(self, targets: str, org_name: str):
        self.targets = [t.strip() for t in targets.split(",") if t.strip()]
        self.org_name = org_name

    @staticmethod
    def _binary() -> str | None:
        return shutil.which("dalfox")

    @staticmethod
    def _flatten_results(raw) -> list:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            for key in ("data", "results", "pocs", "PoCs", "vulnerabilities", "findings"):
                value = raw.get(key)
                if isinstance(value, list):
                    return value
            if raw.get("type") or raw.get("payload") or raw.get("poc") or raw.get("evidence"):
                return [raw]
        return []

    def _load_report(self, out_path: str) -> list:
        if not os.path.exists(out_path):
            return []
        text = ""
        with open(out_path, encoding="utf-8", errors="replace") as f:
            text = f.read().strip()
        if not text:
            return []
        try:
            return self._flatten_results(json.loads(text))
        except json.JSONDecodeError:
            findings = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.extend(self._flatten_results(json.loads(line)))
                except json.JSONDecodeError:
                    if "[V]" in line or "POC" in line.upper() or "XSS" in line.upper():
                        findings.append({"summary": line})
            return findings

    def _scan_target(self, target: str) -> list[dict]:
        binary = self._binary()
        if not binary:
            logger.error("Dalfox not found. Install it with: go install github.com/hahwul/dalfox/v2@latest")
            return []

        url = _ensure_scheme(target)
        hostname = _parse_host(url)
        with tempfile.NamedTemporaryFile(suffix=".json", prefix="dalfox_", delete=False) as tf:
            out_path = tf.name

        cmd = [
            binary,
            "url",
            url,
            "--format", "json",
            "--output", out_path,
            "--silence",
            "--no-spinner",
            "--fast-scan",
            "--skip-headless",
            "--skip-mining-all",
            "--skip-mining-dom",
            "--worker", "20",
            "--timeout", "10",
        ]

        logger.info("Dalfox: scanning %s", url)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode not in (0, 1):
                logger.warning("Dalfox exited with code %d: %s", result.returncode, result.stderr[:500])
        except subprocess.TimeoutExpired:
            logger.warning("Dalfox timed out after 120 seconds for %s; importing any partial report", url)
        except FileNotFoundError:
            logger.error("Dalfox binary disappeared before execution")
            return []

        raw_findings = self._load_report(out_path)
        try:
            os.unlink(out_path)
        except OSError:
            pass

        findings: list[dict] = []
        seen: set[tuple[str, str, str]] = set()
        for item in raw_findings:
            if isinstance(item, str):
                item = {"summary": item}
            if not isinstance(item, dict):
                continue
            if not any(item.get(key) for key in ("type", "category", "vuln", "payload", "evidence", "poc", "PoC", "proof", "summary", "description")):
                continue

            finding_type = item.get("type") or item.get("category") or item.get("vuln") or "Cross-site scripting"
            payload = item.get("payload") or item.get("evidence") or item.get("param") or ""
            poc = item.get("poc") or item.get("PoC") or item.get("proof") or ""
            affected = item.get("url") or item.get("target") or poc or url
            summary_parts = [
                str(item.get("summary") or item.get("description") or finding_type),
                f"Payload: {payload}" if payload else "",
                f"PoC: {poc}" if poc else "",
            ]
            summary = " | ".join(part for part in summary_parts if part)
            key = (str(finding_type), str(affected), str(payload or poc))
            if key in seen:
                continue
            seen.add(key)
            verified = item.get("verified") is True or "verified" in str(item.get("status") or "").lower()
            findings.append(
                {
                    "title": f"XSS: {finding_type}",
                    "host": hostname,
                    "affected_item": affected,
                    "summary": summary,
                    "severity": "high" if verified else "medium",
                    "solution": "Validate and encode user-controlled input in the affected reflection context. Apply a restrictive Content Security Policy as defense in depth.",
                    "references": ["https://owasp.org/www-community/attacks/xss/"],
                }
            )
        return findings

    def run(self) -> None:
        total = 0
        for target in self.targets:
            for f in self._scan_target(target):
                vuln = Vulnerability(
                    title=f["title"],
                    affected_item=f["affected_item"],
                    tool=self.TOOL,
                    confidence=90 if f["severity"] == "high" else 75,
                    severity=f["severity"],
                    host=f["host"],
                    summary=f.get("summary", ""),
                    solution=f.get("solution", ""),
                    cwe="CWE-79",
                    references=f.get("references", []),
                )
                insert_vulnerability_to_database(vuln=vuln, org_name=self.org_name)
                total += 1
        logger.info("Dalfox: inserted %d findings for org %s", total, self.org_name)


# ---------------------------------------------------------------------------
# testssl.sh
# ---------------------------------------------------------------------------

class TestSSLScanner:
    """
    Wraps testssl.sh for TLS/SSL vulnerability detection.

    Produces a JSON file and parses severity HIGH/CRITICAL findings
    into Vulnerability objects.
    """

    TOOL = "testssl"

    # Severities to skip (non-actionable in an automated report)
    SKIP_SEVERITIES = {"ok", "info", "debug"}

    def __init__(self, targets: str, org_name: str):
        self.targets = [t.strip() for t in targets.split(",") if t.strip()]
        self.org_name = org_name

    @staticmethod
    def _testssl_binary() -> str | None:
        """Return the path to testssl.sh or None if not found."""
        for candidate in ("/opt/testssl/testssl.sh", "/usr/local/bin/testssl.sh", "testssl.sh"):
            if os.path.isfile(candidate):
                return candidate
        return None

    def _build_target(self, target: str) -> str:
        """Normalize target to host:port format expected by testssl.sh."""
        target = target.replace("http://", "").replace("https://", "")
        if ":" not in target:
            target = f"{target}:443"
        return target

    def _scan_target(self, target: str) -> list[dict]:
        """Run testssl.sh against one target and return finding dicts."""
        binary = self._testssl_binary()
        if not binary:
            logger.error(
                "testssl.sh not found. Install it: git clone https://github.com/drwetter/testssl.sh /opt/testssl"
            )
            return []

        normalized = self._build_target(target)
        hostname = normalized.split(":")[0]

        with tempfile.NamedTemporaryFile(suffix=".json", prefix="testssl_", delete=False) as tf:
            out_path = tf.name

        cmd = [
            binary,
            "--fast",
            "--warnings", "batch",
            "--jsonfile", out_path,
            normalized,
        ]

        logger.info("testssl.sh: scanning %s", normalized)
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            logger.warning("testssl.sh timed out for %s", normalized)
        except FileNotFoundError:
            logger.error("testssl.sh script not executable or bash not available")
            return []

        findings: list[dict] = []
        if not os.path.exists(out_path):
            return findings

        try:
            with open(out_path) as f:
                raw = json.load(f)

            if not isinstance(raw, list):
                raw = [raw]

            for entry in raw:
                sev_raw = (entry.get("severity") or "").lower()
                if sev_raw in self.SKIP_SEVERITIES:
                    continue
                if not sev_raw:
                    continue

                finding_text = entry.get("finding") or ""
                # Skip "not vulnerable" findings
                if re.search(r"\bnot\b.*\bvulnerable\b|\bnot ok\b", finding_text.lower()) is False:
                    pass  # include
                if "not vulnerable" in finding_text.lower() and sev_raw not in ("high", "critical"):
                    continue

                cve = entry.get("cve") or ""
                cwe = entry.get("cwe") or ""
                ident = entry.get("id") or "testssl-finding"

                findings.append(
                    {
                        "title": f"TLS: {ident.replace('-', ' ').title()}",
                        "host": hostname,
                        "affected_item": f"{normalized}",
                        "summary": finding_text,
                        "severity": _normalize_testssl_severity(sev_raw),
                        "cve": cve,
                        "cwe": cwe,
                        "solution": "Reconfigure TLS settings per best-practice guides (BSI, NIST SP 800-52).",
                        "references": [],
                    }
                )

        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("Could not parse testssl.sh output: %s", exc)
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

        return findings

    def run(self) -> None:
        """Scan all targets and persist findings."""
        total = 0
        for target in self.targets:
            findings = self._scan_target(target)
            for f in findings:
                vuln = Vulnerability(
                    title=f["title"],
                    affected_item=f["affected_item"],
                    tool=self.TOOL,
                    confidence=90,
                    severity=f["severity"],
                    host=f["host"],
                    cve_number=f.get("cve") or "",
                    summary=f.get("summary", ""),
                    solution=f.get("solution", ""),
                    cwe=f.get("cwe", ""),
                    references=f.get("references", []),
                )
                insert_vulnerability_to_database(vuln=vuln, org_name=self.org_name)
                total += 1

        logger.info("testssl.sh: inserted %d findings for org %s", total, self.org_name)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

class ExternalVulnerabilityScanner:
    """
    Dispatcher that routes scanner-name strings to the correct scanner class.

    Used by darkstar.main.worker.run_external_vulnerability_scanner().
    """

    def __init__(self, targets: str, org_name: str):
        self.targets = targets
        self.org_name = org_name

    def run_nikto(self) -> None:
        NiktoScanner(self.targets, self.org_name).run()

    def run_wapiti(self) -> None:
        WapitiScanner(self.targets, self.org_name).run()

    def run_zap(self) -> None:
        ZAPScanner(self.targets, self.org_name).run()

    def run_dalfox(self) -> None:
        DalfoxScanner(self.targets, self.org_name).run()

    def run_testssl(self) -> None:
        TestSSLScanner(self.targets, self.org_name).run()

    # Keep legacy name for backward compatibility with older callers
    def run_sslscan(self) -> None:
        self.run_testssl()
