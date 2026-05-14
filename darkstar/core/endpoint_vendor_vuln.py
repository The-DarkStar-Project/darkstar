"""Vendor and distro-specific endpoint vulnerability matchers.

These matchers deliberately use package-manager identities and vendor release
metadata. They do not fall back to display-name or broad CPE matching.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from .endpoint_vuln import (
    _cvss_score,
    _normalize_vuln_identifier,
    _package_identity_purl,
    hydrate_osv_finding,
    query_osv_cache_results,
)

logger = logging.getLogger(__name__)

DEBIAN_TRACKER_JSON = "https://security-tracker.debian.org/tracker/data/json"
REDHAT_CVE_LIST_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
REDHAT_CVE_DETAIL_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
MSRC_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc_id}"

_DEBIAN_CACHE: dict[str, Any] = {"loaded_at": 0.0, "data": None}
_REDHAT_LIST_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_REDHAT_DETAIL_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_MSRC_UPDATES_CACHE: dict[str, Any] = {"loaded_at": 0.0, "data": None}
_MSRC_DOC_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def _cache_ttl() -> int:
    return 6 * 60 * 60


def _load_json_field(item: dict[str, Any]) -> dict[str, Any]:
    value = item.get("raw_json") or item.get("raw")
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _item_field(item: dict[str, Any], key: str) -> str | None:
    raw = _load_json_field(item)
    value = item.get(key) or raw.get(key)
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _source_from_rpm_filename(value: str | None) -> tuple[str | None, str | None]:
    source = str(value or "").strip()
    if source.endswith(".src.rpm"):
        source = source[:-8]
    if not source or "-" not in source:
        return source or None, None
    name, version, release = source.rsplit("-", 2)
    if not name or not version:
        return source, None
    return name, f"{version}-{release}" if release else version


def _source_package(item: dict[str, Any]) -> str:
    raw = _load_json_field(item)
    source = (
        _item_field(item, "source_package")
        or raw.get("source")
        or item.get("name")
        or ""
    )
    if str(item.get("package_type") or "").lower() == "rpm":
        source_name, _ = _source_from_rpm_filename(str(source))
        return source_name or str(source)
    return str(source)


def _source_version(item: dict[str, Any]) -> str:
    return _item_field(item, "source_version") or str(item.get("version") or "")


def _summary_text(value: Any, fallback: str) -> str:
    if isinstance(value, list):
        value = " ".join(str(part).strip() for part in value if str(part).strip())
    elif isinstance(value, dict):
        value = json.dumps(value, sort_keys=True)
    value = str(value or "").strip()
    return value or fallback


def _codename(os_info: dict[str, Any]) -> str:
    value = (
        os_info.get("codename")
        or os_info.get("version_codename")
        or os_info.get("VERSION_CODENAME")
        or ""
    )
    value = str(value).strip().lower()
    if value:
        return value
    platform_name = _platform(os_info)
    version = str(os_info.get("version") or os_info.get("VERSION_ID") or "")
    major_match = re.search(r"\d+", version)
    major = major_match.group(0) if major_match else ""
    if platform_name == "debian":
        return {
            "9": "stretch",
            "10": "buster",
            "11": "bullseye",
            "12": "bookworm",
            "13": "trixie",
        }.get(major, "")
    if platform_name == "ubuntu":
        ubuntu_versions = {
            "18.04": "bionic",
            "20.04": "focal",
            "22.04": "jammy",
            "24.04": "noble",
        }
        for prefix, codename in ubuntu_versions.items():
            if version.startswith(prefix):
                return codename
    return ""


def _platform(os_info: dict[str, Any]) -> str:
    return str(os_info.get("platform") or os_info.get("id") or "").strip().lower()


def _major_version(os_info: dict[str, Any]) -> str:
    version = str(os_info.get("version") or os_info.get("VERSION_ID") or "").strip()
    match = re.search(r"\d+", version)
    return match.group(0) if match else ""


def _dpkg_lt(installed: str, fixed: str) -> bool:
    if not installed or not fixed:
        return False
    dpkg = shutil.which("dpkg")
    if dpkg:
        try:
            result = subprocess.run(
                [dpkg, "--compare-versions", installed, "lt", fixed],
                capture_output=True,
                timeout=5,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            pass
    return installed < fixed


def _fetch_debian_tracker() -> dict[str, Any]:
    now = time.time()
    if _DEBIAN_CACHE["data"] is not None and now - float(_DEBIAN_CACHE["loaded_at"]) < _cache_ttl():
        return _DEBIAN_CACHE["data"]
    response = requests.get(DEBIAN_TRACKER_JSON, timeout=60)
    response.raise_for_status()
    payload = response.json()
    _DEBIAN_CACHE.update({"loaded_at": now, "data": payload})
    return payload if isinstance(payload, dict) else {}


def _debian_urgency_to_severity(urgency: str | None) -> str:
    value = str(urgency or "").lower()
    if "high" in value:
        return "high"
    if "medium" in value:
        return "medium"
    if "low" in value:
        return "low"
    if "unimportant" in value:
        return "info"
    return "medium"


def _match_debian(software: list[dict[str, Any]], os_info: dict[str, Any]) -> list[dict[str, Any]]:
    release = _codename(os_info)
    if _platform(os_info) != "debian" or not release:
        return []
    packages = [
        item for item in software
        if str(item.get("package_type") or "").lower() == "deb"
    ]
    if not packages:
        return []
    try:
        tracker = _fetch_debian_tracker()
    except Exception as exc:
        logger.warning("Debian Security Tracker lookup failed: %s", exc)
        return []

    findings: list[dict[str, Any]] = []
    for item in packages:
        source = _source_package(item)
        installed = _source_version(item)
        if not source or not installed:
            continue
        for cve, record in (tracker.get(source) or {}).items():
            release_data = (record.get("releases") or {}).get(release)
            if not release_data:
                continue
            status = str(release_data.get("status") or "").lower()
            fixed = str(release_data.get("fixed_version") or "").strip() or None
            vulnerable = False
            confidence = 90
            if status == "resolved" and fixed:
                vulnerable = _dpkg_lt(installed, fixed)
                confidence = 98
            elif status == "open":
                vulnerable = True
                confidence = 92
            if not vulnerable:
                continue
            findings.append({
                "software_key": item["software_key"],
                "cve": cve,
                "source": "DebianSecurityTracker",
                "severity": _debian_urgency_to_severity(release_data.get("urgency")),
                "cvss": None,
                "summary": _summary_text(record.get("description"), f"{cve} affects Debian source package {source}"),
                "fixed_version": fixed,
                "affected_version": installed,
                "purl": item.get("purl"),
                "confidence": confidence,
                "evidence": {
                    "matcher": "debian_security_tracker_source_package",
                    "release": release,
                    "source_package": source,
                    "source_version": installed,
                    "status": status,
                    "urgency": release_data.get("urgency"),
                    "fixed_version": fixed,
                },
            })
    return findings


def _ubuntu_purl(item: dict[str, Any], os_info: dict[str, Any]) -> str | None:
    source = _source_package(item)
    if not source:
        return None
    release = _codename(os_info)
    suffix = f"?arch=source&distro={release}" if release else "?arch=source"
    return f"pkg:deb/ubuntu/{source}{suffix}"


def _match_ubuntu(software: list[dict[str, Any]], os_info: dict[str, Any]) -> list[dict[str, Any]]:
    platform = _platform(os_info)
    if platform != "ubuntu":
        return []
    source_items = []
    for item in software:
        if str(item.get("package_type") or "").lower() != "deb":
            continue
        purl = _ubuntu_purl(item, os_info)
        version = _source_version(item)
        if not purl or not version:
            continue
        source_items.append({
            **item,
            "name": _source_package(item),
            "version": version,
            "purl": purl,
        })
    if not source_items:
        return []
    try:
        results = query_osv_cache_results(source_items)
    except Exception as exc:
        logger.warning("Ubuntu OSV lookup failed: %s", exc)
        return []

    findings = []
    from .endpoint_vuln import osv_cache_key_id, osv_package_key
    for item in source_items:
        key = osv_package_key(item)
        if not key:
            continue
        for finding in results.get(osv_cache_key_id(key), []):
            hydrated = hydrate_osv_finding(item, finding)
            hydrated["source"] = "UbuntuOSV"
            hydrated["confidence"] = 96
            hydrated.setdefault("evidence", {})["matcher"] = "ubuntu_osv_source_package"
            hydrated["evidence"]["source_package"] = item["name"]
            hydrated["evidence"]["query_purl"] = _package_identity_purl(item["purl"])
            findings.append(hydrated)
    return findings


def _split_rpm_evr(value: str) -> tuple[str, str, str]:
    text = str(value or "")
    epoch = "0"
    if ":" in text:
        epoch, text = text.split(":", 1)
    if "-" in text:
        version, release = text.split("-", 1)
    else:
        version, release = text, ""
    return epoch or "0", version, release


def _rpm_segments(value: str) -> list[Any]:
    segments = []
    for segment in re.findall(r"[A-Za-z]+|[0-9]+|~|\^", str(value or "")):
        if segment.isdigit():
            segments.append(int(segment.lstrip("0") or "0"))
        else:
            segments.append(segment)
    return segments


def _rpmvercmp(left: str, right: str) -> int:
    left_segments = _rpm_segments(left)
    right_segments = _rpm_segments(right)
    for left_item, right_item in zip(left_segments, right_segments):
        if left_item == right_item:
            continue
        if left_item == "~":
            return -1
        if right_item == "~":
            return 1
        if isinstance(left_item, int) and isinstance(right_item, str):
            return 1
        if isinstance(left_item, str) and isinstance(right_item, int):
            return -1
        return 1 if left_item > right_item else -1
    if len(left_segments) == len(right_segments):
        return 0
    return 1 if len(left_segments) > len(right_segments) else -1


def _rpm_lt(installed: str, fixed: str) -> bool:
    ie, iv, ir = _split_rpm_evr(installed)
    fe, fv, fr = _split_rpm_evr(fixed)
    for left, right in ((ie, fe), (iv, fv), (ir, fr)):
        result = _rpmvercmp(left, right)
        if result:
            return result < 0
    return False


def _redhat_product(os_info: dict[str, Any]) -> str | None:
    major = _major_version(os_info)
    platform = _platform(os_info)
    if platform in {"rhel", "redhat", "red hat enterprise linux"} and major:
        return f"Red Hat Enterprise Linux {major}"
    if platform in {"rocky", "almalinux", "centos"} and major:
        return f"Red Hat Enterprise Linux {major}"
    return None


def _fetch_redhat_cves(package: str, product: str) -> list[dict[str, Any]]:
    cache_key = f"{product}:{package}"
    now = time.time()
    cached = _REDHAT_LIST_CACHE.get(cache_key)
    if cached and now - cached[0] < _cache_ttl():
        return cached[1]
    response = requests.get(REDHAT_CVE_LIST_URL, params={"package": package, "product": product}, timeout=30)
    response.raise_for_status()
    payload = response.json()
    rows = payload if isinstance(payload, list) else []
    _REDHAT_LIST_CACHE[cache_key] = (now, rows)
    return rows


def _fetch_redhat_detail(cve: str) -> dict[str, Any]:
    now = time.time()
    cached = _REDHAT_DETAIL_CACHE.get(cve)
    if cached and now - cached[0] < _cache_ttl():
        return cached[1]
    response = requests.get(REDHAT_CVE_DETAIL_URL.format(cve=cve), timeout=30)
    response.raise_for_status()
    payload = response.json()
    detail = payload if isinstance(payload, dict) else {}
    _REDHAT_DETAIL_CACHE[cve] = (now, detail)
    return detail


def _redhat_severity(value: str | None) -> str:
    sev = str(value or "").lower()
    if sev == "critical":
        return "critical"
    if sev == "important":
        return "high"
    if sev in {"moderate", "medium"}:
        return "medium"
    if sev == "low":
        return "low"
    return "info"


def _match_redhat(software: list[dict[str, Any]], os_info: dict[str, Any]) -> list[dict[str, Any]]:
    product = _redhat_product(os_info)
    if not product:
        return []
    packages = [
        item for item in software
        if str(item.get("package_type") or "").lower() == "rpm"
    ]
    findings: list[dict[str, Any]] = []
    platform = _platform(os_info)
    confidence = 92 if platform in {"rhel", "redhat", "red hat enterprise linux"} else 82
    for item in packages:
        source = _source_package(item)
        installed = _source_version(item) or str(item.get("version") or "")
        if not source or not installed:
            continue
        try:
            cves = _fetch_redhat_cves(source, product)
        except Exception as exc:
            logger.warning("Red Hat Security Data lookup failed for %s: %s", source, exc)
            continue
        for cve_row in cves:
            cve = cve_row.get("CVE")
            if not cve:
                continue
            try:
                detail = _fetch_redhat_detail(cve)
            except Exception:
                detail = {}
            fixed_version = None
            vulnerable = False
            for release in detail.get("affected_release") or []:
                cpe = str(release.get("cpe") or "")
                package = str(release.get("package") or "")
                if f"enterprise_linux:{_major_version(os_info)}" not in cpe:
                    continue
                if not package.startswith(f"{source}-"):
                    continue
                fixed_version = package[len(source) + 1:]
                vulnerable = _rpm_lt(installed, fixed_version)
                if vulnerable:
                    break
            if not vulnerable:
                for state in detail.get("package_state") or []:
                    if state.get("package_name") != source:
                        continue
                    if str(state.get("product_name") or "") != product:
                        continue
                    if str(state.get("fix_state") or "").lower() in {"affected", "new", "fix deferred"}:
                        vulnerable = True
                        fixed_version = None
                        break
            if not vulnerable:
                continue
            findings.append({
                "software_key": item["software_key"],
                "cve": cve,
                "source": "RedHatSecurityData",
                "severity": _redhat_severity(detail.get("threat_severity") or cve_row.get("severity")),
                "cvss": _cvss_score([{"score": (detail.get("cvss3") or {}).get("cvss3_scoring_vector")}]),
                "summary": _summary_text(detail.get("details"), f"{cve} affects {product} source package {source}"),
                "fixed_version": fixed_version,
                "affected_version": installed,
                "purl": item.get("purl"),
                "confidence": confidence,
                "evidence": {
                    "matcher": "redhat_security_data_source_package",
                    "product": product,
                    "platform": platform,
                    "source_package": source,
                    "source_version": installed,
                    "fixed_version": fixed_version,
                    "api": "Red Hat Security Data API",
                },
            })
    return findings


def match_vendor_vulnerabilities(software: list[dict[str, Any]], os_info: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    os_info = os_info or {}
    findings: list[dict[str, Any]] = []
    findings.extend(_match_debian(software, os_info))
    findings.extend(_match_ubuntu(software, os_info))
    findings.extend(_match_redhat(software, os_info))

    deduped = {}
    for finding in findings:
        key = (
            finding.get("software_key"),
            finding.get("cve"),
            finding.get("source"),
        )
        deduped[key] = finding
    return list(deduped.values())
