"""Vendor and distro-specific endpoint vulnerability matchers.

These matchers deliberately use package-manager identities and vendor release
metadata. They do not fall back to display-name or broad CPE matching.
"""

from __future__ import annotations

import json
import logging
import os
import re
import hashlib
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from functools import cache
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
_DPKG_COMPARE_CACHE: dict[tuple[str, str], bool] = {}
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


def _strip_markup(value: str | None) -> str:
    output: list[str] = []
    in_tag = False
    for character in str(value or ""):
        if character == "<":
            in_tag = True
            output.append(" ")
            continue
        if character == ">":
            in_tag = False
            output.append(" ")
            continue
        if not in_tag:
            output.append(character)
    return " ".join("".join(output).split())


def _numeric_version_parts(value: str | None) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", str(value or "")))


def _version_like(value: str | None) -> bool:
    text = str(value or "").strip()
    if len(text) > 128:
        return False
    parts = text.split(".")
    if not 2 <= len(parts) <= 6:
        return False
    return all(part.isdigit() for part in parts)


def _version_lt(left: str | None, right: str | None) -> bool:
    left_parts = _numeric_version_parts(left)
    right_parts = _numeric_version_parts(right)
    if not left_parts or not right_parts:
        return False
    width = max(len(left_parts), len(right_parts))
    left_parts = left_parts + (0,) * (width - len(left_parts))
    right_parts = right_parts + (0,) * (width - len(right_parts))
    return left_parts < right_parts


def _max_version(values: list[str]) -> str | None:
    clean = [value for value in values if _version_like(value)]
    if not clean:
        return None
    return max(clean, key=_numeric_version_parts)


@cache
def _apt_pkg_module() -> Any | None:
    try:
        import apt_pkg  # type: ignore

        apt_pkg.init_system()
        return apt_pkg
    except Exception:
        return None


def _is_windows_os(os_info: dict[str, Any]) -> bool:
    platform_name = _platform(os_info)
    name = str(os_info.get("name") or os_info.get("product_name") or "").lower()
    return platform_name.startswith("win") or "windows" in name


def _windows_build(os_info: dict[str, Any]) -> str | None:
    build = (
        os_info.get("build")
        or os_info.get("os_build")
        or os_info.get("build_number")
        or os_info.get("CurrentBuildNumber")
    )
    ubr = os_info.get("ubr") or os_info.get("UBR")
    if not build:
        return None
    text = str(build).strip()
    if text.count(".") >= 2:
        return text
    parts = ["10", "0", text]
    if ubr not in (None, ""):
        parts.append(str(ubr).strip())
    return ".".join(parts)


def _windows_build_number(os_info: dict[str, Any]) -> int | None:
    build = _windows_build(os_info)
    parts = _numeric_version_parts(build)
    return parts[2] if len(parts) >= 3 else None


def _windows_release_from_build(os_info: dict[str, Any]) -> str:
    explicit = str(os_info.get("display_version") or os_info.get("release_id") or os_info.get("version") or "").upper()
    match = re.search(r"\b\d{2}H[12]\b", explicit)
    if match:
        return match.group(0)
    build = _windows_build_number(os_info)
    return {
        14393: "1607",
        17763: "1809",
        19044: "21H2",
        19045: "22H2",
        20348: "2022",
        22000: "21H2",
        22621: "22H2",
        22631: "23H2",
        26100: "24H2",
    }.get(build, "")


def _windows_arch_matches(product_name: str, os_info: dict[str, Any]) -> bool:
    product = product_name.lower()
    arch = str(os_info.get("arch") or os_info.get("architecture") or "").lower()
    if "arm64" in product:
        return "arm64" in arch or "aarch64" in arch
    if "x64-based" in product or "64-bit" in product:
        return arch in {"amd64", "x86_64", "x64", "64-bit"} or "64" in arch
    if "32-bit" in product or "x86-based" in product:
        return arch in {"x86", "i386", "i686", "32-bit"} or "86" in arch
    return True


def _windows_name_matches(product_name: str, os_info: dict[str, Any]) -> bool:
    product = product_name.lower()
    os_name = str(os_info.get("name") or os_info.get("product_name") or "").lower()
    build = _windows_build_number(os_info)
    release = _windows_release_from_build(os_info).upper()
    is_server = "server" in os_name or str(os_info.get("installation_type") or "").lower() in {"server", "server core"}
    product_is_server = "windows server" in product
    if product_is_server != is_server:
        return False
    if "server core installation" in product:
        if "core" not in str(os_info.get("installation_type") or os_name).lower():
            return False
    elif is_server and "core" in str(os_info.get("installation_type") or os_name).lower():
        return False
    if product_is_server:
        server_builds = {
            "2012 r2": 9600,
            "2016": 14393,
            "2019": 17763,
            "2022": 20348,
            "2025": 26100,
        }
        for label, expected_build in server_builds.items():
            if label in product:
                return label in os_name or build == expected_build or release == label.upper()
        return "windows server" in os_name
    if "windows 11" in product:
        if "windows 11" not in os_name and not (build and build >= 22000):
            return False
    elif "windows 10" in product:
        if "windows 10" not in os_name and not (build and 10240 <= build < 22000):
            return False
    else:
        return False
    version_match = re.search(r"version\s+([0-9]{2}h[12])", product, flags=re.IGNORECASE)
    if version_match and release != version_match.group(1).upper():
        return False
    return True


def _windows_system_product_match(product_name: str, os_info: dict[str, Any]) -> bool:
    product = product_name.strip()
    lowered = product.lower()
    if any(marker in lowered for marker in (" for ios", " for android", " for mac", " on mac")):
        return False
    if lowered.startswith("windows "):
        return _windows_arch_matches(product, os_info) and _windows_name_matches(product, os_info)
    if lowered.startswith("microsoft .net framework") and " on windows " in lowered:
        _, _, windows_part = product.partition(" on ")
        return _windows_arch_matches(windows_part, os_info) and _windows_name_matches(windows_part, os_info)
    return False


def _windows_os_inventory_item(software: list[dict[str, Any]], os_info: dict[str, Any]) -> dict[str, Any] | None:
    for item in software or []:
        if str(item.get("package_type") or "").lower() == "windows_os":
            return item
    if not _is_windows_os(os_info):
        return None
    build = _windows_build(os_info) or str(os_info.get("version") or "")
    if not build:
        return None
    key_seed = f"windows_os:{os_info.get('name')}:{build}:{os_info.get('arch')}"
    return {
        "software_key": hashlib.sha256(key_seed.lower().encode("utf-8")).hexdigest()[:40],
        "name": os_info.get("name") or "Microsoft Windows",
        "version": build,
        "vendor": "Microsoft",
        "ecosystem": "windows_os",
        "package_type": "windows_os",
        "purl": None,
    }


def _installed_windows_kbs(software: list[dict[str, Any]]) -> set[str]:
    kbs: set[str] = set()
    for item in software or []:
        if str(item.get("package_type") or "").lower() != "windows_kb":
            continue
        raw = _load_json_field(item)
        values = [item.get("name"), item.get("version"), raw.get("hotfix_id"), raw.get("caption")]
        for value in values:
            for match in re.findall(r"KB\s*(\d{5,8})", str(value or ""), flags=re.IGNORECASE):
                kbs.add(match)
    return kbs


def _dpkg_lt(installed: str, fixed: str) -> bool:
    if not installed or not fixed:
        return False
    cache_key = (installed, fixed)
    if cache_key in _DPKG_COMPARE_CACHE:
        return _DPKG_COMPARE_CACHE[cache_key]
    apt_pkg = _apt_pkg_module()
    if apt_pkg is not None:
        result = apt_pkg.version_compare(installed, fixed) < 0
        _DPKG_COMPARE_CACHE[cache_key] = result
        return result
    dpkg = shutil.which("dpkg")
    if dpkg:
        try:
            result = subprocess.run(
                [dpkg, "--compare-versions", installed, "lt", fixed],
                capture_output=True,
                timeout=5,
                check=False,
            )
            comparison = result.returncode == 0
            _DPKG_COMPARE_CACHE[cache_key] = comparison
            return comparison
        except Exception as exc:
            logger.debug("dpkg version comparison failed, using string fallback: %s", exc)
    comparison = installed < fixed
    _DPKG_COMPARE_CACHE[cache_key] = comparison
    return comparison


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


MSRC_NS = {
    "prod": "http://www.icasi.org/CVRF/schema/prod/1.1",
    "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1",
}


def _msrc_severity(value: str | None) -> str:
    severity = str(value or "").strip().lower()
    if severity == "critical":
        return "critical"
    if severity in {"important", "high"}:
        return "high"
    if severity in {"moderate", "medium"}:
        return "medium"
    if severity == "low":
        return "low"
    return "info"


def _msrc_child_text(element: ET.Element, child_name: str) -> str | None:
    child = element.find(f"vuln:{child_name}", MSRC_NS)
    if child is None:
        return None
    text = "".join(child.itertext()).strip()
    return text or None


def _msrc_product_ids(element: ET.Element) -> list[str]:
    return [
        str(child.text).strip()
        for child in element.findall("vuln:ProductID", MSRC_NS)
        if str(child.text or "").strip()
    ]


def _fetch_msrc_updates() -> list[dict[str, Any]]:
    now = time.time()
    if _MSRC_UPDATES_CACHE["data"] is not None and now - float(_MSRC_UPDATES_CACHE["loaded_at"]) < _cache_ttl():
        return _MSRC_UPDATES_CACHE["data"]
    response = requests.get(MSRC_UPDATES_URL, timeout=30)
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("value") if isinstance(payload, dict) else []
    rows = rows if isinstance(rows, list) else []
    _MSRC_UPDATES_CACHE.update({"loaded_at": now, "data": rows})
    return rows


def _parse_msrc_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _msrc_document_ids() -> list[str]:
    lookback_months = max(1, min(int(os.environ.get("ENDPOINT_MSRC_LOOKBACK_MONTHS", "18")), 36))
    max_docs = max(1, min(int(os.environ.get("ENDPOINT_MSRC_MAX_DOCS", str(lookback_months))), 36))
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_months * 31)
    try:
        updates = _fetch_msrc_updates()
    except Exception as exc:
        logger.warning("MSRC update index lookup failed: %s", exc)
        now = datetime.now(timezone.utc)
        return [now.strftime("%Y-%b")]

    selected: list[tuple[datetime, str]] = []
    for row in updates:
        doc_id = str(row.get("ID") or row.get("Alias") or "").strip()
        if not re.fullmatch(r"\d{4}-[A-Z][a-z]{2}", doc_id):
            continue
        release_date = _parse_msrc_date(row.get("InitialReleaseDate")) or _parse_msrc_date(row.get("CurrentReleaseDate"))
        if not release_date or release_date < cutoff:
            continue
        selected.append((release_date, doc_id))
    selected.sort(reverse=True)
    return [doc_id for _, doc_id in selected[:max_docs]]


def _parse_msrc_document(doc_id: str, xml_text: str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    products = {
        str(full.attrib.get("ProductID") or "").strip(): "".join(full.itertext()).strip()
        for full in root.findall(".//prod:FullProductName", MSRC_NS)
        if str(full.attrib.get("ProductID") or "").strip()
    }
    records: list[dict[str, Any]] = []
    for vuln in root.findall(".//vuln:Vulnerability", MSRC_NS):
        cve = _normalize_vuln_identifier(vuln.findtext("vuln:CVE", default="", namespaces=MSRC_NS))
        if not cve:
            continue
        title = _strip_markup(vuln.findtext("vuln:Title", default="", namespaces=MSRC_NS))
        description = ""
        tags: list[str] = []
        for note in vuln.findall("vuln:Notes/vuln:Note", MSRC_NS):
            note_type = str(note.attrib.get("Type") or note.attrib.get("Title") or "").lower()
            text = _strip_markup("".join(note.itertext()))
            if note_type == "description" and not description:
                description = text
            elif note_type == "tag" and text:
                tags.append(text)

        affected_ids: set[str] = set()
        for status in vuln.findall("vuln:ProductStatuses/vuln:Status", MSRC_NS):
            if str(status.attrib.get("Type") or "").lower() == "known affected":
                affected_ids.update(_msrc_product_ids(status))
        if not affected_ids:
            continue

        severities: dict[str, str] = {}
        impacts: dict[str, str] = {}
        exploit_status = ""
        for threat in vuln.findall("vuln:Threats/vuln:Threat", MSRC_NS):
            threat_type = str(threat.attrib.get("Type") or "").lower()
            description_text = _strip_markup(_msrc_child_text(threat, "Description"))
            pids = _msrc_product_ids(threat) or list(affected_ids)
            if threat_type == "severity":
                for pid in pids:
                    severities[pid] = description_text
            elif threat_type == "impact":
                for pid in pids:
                    impacts[pid] = description_text
            elif threat_type == "exploit status" and description_text:
                exploit_status = description_text

        cvss_by_pid: dict[str, float] = {}
        for score_set in vuln.findall("vuln:CVSSScoreSets/vuln:ScoreSet", MSRC_NS):
            score_text = _msrc_child_text(score_set, "BaseScore")
            try:
                score = float(score_text) if score_text else None
            except ValueError:
                score = None
            if score is None:
                continue
            for pid in _msrc_product_ids(score_set) or list(affected_ids):
                cvss_by_pid[pid] = score

        remediations: dict[str, list[dict[str, Any]]] = {pid: [] for pid in affected_ids}
        for remediation in vuln.findall("vuln:Remediations/vuln:Remediation", MSRC_NS):
            rem_type = str(remediation.attrib.get("Type") or "").strip()
            if rem_type.lower() not in {"vendor fix", "known issue", "release notes"}:
                continue
            pids = [pid for pid in _msrc_product_ids(remediation) if pid in affected_ids]
            if not pids:
                continue
            row = {
                "type": rem_type,
                "description": _strip_markup(_msrc_child_text(remediation, "Description")),
                "url": _msrc_child_text(remediation, "URL"),
                "fixed_build": _strip_markup(_msrc_child_text(remediation, "FixedBuild")),
                "subtype": _strip_markup(_msrc_child_text(remediation, "SubType")),
                "supercedence": _strip_markup(_msrc_child_text(remediation, "Supercedence")),
                "restart_required": _strip_markup(_msrc_child_text(remediation, "RestartRequired")),
            }
            for pid in pids:
                remediations.setdefault(pid, []).append(row)

        for pid in affected_ids:
            product_name = products.get(pid)
            if not product_name:
                continue
            records.append({
                "doc_id": doc_id,
                "product_id": pid,
                "product_name": product_name,
                "cve": cve,
                "title": title,
                "summary": description or title or f"{cve} affects {product_name}",
                "severity": _msrc_severity(severities.get(pid)),
                "impact": impacts.get(pid),
                "cvss": cvss_by_pid.get(pid),
                "exploit_status": exploit_status,
                "tags": tags,
                "remediations": remediations.get(pid) or [],
            })
    return records


def _fetch_one_msrc_document(doc_id: str) -> list[dict[str, Any]]:
    now = time.time()
    cached = _MSRC_DOC_CACHE.get(doc_id)
    if cached and now - cached[0] < _cache_ttl():
        return cached[1]
    response = requests.get(MSRC_CVRF_URL.format(doc_id=doc_id), timeout=60)
    response.raise_for_status()
    parsed = _parse_msrc_document(doc_id, response.text)
    _MSRC_DOC_CACHE[doc_id] = (now, parsed)
    return parsed


def _fetch_msrc_records() -> list[dict[str, Any]]:
    doc_ids = _msrc_document_ids()
    if not doc_ids:
        return []
    records: list[dict[str, Any]] = []
    workers = max(1, min(int(os.environ.get("ENDPOINT_MSRC_FETCH_WORKERS", "6")), 12))
    with ThreadPoolExecutor(max_workers=min(workers, len(doc_ids))) as executor:
        future_map = {executor.submit(_fetch_one_msrc_document, doc_id): doc_id for doc_id in doc_ids}
        for future in as_completed(future_map):
            doc_id = future_map[future]
            try:
                records.extend(future.result())
            except Exception as exc:
                logger.warning("MSRC CVRF lookup failed for %s: %s", doc_id, exc)
    return records


def _msrc_vendor_fixes(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        remediation for remediation in record.get("remediations") or []
        if str(remediation.get("type") or "").lower() == "vendor fix"
    ]


def _msrc_kb_ids(remediations: list[dict[str, Any]]) -> set[str]:
    kbs: set[str] = set()
    for remediation in remediations:
        for field in ("description", "url"):
            for match in re.findall(r"KB?\s*(\d{5,8})", str(remediation.get(field) or ""), flags=re.IGNORECASE):
                kbs.add(match)
    return kbs


def _best_fixed_build(remediations: list[dict[str, Any]]) -> str | None:
    normal_builds = [
        str(remediation.get("fixed_build") or "")
        for remediation in remediations
        if _version_like(remediation.get("fixed_build"))
        and "hotpatch" not in str(remediation.get("subtype") or "").lower()
    ]
    if normal_builds:
        return _max_version(normal_builds)
    return _max_version([
        str(remediation.get("fixed_build") or "")
        for remediation in remediations
        if _version_like(remediation.get("fixed_build"))
    ])


def _microsoft_publisher(item: dict[str, Any]) -> bool:
    vendor = str(item.get("vendor") or "").lower()
    raw = _load_json_field(item)
    publisher = str(raw.get("publisher") or raw.get("Publisher") or "").lower()
    name = str(item.get("name") or "").lower()
    return "microsoft" in vendor or "microsoft" in publisher or name.startswith(("microsoft ", ".net", "dotnet"))


def _msrc_windows_app_match(product_name: str, item: dict[str, Any]) -> bool:
    product = product_name.lower()
    name = str(item.get("name") or "").lower()
    version = str(item.get("version") or "")
    if not _microsoft_publisher(item):
        return False
    if any(marker in product for marker in (" for ios", " for android", " for mac", " on mac")):
        return False
    if product.startswith(".net ") and "installed on windows" in product:
        match = re.search(r"\.net\s+(\d+\.\d+)", product)
        return bool(match and (".net" in name or "dotnet" in name) and version.startswith(match.group(1)))
    if "microsoft visual studio" in product:
        product_match = re.search(r"visual studio\s+(20\d{2})\s+version\s+(\d+(?:\.\d+)?)", product)
        if not product_match:
            return False
        year, product_version = product_match.groups()
        return "visual studio" in name and year in name and version.startswith(product_version)
    if product.startswith("microsoft edge"):
        return "microsoft edge" in name
    return False


def _match_windows_msrc(software: list[dict[str, Any]], os_info: dict[str, Any]) -> list[dict[str, Any]]:
    if not _is_windows_os(os_info):
        return []
    try:
        records = _fetch_msrc_records()
    except Exception as exc:
        logger.warning("MSRC matcher failed: %s", exc)
        return []

    findings: list[dict[str, Any]] = []
    os_item = _windows_os_inventory_item(software, os_info)
    installed_build = _windows_build(os_info)
    installed_kbs = _installed_windows_kbs(software)
    for record in records:
        product_name = str(record.get("product_name") or "")
        vendor_fixes = _msrc_vendor_fixes(record)
        fixed_build = _best_fixed_build(vendor_fixes)
        if os_item and fixed_build and _windows_system_product_match(product_name, os_info):
            kb_ids = _msrc_kb_ids(vendor_fixes)
            if installed_kbs.intersection(kb_ids):
                continue
            if not installed_build or not _version_lt(installed_build, fixed_build):
                continue
            findings.append({
                "software_key": os_item["software_key"],
                "cve": record["cve"],
                "source": "MSRC",
                "severity": record.get("severity"),
                "cvss": record.get("cvss"),
                "summary": record.get("summary"),
                "fixed_version": fixed_build,
                "affected_version": installed_build,
                "purl": os_item.get("purl"),
                "confidence": 96,
                "evidence": {
                    "matcher": "msrc_windows_product_fixed_build",
                    "doc_id": record.get("doc_id"),
                    "product_id": record.get("product_id"),
                    "product_name": product_name,
                    "installed_build": installed_build,
                    "fixed_build": fixed_build,
                    "kb_ids": sorted(kb_ids),
                    "installed_kb_match": sorted(installed_kbs.intersection(kb_ids)),
                    "impact": record.get("impact"),
                    "exploit_status": record.get("exploit_status"),
                    "tags": record.get("tags") or [],
                    "api": "MSRC CVRF API",
                },
            })

        if not vendor_fixes:
            continue
        app_fixed = _best_fixed_build(vendor_fixes)
        if not app_fixed:
            continue
        for item in software or []:
            if str(item.get("package_type") or "").lower() != "windows_program":
                continue
            installed_version = str(item.get("version") or "")
            if not installed_version or not _version_like(installed_version):
                continue
            if not _msrc_windows_app_match(product_name, item):
                continue
            if not _version_lt(installed_version, app_fixed):
                continue
            findings.append({
                "software_key": item["software_key"],
                "cve": record["cve"],
                "source": "MSRC",
                "severity": record.get("severity"),
                "cvss": record.get("cvss"),
                "summary": record.get("summary"),
                "fixed_version": app_fixed,
                "affected_version": installed_version,
                "purl": item.get("purl"),
                "confidence": 90,
                "evidence": {
                    "matcher": "msrc_windows_app_fixed_build",
                    "doc_id": record.get("doc_id"),
                    "product_id": record.get("product_id"),
                    "product_name": product_name,
                    "software_name": item.get("name"),
                    "installed_version": installed_version,
                    "fixed_build": app_fixed,
                    "kb_ids": sorted(_msrc_kb_ids(vendor_fixes)),
                    "impact": record.get("impact"),
                    "exploit_status": record.get("exploit_status"),
                    "tags": record.get("tags") or [],
                    "api": "MSRC CVRF API",
                },
            })
    return findings


def match_vendor_vulnerabilities(software: list[dict[str, Any]], os_info: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    os_info = os_info or {}
    findings: list[dict[str, Any]] = []
    findings.extend(_match_debian(software, os_info))
    findings.extend(_match_ubuntu(software, os_info))
    findings.extend(_match_redhat(software, os_info))
    findings.extend(_match_windows_msrc(software, os_info))

    deduped = {}
    for finding in findings:
        key = (
            finding.get("software_key"),
            finding.get("cve"),
            finding.get("source"),
        )
        deduped[key] = finding
    return list(deduped.values())
