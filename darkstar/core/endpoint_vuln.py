"""Strict endpoint vulnerability matching helpers.

The endpoint matcher intentionally starts narrow: it only creates findings when
an installed package has a strong Package URL identity and OSV confirms the
exact package/version is affected. Name-only and broad CPE fallback matching are
not used because they create high-impact false positives across platforms.
"""

from __future__ import annotations

import logging
import hashlib
import math
import re
from typing import Any

import requests

logger = logging.getLogger(__name__)


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _package_identity_purl(purl: str) -> str:
    """Return PURL package identity without the installed version component."""
    value = str(purl or "").strip()
    if not value:
        return value
    base, marker, rest = value.partition("?")
    if "@" in base:
        base = base.rsplit("@", 1)[0]
    return f"{base}{marker}{rest}" if marker else base


def osv_package_key(item: dict[str, Any]) -> dict[str, str] | None:
    """Return the stable OSV cache key for one software item."""
    if not item.get("purl") or not item.get("version") or not item.get("software_key"):
        return None
    identity = _package_identity_purl(item["purl"])
    if not identity:
        return None
    return {
        "package_identity": identity,
        "package_hash": hashlib.sha256(identity.lower().encode("utf-8")).hexdigest(),
        "version": str(item["version"]),
        "source": "OSV",
    }


def osv_cache_key_id(key: dict[str, Any]) -> str:
    return f"{key.get('source') or 'OSV'}:{key.get('package_hash')}:{key.get('version')}"


def _cvss_score(severity: list[dict[str, Any]] | None) -> float | None:
    if not severity:
        return None
    scores = []
    for item in severity:
        score = item.get("score")
        if not score:
            continue
        try:
            # OSV usually provides a vector string; the numeric score is not
            # guaranteed. Keep this conservative instead of parsing vectors by
            # hand.
            scores.append(float(score))
        except (TypeError, ValueError):
            parsed = _cvss3_vector_score(str(score))
            if parsed is not None:
                scores.append(parsed)
    return max(scores) if scores else None


def _round_up_1(value: float) -> float:
    return math.ceil(value * 10) / 10.0


def _cvss3_vector_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3."):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        key, sep, value = part.partition(":")
        if sep:
            metrics[key] = value
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        scope_changed = metrics["S"] == "C"
        pr = (
            {"N": 0.85, "L": 0.68, "H": 0.50}
            if scope_changed
            else {"N": 0.85, "L": 0.62, "H": 0.27}
        )[metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
        c = impact_values[metrics["C"]]
        i = impact_values[metrics["I"]]
        a = impact_values[metrics["A"]]
    except KeyError:
        return None

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = (
        7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        if scope_changed
        else 6.42 * isc_base
    )
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _round_up_1(min(1.08 * (impact + exploitability), 10))
    return _round_up_1(min(impact + exploitability, 10))


def _severity_from_osv(vuln: dict[str, Any]) -> str:
    database_specific = vuln.get("database_specific") or {}
    severity = str(database_specific.get("severity") or "").lower()
    if severity in {"critical", "high", "medium", "low"}:
        return severity
    cvss = _cvss_score(vuln.get("severity"))
    if cvss is None:
        return "info"
    if cvss >= 9:
        return "critical"
    if cvss >= 7:
        return "high"
    if cvss >= 4:
        return "medium"
    return "low"


def _normalize_vuln_identifier(value: Any) -> str:
    identifier = str(value or "OSV-UNKNOWN")
    match = CVE_RE.search(identifier)
    return match.group(0).upper() if match else identifier


def _finding_id(vuln: dict[str, Any]) -> str:
    aliases = [str(alias) for alias in vuln.get("aliases") or []]
    cves = [_normalize_vuln_identifier(alias) for alias in aliases if CVE_RE.search(alias)]
    return cves[0] if cves else _normalize_vuln_identifier(vuln.get("id") or "OSV-UNKNOWN")


def _fixed_version_from_osv(vuln: dict[str, Any]) -> str | None:
    for affected in vuln.get("affected") or []:
        for item in affected.get("ranges") or []:
            for event in item.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])
    return None


def _generic_osv_finding(vuln: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": _finding_id(vuln),
        "source": "OSV",
        "severity": _severity_from_osv(vuln),
        "cvss": _cvss_score(vuln.get("severity")),
        "summary": vuln.get("summary") or vuln.get("details"),
        "fixed_version": _fixed_version_from_osv(vuln),
        "confidence": 95,
        "evidence": {
            "matcher": "osv_purl_exact_version",
            "osv_id": vuln.get("id"),
            "aliases": vuln.get("aliases") or [],
            "modified": vuln.get("modified"),
            "published": vuln.get("published"),
        },
    }


def hydrate_osv_finding(item: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    hydrated = dict(finding or {})
    evidence = dict(hydrated.get("evidence") or {})
    evidence["package"] = {
        "name": item.get("name"),
        "version": item.get("version"),
        "ecosystem": item.get("ecosystem"),
        "purl": item.get("purl"),
        "query_purl": _package_identity_purl(item.get("purl")),
    }
    hydrated.update({
        "software_key": item["software_key"],
        "cve": _normalize_vuln_identifier(hydrated.get("cve") or hydrated.get("id")),
        "affected_version": item.get("version"),
        "purl": item.get("purl"),
        "confidence": int(hydrated.get("confidence") or 95),
        "evidence": evidence,
    })
    return hydrated


def _query_osv_package(item: dict[str, Any], timeout: int) -> list[dict[str, Any]] | None:
    """Fetch full OSV vulnerability records for one matched package/version."""
    try:
        response = requests.post(
            OSV_QUERY_URL,
            json={
                "package": {"purl": _package_identity_purl(item["purl"])},
                "version": str(item["version"]),
            },
            timeout=min(timeout, 20),
        )
        response.raise_for_status()
        vulns = response.json().get("vulns") or []
        return vulns if isinstance(vulns, list) else []
    except Exception as exc:
        logger.debug("OSV package detail lookup failed for %s: %s", item.get("purl"), exc)
        return None


def query_osv_cache_results(software_items: list[dict[str, Any]], timeout: int = 30) -> dict[str, list[dict[str, Any]]]:
    """Return generic OSV findings keyed by package identity/version cache id."""
    representatives: dict[str, dict[str, Any]] = {}
    for item in software_items or []:
        key = osv_package_key(item)
        if not key:
            continue
        cache_id = osv_cache_key_id(key)
        representatives.setdefault(cache_id, {**item, "_osv_key": key})
    if not representatives:
        return {}

    items = list(representatives.values())
    results_by_key: dict[str, list[dict[str, Any]]] = {}
    for start in range(0, len(items), 100):
        chunk = items[start:start + 100]
        payload = {
            "queries": [
                {
                    "package": {"purl": item["_osv_key"]["package_identity"]},
                    "version": item["_osv_key"]["version"],
                }
                for item in chunk
            ]
        }
        try:
            response = requests.post(OSV_BATCH_URL, json=payload, timeout=timeout)
            response.raise_for_status()
            results = response.json().get("results") or []
        except Exception as exc:
            logger.warning("OSV endpoint matching failed: %s", exc)
            return results_by_key

        for item, result in zip(chunk, results):
            cache_id = osv_cache_key_id(item["_osv_key"])
            vuln_refs = result.get("vulns") or []
            if not vuln_refs:
                results_by_key[cache_id] = []
                continue
            vulns = _query_osv_package(item, timeout) or vuln_refs
            results_by_key[cache_id] = [_generic_osv_finding(vuln) for vuln in vulns]
    return results_by_key


def match_osv_vulnerabilities(software_items: list[dict[str, Any]], timeout: int = 30) -> list[dict[str, Any]]:
    """Return OSV findings for packages with exact PURL identity.

    Packages without PURL are deliberately ignored. That means products such as
    Windows desktop apps require a Microsoft/vendor matcher before they can
    create endpoint CVEs.
    """
    candidates = [
        item for item in software_items
        if item.get("purl") and item.get("version") and item.get("software_key")
    ]
    if not candidates:
        return []

    findings: list[dict[str, Any]] = []
    cached = query_osv_cache_results(candidates, timeout=timeout)
    for item in candidates:
        key = osv_package_key(item)
        if not key:
            continue
        for finding in cached.get(osv_cache_key_id(key), []):
            findings.append(hydrate_osv_finding(item, finding))
    return findings
