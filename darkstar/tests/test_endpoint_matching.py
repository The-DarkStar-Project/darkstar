import json
import textwrap

import pytest

from darkstar.core import endpoint_vendor_vuln as vendor
from darkstar.core.endpoint_custom_checks import (
    POSTURE_SOFTWARE_KEY,
    match_custom_vulnerabilities,
)
from darkstar.core.endpoint_vuln import (
    _cvss3_vector_score,
    hydrate_osv_finding,
    osv_cache_key_id,
    osv_package_key,
)


pytestmark = pytest.mark.unit


def test_osv_package_key_strips_purl_version_but_keeps_qualifiers():
    item = {
        "software_key": "pkg-1",
        "purl": "pkg:pypi/django@4.2.0?arch=x86_64",
        "version": "4.2.0",
    }

    key = osv_package_key(item)

    assert key == {
        "package_identity": "pkg:pypi/django?arch=x86_64",
        "package_hash": key["package_hash"],
        "version": "4.2.0",
        "source": "OSV",
    }
    assert osv_cache_key_id(key).startswith("OSV:")
    assert osv_cache_key_id(key).endswith(":4.2.0")


def test_hydrate_osv_finding_adds_package_evidence_and_normalizes_cve():
    item = {
        "software_key": "pkg-1",
        "name": "Django",
        "version": "4.2.0",
        "ecosystem": "PyPI",
        "purl": "pkg:pypi/django@4.2.0",
    }

    finding = hydrate_osv_finding(
        item,
        {
            "id": "GHSA-test",
            "cve": "cve-2026-12345",
            "source": "OSV",
            "evidence": {"aliases": ["GHSA-test"]},
        },
    )

    assert finding["software_key"] == "pkg-1"
    assert finding["cve"] == "CVE-2026-12345"
    assert finding["affected_version"] == "4.2.0"
    assert finding["evidence"]["package"]["query_purl"] == "pkg:pypi/django"


def test_cvss3_vector_score_handles_common_high_vector():
    assert _cvss3_vector_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert _cvss3_vector_score("not-a-vector") is None


def test_custom_posture_checks_create_non_cve_findings():
    findings = match_custom_vulnerabilities(
        [
            {
                "software_key": POSTURE_SOFTWARE_KEY,
                "package_type": "security_posture",
                "version": "1",
                "raw": {
                    "platform": "linux",
                    "collected_at": "2026-05-15T10:00:00Z",
                    "security_checks": [
                        {
                            "id": "DARKSTAR-LINUX-SSH-ROOT-LOGIN",
                            "passed": False,
                            "confidence": 91,
                            "evidence": {"effective_value": "yes"},
                        },
                        {"id": "DARKSTAR-UNKNOWN-CHECK", "passed": False},
                    ],
                },
            }
        ],
        os_info={"platform": "linux"},
    )

    assert len(findings) == 1
    assert findings[0]["cve"] == "DARKSTAR-LINUX-SSH-ROOT-LOGIN"
    assert findings[0]["source"] == "DarkstarCheck"
    assert findings[0]["severity"] == "high"
    assert findings[0]["confidence"] == 91
    assert findings[0]["evidence"]["agent_evidence"] == {"effective_value": "yes"}


def test_custom_posture_checks_read_stored_raw_json():
    raw_json = json.dumps({
        "raw": {
            "platform": "windows",
            "security_checks": [
                {"id": "DARKSTAR-WINDOWS-ALWAYS-INSTALL-ELEVATED", "passed": False}
            ],
        }
    })

    findings = match_custom_vulnerabilities(
        [{"software_key": POSTURE_SOFTWARE_KEY, "package_type": "security_posture", "raw_json": raw_json}],
        os_info={"platform": "windows"},
    )

    assert [finding["cve"] for finding in findings] == ["DARKSTAR-WINDOWS-ALWAYS-INSTALL-ELEVATED"]


def test_vendor_version_like_rejects_unbounded_numeric_input():
    assert vendor._version_like("10.0.22631.4000")
    assert not vendor._version_like("0" * 129)
    assert not vendor._version_like("1.2.3.4.5.6.7")
    assert not vendor._version_like("1.two")


def test_windows_build_and_release_detection():
    os_info = {
        "platform": "windows",
        "name": "Microsoft Windows 11 Pro",
        "build": "22631",
        "ubr": "3593",
        "arch": "x64",
    }

    assert vendor._windows_build(os_info) == "10.0.22631.3593"
    assert vendor._windows_build_number(os_info) == 22631
    assert vendor._windows_release_from_build(os_info) == "23H2"
    assert vendor._windows_system_product_match("Windows 11 Version 23H2 for x64-based Systems", os_info)
    assert not vendor._windows_system_product_match("Windows 10 Version 22H2 for x64-based Systems", os_info)


def test_dpkg_version_compare_caches_fallback_result(monkeypatch):
    monkeypatch.setattr(vendor, "_APT_PKG_INIT_ATTEMPTED", True)
    monkeypatch.setattr(vendor, "_APT_PKG", None)
    monkeypatch.setattr(vendor.shutil, "which", lambda binary: None)
    vendor._DPKG_COMPARE_CACHE.clear()

    assert vendor._dpkg_lt("1.0", "2.0") is True

    monkeypatch.setattr(
        vendor.shutil,
        "which",
        lambda binary: (_ for _ in ()).throw(AssertionError("cache should be used")),
    )
    assert vendor._dpkg_lt("1.0", "2.0") is True


def test_windows_os_inventory_item_is_synthesized_when_agent_has_no_package():
    item = vendor._windows_os_inventory_item(
        software=[],
        os_info={
            "platform": "windows",
            "name": "Microsoft Windows 11 Pro",
            "build": "22631",
            "ubr": "3593",
            "arch": "x64",
        },
    )

    assert item is not None
    assert item["package_type"] == "windows_os"
    assert item["version"] == "10.0.22631.3593"
    assert item["software_key"]


def test_parse_msrc_document_extracts_product_specific_record():
    xml_text = textwrap.dedent(
        """\
        <cvrfdoc xmlns:prod="http://www.icasi.org/CVRF/schema/prod/1.1"
                 xmlns:vuln="http://www.icasi.org/CVRF/schema/vuln/1.1">
          <prod:ProductTree>
            <prod:FullProductName ProductID="1000">Windows 11 Version 23H2 for x64-based Systems</prod:FullProductName>
          </prod:ProductTree>
          <vuln:Vulnerability>
            <vuln:CVE>CVE-2026-11111</vuln:CVE>
            <vuln:Title>Windows test vulnerability</vuln:Title>
            <vuln:Notes>
              <vuln:Note Type="Description">Remote code execution in Windows.</vuln:Note>
              <vuln:Note Type="Tag">Exploitation More Likely</vuln:Note>
            </vuln:Notes>
            <vuln:ProductStatuses>
              <vuln:Status Type="Known Affected"><vuln:ProductID>1000</vuln:ProductID></vuln:Status>
            </vuln:ProductStatuses>
            <vuln:Threats>
              <vuln:Threat Type="Severity"><vuln:ProductID>1000</vuln:ProductID><vuln:Description>Critical</vuln:Description></vuln:Threat>
              <vuln:Threat Type="Impact"><vuln:ProductID>1000</vuln:ProductID><vuln:Description>Remote Code Execution</vuln:Description></vuln:Threat>
            </vuln:Threats>
            <vuln:CVSSScoreSets>
              <vuln:ScoreSet><vuln:ProductID>1000</vuln:ProductID><vuln:BaseScore>9.8</vuln:BaseScore></vuln:ScoreSet>
            </vuln:CVSSScoreSets>
            <vuln:Remediations>
              <vuln:Remediation Type="Vendor Fix">
                <vuln:ProductID>1000</vuln:ProductID>
                <vuln:Description>Security Update KB5030000</vuln:Description>
                <vuln:URL>https://support.microsoft.com/help/5030000</vuln:URL>
                <vuln:FixedBuild>10.0.22631.4000</vuln:FixedBuild>
              </vuln:Remediation>
            </vuln:Remediations>
          </vuln:Vulnerability>
        </cvrfdoc>
        """
    )

    records = vendor._parse_msrc_document("2026-May", xml_text)

    assert len(records) == 1
    assert records[0]["cve"] == "CVE-2026-11111"
    assert records[0]["severity"] == "critical"
    assert records[0]["cvss"] == 9.8
    assert records[0]["remediations"][0]["fixed_build"] == "10.0.22631.4000"


def test_match_windows_msrc_creates_os_finding_when_build_is_vulnerable(monkeypatch):
    monkeypatch.setattr(
        vendor,
        "_fetch_msrc_records",
        lambda: [
            {
                "doc_id": "2026-May",
                "product_id": "1000",
                "product_name": "Windows 11 Version 23H2 for x64-based Systems",
                "cve": "CVE-2026-11111",
                "severity": "critical",
                "cvss": 9.8,
                "summary": "Windows test vulnerability",
                "impact": "Remote Code Execution",
                "exploit_status": "Exploitation More Likely",
                "tags": ["test"],
                "remediations": [
                    {
                        "type": "Vendor Fix",
                        "description": "Security Update KB5030000",
                        "url": "https://support.microsoft.com/help/5030000",
                        "fixed_build": "10.0.22631.4000",
                    }
                ],
            }
        ],
    )

    findings = vendor._match_windows_msrc(
        software=[],
        os_info={
            "platform": "windows",
            "name": "Microsoft Windows 11 Pro",
            "build": "22631",
            "ubr": "3593",
            "arch": "x64",
        },
    )

    assert len(findings) == 1
    assert findings[0]["source"] == "MSRC"
    assert findings[0]["cve"] == "CVE-2026-11111"
    assert findings[0]["fixed_version"] == "10.0.22631.4000"
    assert findings[0]["evidence"]["kb_ids"] == ["5030000"]
