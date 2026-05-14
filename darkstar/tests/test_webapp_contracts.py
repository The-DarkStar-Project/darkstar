import base64

import pytest
from fastapi import HTTPException

from darkstar import webapp


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "password,expected",
    [
        ("Short1!", "Password must be at least 8 characters."),
        ("longbutweak", "Password must include one uppercase letter, one number, one special character."),
        ("StrongPass1!", None),
        (None, None),
    ],
)
def test_password_policy_error(password, expected):
    assert webapp._password_policy_error(password) == expected


@pytest.mark.parametrize(
    "payload,detail",
    [
        ({"targets": "example.com"}, "Provide either mode or scanner, but not both"),
        ({"targets": "example.com", "mode": 2, "scanner": "nuclei"}, "Provide either mode or scanner, but not both"),
        ({"targets": "example.com", "mode": 99}, "Mode must be one of 1,2,3,4"),
        ({"targets": "example.com", "scanner": "unknown"}, "Unsupported scanner"),
        ({"targets": "   ", "mode": 1}, "Targets cannot be empty"),
    ],
)
def test_validate_scan_payload_rejects_invalid_combinations(payload, detail):
    body = webapp.ScanStartRequest(**payload)

    with pytest.raises(HTTPException) as exc:
        webapp._validate_scan_payload(body)

    assert exc.value.status_code == 400
    assert exc.value.detail == detail


@pytest.mark.parametrize(
    "payload",
    [
        {"targets": "example.com", "mode": 1},
        {"targets": "example.com", "scanner": "nuclei"},
        {"targets": " example.com ", "scanner": "zap"},
    ],
)
def test_validate_scan_payload_accepts_supported_modes_and_scanners(payload):
    webapp._validate_scan_payload(webapp.ScanStartRequest(**payload))


def test_scan_signature_normalizes_order_case_and_trailing_slash():
    left = webapp._scan_signature(2, None, "HTTPS://Example.com/, api.example.com")
    right = webapp._scan_signature(2, None, "api.example.com, https://example.com")

    assert left == right
    assert left == ("2", "api.example.com,https://example.com")


def test_totp_verification_accepts_current_and_adjacent_windows(monkeypatch):
    secret = base64.b32encode(b"darkstar-test-secret").decode("ascii").rstrip("=")
    timestamp = 1_800_000_000
    code = webapp._totp_code(secret, timestamp)

    monkeypatch.setattr(webapp.time, "time", lambda: timestamp + 30)

    assert webapp._verify_totp(secret, code) is True
    assert webapp._verify_totp(secret, "000000") is False
    assert webapp._verify_totp(None, code) is False


def test_endpoint_os_info_from_agent_prefers_agent_columns_over_metadata():
    agent = {
        "os_platform": "windows",
        "os_name": "Windows 11 Pro",
        "os_version": "23H2",
        "os_arch": "x64",
        "os_build": "22631",
        "metadata_json": '{"os": {"name": "metadata name"}, "codename": "meta"}',
    }

    result = webapp._endpoint_os_info_from_agent(agent)

    assert result["platform"] == "windows"
    assert result["name"] == "Windows 11 Pro"
    assert result["version"] == "23H2"
    assert result["arch"] == "x64"
    assert result["build"] == "22631"
    assert result["codename"] == "meta"


def test_dedupe_endpoint_findings_prefers_vendor_source_over_osv():
    findings = [
        {"software_key": "pkg", "cve": "CVE-2026-1000", "source": "OSV", "confidence": 95},
        {"software_key": "pkg", "cve": "cve-2026-1000", "source": "MSRC", "confidence": 90},
        {"software_key": "other", "cve": "CVE-2026-1000", "source": "OSV", "confidence": 95},
    ]

    result = webapp._dedupe_endpoint_findings(findings)

    assert len(result) == 2
    chosen = [item for item in result if item["software_key"] == "pkg"][0]
    assert chosen["source"] == "MSRC"


def test_match_endpoint_vulnerabilities_skips_vendor_packages_for_osv(monkeypatch):
    queried_items = []

    monkeypatch.setenv("ENDPOINT_OSV_MATCHING", "true")
    monkeypatch.setenv("ENDPOINT_VENDOR_MATCHING", "true")
    monkeypatch.setattr(webapp, "get_endpoint_vuln_cache_entries", lambda org_db, queries: {})
    monkeypatch.setattr(webapp, "upsert_endpoint_vuln_cache_entries", lambda *args, **kwargs: None)
    monkeypatch.setattr(webapp, "match_vendor_vulnerabilities", lambda software, os_info: [])

    def fake_query_osv_cache_results(items):
        queried_items.extend(items)
        return {}

    monkeypatch.setattr(webapp, "query_osv_cache_results", fake_query_osv_cache_results)

    _findings, stats = webapp._match_endpoint_vulnerabilities(
        "tenant_db",
        [
            {
                "software_key": "deb-1",
                "package_type": "deb",
                "purl": "pkg:deb/debian/openssl@1.1.1",
                "version": "1.1.1",
            },
            {
                "software_key": "npm-1",
                "package_type": "npm",
                "purl": "pkg:npm/lodash@4.17.20",
                "version": "4.17.20",
            },
        ],
        os_info={"platform": "debian"},
    )

    assert [item["software_key"] for item in queried_items] == ["npm-1"]
    assert stats["candidates"] == 1
    assert stats["skipped_vendor_os_packages"] == 1


def test_refresh_endpoint_vulnerabilities_replaces_agent_findings(monkeypatch):
    monkeypatch.setattr(
        webapp,
        "_match_endpoint_vulnerabilities",
        lambda org_db, software, os_info=None: (
            [{"software_key": "pkg", "cve": "CVE-2026-12345"}],
            {"matcher": "test"},
        ),
    )
    replaced = {}

    def fake_replace(org_db, agent_id, findings):
        replaced["org_db"] = org_db
        replaced["agent_id"] = agent_id
        replaced["findings"] = findings
        return len(findings)

    monkeypatch.setattr(webapp, "replace_endpoint_vulnerabilities", fake_replace)

    result = webapp._refresh_endpoint_vulnerabilities(
        "tenant_db",
        "agent-1",
        [{"software_key": "pkg"}],
        os_info={"platform": "linux"},
    )

    assert result == {"vulnerability_count": 1, "matcher_stats": {"matcher": "test"}}
    assert replaced["org_db"] == "tenant_db"
    assert replaced["agent_id"] == "agent-1"
    assert replaced["findings"][0]["cve"] == "CVE-2026-12345"


def test_scanner_attach_command_uses_public_url_and_expected_env(monkeypatch):
    monkeypatch.setenv("DARKSTAR_PUBLIC_URL", "https://darkstar.example/")
    monkeypatch.setenv("DARKSTAR_SCANNER_IMAGE", "darkstar:test")
    monkeypatch.setenv("DB_HOST", "db")
    monkeypatch.setenv("DB_NAME", "darkstar")
    monkeypatch.setenv("DB_USER", "runner")
    monkeypatch.setenv("DB_PASSWORD", "")

    command = webapp._scanner_attach_command(
        {"node_id": "node-1", "token": "dscan_test", "name": "edge"},
        request=None,
    )

    assert "--name darkstar-scanner-node-1" in command
    assert "DARKSTAR_ORCHESTRATOR_URL='https://darkstar.example/'" in command
    assert "DARKSTAR_SCANNER_TOKEN='dscan_test'" in command
    assert "DB_PASSWORD=''" in command
    assert command.endswith("darkstar:test python3 -m darkstar.scanner_worker")
