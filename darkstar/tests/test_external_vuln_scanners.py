import json
import os

import pytest

from scanners import external_vuln


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "target,expected",
    [
        ("example.com", "http://example.com"),
        ("https://example.com", "https://example.com"),
        ("http://example.com", "http://example.com"),
    ],
)
def test_ensure_scheme(target, expected):
    assert external_vuln._ensure_scheme(target) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Remote code execution possible", "high"),
        ("Reflected XSS in query", "medium"),
        ("Missing header X-Frame-Options", "low"),
        ("Banner observed", "info"),
    ],
)
def test_severity_from_keyword(text, expected):
    assert external_vuln._severity_from_keyword(text) == expected


@pytest.mark.parametrize(
    "risk,expected",
    [("0", "info"), ("1", "low"), ("2", "medium"), ("3", "high")],
)
def test_normalize_zap_risk(risk, expected):
    assert external_vuln._normalize_zap_risk(risk) == expected


def test_dalfox_load_report_accepts_json_array(tmp_path):
    report = tmp_path / "dalfox.json"
    report.write_text(json.dumps([{"type": "vuln", "poc": "https://example.com/?q=<script>"}]))

    scanner = external_vuln.DalfoxScanner("https://example.com", "org")

    assert scanner._load_report(str(report)) == [{"type": "vuln", "poc": "https://example.com/?q=<script>"}]


def test_dalfox_load_report_accepts_jsonl_and_text_fallback(tmp_path):
    report = tmp_path / "dalfox.jsonl"
    report.write_text(
        '{"type": "vuln", "payload": "<img>"}\n'
        "[V] Reflected XSS POC: https://example.com/?q=x\n"
    )

    scanner = external_vuln.DalfoxScanner("https://example.com", "org")
    findings = scanner._load_report(str(report))

    assert findings[0]["payload"] == "<img>"
    assert "Reflected XSS" in findings[1]["summary"]


def test_nikto_scan_target_parses_json_report(monkeypatch):
    def fake_run(cmd, capture_output=True, text=True, timeout=240):
        out_path = cmd[cmd.index("-output") + 1]
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "host": {
                        "vulnerabilities": [
                            {
                                "msg": "Missing header X-Frame-Options",
                                "url": "https://example.com/",
                                "references": {"CVE": "CVE-2026-22222"},
                            }
                        ]
                    }
                },
                handle,
            )

        class Result:
            returncode = 0
            stderr = ""

        return Result()

    monkeypatch.setattr(external_vuln.subprocess, "run", fake_run)

    scanner = external_vuln.NiktoScanner("https://example.com", "org")
    findings = scanner._scan_target("https://example.com")

    assert len(findings) == 1
    assert findings[0]["title"] == "Missing header X-Frame-Options"
    assert findings[0]["host"] == "example.com"
    assert findings[0]["severity"] == "low"
    assert findings[0]["cve"] == "CVE-2026-22222"


def test_wapiti_scan_target_parses_vulnerabilities_and_anomalies(monkeypatch):
    def fake_run(cmd, capture_output=True, text=True, timeout=360):
        out_path = cmd[cmd.index("-o") + 1]
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "vulnerabilities": {
                        "SQL Injection": [
                            {
                                "info": "SQL injection via id",
                                "level": 3,
                                "path": "/product?id=1",
                                "wstg": "Validate input",
                            }
                        ]
                    },
                    "anomalies": {
                        "Missing Header": [{"info": "X-Frame-Options missing", "path": "/"}]
                    },
                },
                handle,
            )

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(external_vuln.subprocess, "run", fake_run)

    scanner = external_vuln.WapitiScanner("https://example.com", "org")
    findings = scanner._scan_target("https://example.com")

    assert [finding["title"] for finding in findings] == ["SQL Injection", "Missing Header"]
    assert findings[0]["severity"] == "high"
    assert findings[0]["cwe"] == "CWE-89"
    assert findings[0]["affected_item"] == "https://example.com/product?id=1"
    assert findings[1]["severity"] == "low"
