from darkstar.scanners.email import MailSecurityScanner


class DummyResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


def test_scan_skipped_when_no_spf_or_dmarc(monkeypatch):
    # Arrange: no TXT records for domain or _dmarc subdomain
    def fake_get_txt_records(self, qdomain: str):
        return []

    monkeypatch.setattr(
        MailSecurityScanner, "get_txt_records", fake_get_txt_records
    )
    # Avoid DB writes
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")

    # Act
    results = scanner.scan_domain("noscan.example")

    # Assert
    assert results["skipped"] is True
    assert results["reason"].startswith("Domain has no SPF/DMARC records")
    assert results["vulnerabilities"] == []


def test_scan_detects_spf_and_dmarc_issues(monkeypatch):
    domain = "example.com"

    # Provide specific TXT records for SPF and DMARC
    def fake_get_txt_records(self, qdomain: str):
        if qdomain == domain:
            # Two SPF records to trigger multiple records finding and include risky mechanisms
            return [
                "v=spf1 a mx include:gooogle.com ptr exists:example.com +all",
                "v=spf1 ip4:203.0.113.5 ~all",
            ]
        if qdomain == f"_dmarc.{domain}":
            # p=none and pct<100 without rua to trigger several DMARC findings
            return ["v=DMARC1; p=none; pct=50"]
        # No MTA-STS in this test
        if qdomain == f"_mta-sts.{domain}":
            return []
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)
    # Avoid running MTA-STS network checks in this test
    monkeypatch.setattr(MailSecurityScanner, "check_mta_sts_record", lambda self: None)
    # Avoid DB writes
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")

    # Act
    results = scanner.scan_domain(domain)

    # Assert
    assert results["skipped"] is False
    titles = {v.title for v in results["vulnerabilities"]}

    # SPF-related
    assert "SPF_MULTIPLE_RECORDS" in titles
    assert "SPF_DEPRECATED_PTR" in titles
    assert "SPF_RISKY_EXISTS" in titles
    assert "SPF_PERMISSIVE_ALL" in titles
    assert "SPF_DOMAIN_TYPO" in titles

    # DMARC-related
    assert "DMARC_MONITORING_ONLY" in titles
    assert "DMARC_PARTIAL_ENFORCEMENT" in titles
    assert "DMARC_NO_SUBDOMAIN_POLICY" in titles
    assert "DMARC_SPF_ALIGNMENT_RELAXED" in titles
    assert "DMARC_DKIM_ALIGNMENT_RELAXED" in titles
    assert "DMARC_NO_REPORTING" in titles


def _stub_good_spf_dmarc(monkeypatch, scanner: MailSecurityScanner):
    # Ensure SPF/DMARC checks pass quietly so we can focus on MTA-STS in tests
    monkeypatch.setattr(scanner, "check_spf_presence", lambda _domain: True)
    monkeypatch.setattr(scanner, "get_spf_records", lambda _domain: ["v=spf1 -all"])
    monkeypatch.setattr(scanner, "check_dmarc_presence", lambda _domain: True)
    monkeypatch.setattr(
        scanner,
        "get_dmarc_records",
        lambda _domain: [
            "v=DMARC1; p=reject; rua=mailto:a@b.com; aspf=s; adkim=s; sp=reject",
        ],
    )


def test_mta_sts_missing_record(monkeypatch):
    domain = "mail.example"

    def fake_get_txt_records(self, qdomain: str):
        if qdomain == f"_mta-sts.{domain}":
            return []  # No MTA-STS record
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)
    # Avoid DB writes
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)

    # Act (force to skip pre-check logic but keep SPF/DMARC quiet)
    results = scanner.scan_domain(domain, force=True)

    # Assert
    titles = {v.title for v in results["vulnerabilities"]}
    assert "MTA_STS_MISSING" in titles


def test_mta_sts_invalid_record_format(monkeypatch):
    domain = "mta.invalid"

    def fake_get_txt_records(self, qdomain: str):
        if qdomain == f"_mta-sts.{domain}":
            # Missing id= field
            return ["v=STSv1"]
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)
    # Avoid DB writes
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)

    # Act
    results = scanner.scan_domain(domain, force=True)

    # Assert
    titles = {v.title for v in results["vulnerabilities"]}
    assert "MTA_STS_INVALID_FORMAT" in titles


def test_mta_sts_policy_file_weak_mode(monkeypatch):
    domain = "mta.policy"

    def fake_get_txt_records(self, qdomain: str):
        if qdomain == f"_mta-sts.{domain}":
            # Valid DNS record
            return ["v=STSv1; id=12345"]
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)

    # Stub SSL certificate check to avoid network
    monkeypatch.setattr(MailSecurityScanner, "_check_mta_sts_ssl_certificate", lambda self: None)

    # Stub HTTP fetch of policy file
    def fake_get(url, timeout=10, verify=True):
        assert url == f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        headers = {"content-type": "text/plain"}
        text = (
            "version: STSv1\n"
            "mode: testing\n"  # weak mode triggers finding
            "mx: mail.mta.policy\n"
            "max_age: 86400\n"
        )
        return DummyResponse(status_code=200, headers=headers, text=text)

    monkeypatch.setattr("darkstar.scanners.email.requests.get", fake_get)
    # Avoid DB writes
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)

    # Act
    results = scanner.scan_domain(domain, force=True)

    # Assert
    titles = {v.title for v in results["vulnerabilities"]}
    assert "MTA_STS_WEAK_MODE" in titles


def test_spf_syntax_invalid_mechanism_and_malformed_ip(monkeypatch):
    domain = "spf.invalid"

    def fake_get_txt_records(self, qdomain: str):
        if qdomain == domain:
            return ["v=spf1 banana ip4:999.999.0.1 -all"]
        if qdomain == f"_dmarc.{domain}":
            return [
                "v=DMARC1; p=reject; rua=mailto:a@b.com; aspf=s; adkim=s; sp=reject",
            ]
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)
    monkeypatch.setattr(MailSecurityScanner, "check_mta_sts_record", lambda self: None)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "SPF_INVALID_MECHANISM" in titles
    assert "SPF_MALFORMED_IP" in titles


def test_spf_missing_all_and_record_too_long(monkeypatch):
    domain = "spf.long"

    long_spf = "v=spf1 " + " ".join(["include:example.com"] * 60)  # > 512 chars

    def fake_get_txt_records(self, qdomain: str):
        if qdomain == domain:
            return [long_spf]
        if qdomain == f"_dmarc.{domain}":
            return [
                "v=DMARC1; p=reject; rua=mailto:a@b.com; aspf=s; adkim=s; sp=reject",
            ]
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)
    monkeypatch.setattr(MailSecurityScanner, "check_mta_sts_record", lambda self: None)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "SPF_RECORD_TOO_LONG" in titles
    assert "SPF_MISSING_ALL" in titles


def test_dmarc_weak_subdomain_policy(monkeypatch):
    domain = "dmarc.sp.none"

    def fake_get_txt_records(self, qdomain: str):
        if qdomain == domain:
            return ["v=spf1 -all"]
        if qdomain == f"_dmarc.{domain}":
            return ["v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com"]
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)
    monkeypatch.setattr(MailSecurityScanner, "check_mta_sts_record", lambda self: None)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "DMARC_WEAK_SUBDOMAIN_POLICY" in titles


def test_dmarc_order_and_syntax_errors(monkeypatch):
    domain = "dmarc.order"

    def fake_get_txt_records(self, qdomain: str):
        if qdomain == domain:
            return ["v=spf1 -all"]
        if qdomain == f"_dmarc.{domain}":
            # Return malformed DMARC records that will trigger syntax/order errors
            return [
                "p=reject; v=DMARC1; rua=mailto:a@b.com",  # Wrong order
                "p=reject; rua=mailto:a@b.com"  # Missing v=DMARC1
            ]
        return []

    # Mock get_dmarc_records to return the malformed records without filtering
    def fake_get_dmarc_records(self, domain: str):
        return [
            "p=reject; v=DMARC1; rua=mailto:a@b.com",  # Wrong order
            "p=reject; rua=mailto:a@b.com"  # Missing v=DMARC1 entirely
        ]

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)
    monkeypatch.setattr(MailSecurityScanner, "get_dmarc_records", fake_get_dmarc_records)
    monkeypatch.setattr(MailSecurityScanner, "check_mta_sts_record", lambda self: None)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    
    # Should find both syntax error and incorrect order
    assert "DMARC_SYNTAX_ERROR" in titles
    assert "DMARC_INCORRECT_ORDER" in titles


def test_dmarc_alignment_and_reporting_good(monkeypatch):
    domain = "dmarc.good"

    def fake_get_txt_records(self, qdomain: str):
        if qdomain == domain:
            return ["v=spf1 -all"]
        if qdomain == f"_dmarc.{domain}":
            return [
                "v=DMARC1; p=reject; rua=mailto:a@b.com; aspf=s; adkim=s; sp=reject",
            ]
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)
    monkeypatch.setattr(MailSecurityScanner, "check_mta_sts_record", lambda self: None)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "DMARC_SPF_ALIGNMENT_RELAXED" not in titles
    assert "DMARC_DKIM_ALIGNMENT_RELAXED" not in titles
    assert "DMARC_NO_REPORTING" not in titles
    assert "DMARC_MONITORING_ONLY" not in titles
    assert "DMARC_PARTIAL_ENFORCEMENT" not in titles


def test_is_email_sending_domain_from_emails_file(monkeypatch):
    scanner = MailSecurityScanner(org_name="test_org")
    assert scanner.is_email_sending_domain("any.domain", from_emails_file=True) is True


def test_is_email_sending_domain_spf_or_dmarc(monkeypatch):
    scanner = MailSecurityScanner(org_name="test_org")
    # SPF present case
    monkeypatch.setattr(scanner, "check_spf_presence_quiet", lambda d: True)
    monkeypatch.setattr(scanner, "check_dmarc_presence_quiet", lambda d: False)
    assert scanner.is_email_sending_domain("domain.example") is True
    # DMARC present case
    monkeypatch.setattr(scanner, "check_spf_presence_quiet", lambda d: False)
    monkeypatch.setattr(scanner, "check_dmarc_presence_quiet", lambda d: True)
    assert scanner.is_email_sending_domain("domain.example") is True
    # Neither present
    monkeypatch.setattr(scanner, "check_spf_presence_quiet", lambda d: False)
    monkeypatch.setattr(scanner, "check_dmarc_presence_quiet", lambda d: False)
    assert scanner.is_email_sending_domain("domain.example") is False


def test_scan_force_logs_missing_spf_and_dmarc(monkeypatch):
    domain = "forced.missing"

    def fake_get_txt_records(self, qdomain: str):
        # No SPF and no DMARC records
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)
    # Avoid MTA-STS during this test
    monkeypatch.setattr(MailSecurityScanner, "check_mta_sts_record", lambda self: None)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    # Since forced, it should run and report both missing records
    assert "SPF_MISSING" in titles
    assert "DMARC_MISSING" in titles


# ---- MTA-STS extra cases ----

def _stub_mta_sts_dns(monkeypatch, domain: str):
    def fake_get_txt_records(self, qdomain: str):
        if qdomain == f"_mta-sts.{domain}":
            return ["v=STSv1; id=abc"]
        return []

    monkeypatch.setattr(MailSecurityScanner, "get_txt_records", fake_get_txt_records)


def test_mta_sts_policy_file_missing_http_error(monkeypatch):
    domain = "sts.404"
    _stub_mta_sts_dns(monkeypatch, domain)
    # Stub SSL OK
    monkeypatch.setattr(MailSecurityScanner, "_check_mta_sts_ssl_certificate", lambda self: None)

    def fake_get(url, timeout=10, verify=True):
        return DummyResponse(status_code=404, headers={"content-type": "text/plain"}, text="not found")

    monkeypatch.setattr("darkstar.scanners.email.requests.get", fake_get)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "MTA_STS_POLICY_FILE_MISSING" in titles


def test_mta_sts_content_type_error(monkeypatch):
    domain = "sts.ct"
    _stub_mta_sts_dns(monkeypatch, domain)
    monkeypatch.setattr(MailSecurityScanner, "_check_mta_sts_ssl_certificate", lambda self: None)

    def fake_get(url, timeout=10, verify=True):
        headers = {"content-type": "text/html"}
        text = (
            "version: STSv1\n"
            "mode: enforce\n"
            "mx: mail.sts.ct\n"
            "max_age: 86400\n"
        )
        return DummyResponse(status_code=200, headers=headers, text=text)

    monkeypatch.setattr("darkstar.scanners.email.requests.get", fake_get)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "MTA_STS_CONTENT_TYPE_ERROR" in titles
    # Ensure policy itself didn't raise invalid findings
    assert "MTA_STS_POLICY_INVALID" not in titles


def test_mta_sts_policy_missing_fields(monkeypatch):
    domain = "sts.missing"
    _stub_mta_sts_dns(monkeypatch, domain)
    monkeypatch.setattr(MailSecurityScanner, "_check_mta_sts_ssl_certificate", lambda self: None)

    def fake_get(url, timeout=10, verify=True):
        headers = {"content-type": "text/plain"}
        text = (
            "version: STSv1\n"
            "mode: enforce\n"
            # missing mx
            "max_age: 86400\n"
        )
        return DummyResponse(status_code=200, headers=headers, text=text)

    monkeypatch.setattr("darkstar.scanners.email.requests.get", fake_get)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "MTA_STS_POLICY_INVALID" in titles


def test_mta_sts_policy_invalid_version_mode_and_low_max_age(monkeypatch):
    domain = "sts.badvals"
    _stub_mta_sts_dns(monkeypatch, domain)
    monkeypatch.setattr(MailSecurityScanner, "_check_mta_sts_ssl_certificate", lambda self: None)

    def fake_get(url, timeout=10, verify=True):
        headers = {"content-type": "text/plain"}
        text = (
            "version: STSv2\n"  # invalid version
            "mode: invalid\n"   # invalid mode
            "mx: mail.sts.bad\n"
            "max_age: 3600\n"   # too low
        )
        return DummyResponse(status_code=200, headers=headers, text=text)

    monkeypatch.setattr("darkstar.scanners.email.requests.get", fake_get)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)
    results = scanner.scan_domain(domain, force=True)
    invalid_count = sum(1 for v in results["vulnerabilities"] if v.title == "MTA_STS_POLICY_INVALID")
    assert invalid_count >= 2


def test_mta_sts_policy_non_integer_max_age(monkeypatch):
    domain = "sts.maxage"
    _stub_mta_sts_dns(monkeypatch, domain)
    monkeypatch.setattr(MailSecurityScanner, "_check_mta_sts_ssl_certificate", lambda self: None)

    def fake_get(url, timeout=10, verify=True):
        headers = {"content-type": "text/plain"}
        text = (
            "version: STSv1\n"
            "mode: enforce\n"
            "mx: mail.sts.max\n"
            "max_age: abc\n"  # non-integer
        )
        return DummyResponse(status_code=200, headers=headers, text=text)

    monkeypatch.setattr("darkstar.scanners.email.requests.get", fake_get)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "MTA_STS_POLICY_INVALID" in titles


def test_mta_sts_ssl_error_from_requests(monkeypatch):
    import requests as _requests

    domain = "sts.ssl"
    _stub_mta_sts_dns(monkeypatch, domain)
    # Let SSL precheck pass so requests.get is called and raises SSLError
    monkeypatch.setattr(MailSecurityScanner, "_check_mta_sts_ssl_certificate", lambda self: None)

    def fake_get(url, timeout=10, verify=True):
        raise _requests.exceptions.SSLError("bad ssl")

    monkeypatch.setattr("darkstar.scanners.email.requests.get", fake_get)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "MTA_STS_SSL_ERROR" in titles


def test_mta_sts_request_exception(monkeypatch):
    import requests as _requests

    domain = "sts.reqexc"
    _stub_mta_sts_dns(monkeypatch, domain)
    monkeypatch.setattr(MailSecurityScanner, "_check_mta_sts_ssl_certificate", lambda self: None)

    def fake_get(url, timeout=10, verify=True):
        raise _requests.exceptions.RequestException("timeout")

    monkeypatch.setattr("darkstar.scanners.email.requests.get", fake_get)
    monkeypatch.setattr(
        "darkstar.scanners.email.insert_vulnerability_to_database", lambda *args, **kwargs: None
    )

    scanner = MailSecurityScanner(org_name="test_org")
    _stub_good_spf_dmarc(monkeypatch, scanner)
    results = scanner.scan_domain(domain, force=True)
    titles = {v.title for v in results["vulnerabilities"]}
    assert "MTA_STS_POLICY_FILE_MISSING" in titles

