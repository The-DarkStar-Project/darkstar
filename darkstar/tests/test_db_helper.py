import mysql.connector
import pytest
from pathlib import Path
from pytest_mock import MockerFixture
import pandas as pd
from core.db_helper import (
    ORG_SCHEMA_MIGRATION_STATEMENTS,
    ORG_SCHEMA_STATEMENTS,
    DatabaseConnectionManager,
    _coerce_optional_date,
    insert_bbot_to_db,
    insert_email_data,
    insert_vulnerabilities_to_database,
    get_vulnerabilities_filtered,
    sanitize_string,
    flatten_list,
    convert_to_json,
    prepare_cve_data,
    prepare_non_cve_data,
)
from core.models.vulnerability import Vulnerability, CVE


# Parametrized tests for sanitize_string function
@pytest.mark.parametrize(
    "input_value,expected",
    [
        ("\x1b[31mRed text\x1b[0m", "Red text"),  # ANSI escape codes
        ("  spaces  ", "spaces"),  # Leading/trailing spaces
        ("normal text", "normal text"),  # Normal text
        (
            "<div>Some <b>bold</b> text</div>",
            "&lt;div&gt;Some &lt;b&gt;bold&lt;/b&gt; text&lt;/div&gt;",
        ),  # HTML encoding
        (
            "\x1b[33m  Yellow with spaces  \x1b[0m",
            "Yellow with spaces",
        ),  # ANSI + spaces
        ("", ""),  # Empty string
        (None, None),  # Should return None, not empty string
    ],
)
def test_sanitize_string(input_value, expected):
    """Parametrized test for sanitize_string function."""
    assert sanitize_string(input_value) == expected


# Parametrized tests for flatten_list function
@pytest.mark.parametrize(
    "input_value,expected",
    [
        (["mixed", 123, True], "mixed, 123, True"),  # Mixed types
        ("not a list", "not a list"),  # String input
    ],
)
def test_flatten_list(input_value, expected):
    """Parametrized test for flatten_list function."""
    assert flatten_list(input_value) == expected


# Parametrized tests for convert_to_json function
@pytest.mark.parametrize(
    "input_value,expected",
    [
        ({"nested": {"key": "value"}}, '{"nested": {"key": "value"}}'),  # Nested dict
        (123, 123),  # Integer input
    ],
)
def test_convert_to_json(input_value, expected):
    """Parametrized test for convert_to_json function."""
    assert convert_to_json(input_value) == expected


# Parametrized tests for prepare_cve_data with different CVE configurations
@pytest.mark.parametrize(
    "cve_data,vuln_data,expected_length",
    [
        (
            {  # Standard CVE
                "cve": "CVE-2023-1234",
                "cvss": 8.5,
                "epss": 0.5,
                "summary": "Test summary",
                "cwe": "CWE-79",
                "references": ["ref1", "ref2"],
                "capec": "CAPEC-123",
                "solution": "Test solution",
                "impact": {"confidentiality": "high"},
                "access": {"vector": "network"},
                "age": 30,
                "pocs": ["poc1", "poc2"],
                "kev": True,
            },
            {
                "title": "Test CVE",
                "affected_item": "test.com",
                "tool": "nuclei",
                "confidence": 90,
                "severity": "high",
                "host": "192.168.1.1",
            },
            19,
        ),
        (
            {  # CVE with minimal data
                "cve": "CVE-2023-5678",
                "cvss": 5.0,
                "epss": 0.1,
                "summary": None,
                "cwe": None,
                "references": [],
                "capec": None,
                "solution": None,
                "impact": {},
                "access": {},
                "age": 0,
                "pocs": [],
                "kev": False,
            },
            {
                "title": "Minimal CVE",
                "affected_item": "example.org",
                "tool": "custom",
                "confidence": 50,
                "severity": "low",
                "host": "10.0.0.1",
            },
            19,
        ),
    ],
)
def test_prepare_cve_data_parametrized(
    mocker: MockerFixture, cve_data, vuln_data, expected_length
):
    """Parametrized test for prepare_cve_data with different CVE configurations."""
    # Set up mocks
    mock_sanitize = mocker.patch(
        "core.db_helper.sanitize_string", side_effect=lambda x: x
    )
    mock_flatten = mocker.patch("core.db_helper.flatten_list", return_value="flattened")
    mock_convert = mocker.patch(
        "core.db_helper.convert_to_json", return_value="json_converted"
    )

    # Create CVE and Vulnerability objects
    cve = CVE(**cve_data)
    vuln = Vulnerability(**vuln_data)
    vuln.cve = cve

    # Call the function
    result = prepare_cve_data(vuln)

    # Assertions
    assert isinstance(result, tuple)
    assert len(result) == expected_length
    mock_sanitize.assert_called()
    mock_flatten.assert_called()
    mock_convert.assert_called()


# Parametrized tests for prepare_non_cve_data with different vulnerability configurations
@pytest.mark.parametrize(
    "vuln_data,expected_length",
    [
        (
            {  # Standard non-CVE vulnerability
                "title": "Test non-CVE",
                "affected_item": "test.com",
                "tool": "nuclei",
                "confidence": 90,
                "severity": "medium",
                "host": "192.168.1.1",
                "summary": "Test summary",
                "impact": "Test impact",
                "solution": "Test solution",
                "poc": ["poc1", "poc2"],
                "references": ["ref1", "ref2"],
                "cvss": 7.5,
                "epss": 0.3,
                "cwe": "CWE-352",
                "capec": "CAPEC-456",
            },
            19,
        ),
        (
            {  # Minimal non-CVE vulnerability
                "title": "Minimal vuln",
                "affected_item": "minimal.com",
                "tool": "custom",
                "confidence": 30,
                "severity": "info",
                "host": "127.0.0.1",
                "summary": None,
                "impact": None,
                "solution": None,
                "poc": [],
                "references": [],
                "cvss": 0.0,
                "epss": 0.0,
                "cwe": None,
                "capec": None,
            },
            19,
        ),
    ],
)
def test_prepare_non_cve_data_parametrized(
    mocker: MockerFixture, vuln_data, expected_length
):
    """Parametrized test for prepare_non_cve_data with different vulnerability configurations."""
    # Set up mocks
    mock_sanitize = mocker.patch(
        "core.db_helper.sanitize_string", side_effect=lambda x: x
    )
    mock_flatten = mocker.patch("core.db_helper.flatten_list", return_value="flattened")

    # Create vulnerability object
    vuln = Vulnerability(**vuln_data)

    # Call the function
    result = prepare_non_cve_data(vuln)

    # Assertions
    assert isinstance(result, tuple)
    assert len(result) == expected_length
    mock_sanitize.assert_called()
    mock_flatten.assert_called()


# Parametrized tests for insert_bbot_to_db with different DataFrame configurations
@pytest.mark.parametrize(
    "dataframe_data,org_name,expected_result",
    [
        (
            {  # Standard bbot data
                "Event type": ["DNS_NAME", "URL"],
                "Event data": [
                    '{"host": "example.com"}',
                    '{"url": "https://example.com"}',
                ],
                "IP Address": ["192.168.1.1", "192.168.1.2"],
                "Source Module": ["bbot", "nuclei"],
                "Scope Distance": ["0", "1"],
                "Event Tags": ['["tag1", "tag2"]', '["tag3"]'],
            },
            "test_org",
            True,
        ),
        (
            {  # Single row data
                "Event type": ["SUBDOMAIN"],
                "Event data": ['{"subdomain": "sub.example.com"}'],
                "IP Address": ["10.0.0.1"],
                "Source Module": ["subfinder"],
                "Scope Distance": ["1"],
                "Event Tags": ['["discovery"]'],
            },
            "single_org",
            True,
        ),
        (
            {  # Empty DataFrame
                "Event type": [],
                "Event data": [],
                "IP Address": [],
                "Source Module": [],
                "Scope Distance": [],
                "Event Tags": [],
            },
            "empty_org",
            True,
        ),
    ],
)
def test_insert_bbot_to_db_parametrized(
    mocker: MockerFixture, dataframe_data, org_name, expected_result
):
    """Parametrized test for insert_bbot_to_db with different DataFrame configurations."""
    # Set up mock connection manager and connection
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    # Create test DataFrame
    test_data = pd.DataFrame(dataframe_data)

    # Call the function
    result = insert_bbot_to_db(test_data, org_name)

    # Assertions
    mock_db_manager.assert_called_once()
    mock_connection.commit.assert_called_once()
    assert result == expected_result


# Fixtures remain the same but are now used by parametrized tests
@pytest.fixture
def sample_cve():
    """Fixture for creating a sample CVE object."""
    return CVE(
        cve="CVE-2023-1234",
        cvss=8.5,
        epss=0.5,
        summary="Test summary",
        cwe="CWE-79",
        references=["ref1", "ref2"],
        capec="CAPEC-123",
        solution="Test solution",
        impact={"confidentiality": "high"},
        access={"vector": "network"},
        age=30,
        pocs=["poc1", "poc2"],
        kev=True,
    )


@pytest.fixture
def sample_vulnerability():
    """Fixture for creating a sample Vulnerability object."""
    return Vulnerability(
        title="Test Vulnerability",
        affected_item="test.com",
        tool="nuclei",
        confidence=90,
        severity="high",
        host="192.168.1.1",
    )


@pytest.fixture
def sample_bbot_dataframe():
    """Fixture for creating a sample bbot DataFrame."""
    return pd.DataFrame(
        {
            "Event type": ["DNS_NAME", "URL"],
            "Event data": [
                '{"host": "example.com"}',
                '{"url": "https://example.com"}',
            ],
            "IP Address": ["192.168.1.1", "192.168.1.2"],
            "Source Module": ["bbot", "nuclei"],
            "Scope Distance": ["0", "1"],
            "Event Tags": ['["tag1", "tag2"]', '["tag3"]'],
        }
    )


def test_get_vulnerabilities_filtered_uses_single_fetchone_for_total(mocker: MockerFixture):
    """Regression: total count should be read from a single fetchone() call."""
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    mock_cursor.fetchone.return_value = {"total": 5}
    mock_cursor.fetchall.return_value = [{"id": 1, "title": "vuln"}]

    items, total = get_vulnerabilities_filtered("org_test", severity="high", limit=10, offset=0)

    assert total == 5
    assert items == [{"id": 1, "title": "vuln"}]
    # One fetchone for count query only; rows come from fetchall.
    assert mock_cursor.fetchone.call_count == 1


def test_database_connection_manager_does_not_suppress_exceptions(mocker: MockerFixture):
    """Regression: __exit__ should not swallow exceptions."""
    manager = DatabaseConnectionManager.__new__(DatabaseConnectionManager)
    manager.connection = mocker.Mock()
    manager.connection.is_connected.return_value = True

    should_suppress = manager.__exit__(ValueError, ValueError("boom"), None)

    assert should_suppress is False
    manager.connection.close.assert_called_once()


def test_vulnerability_batch_uses_one_connection_and_commit(mocker: MockerFixture):
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_connection.cursor.return_value = mock_cursor
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    vulnerabilities = [
        Vulnerability(
            title=f"Finding {index}",
            affected_item="https://example.com",
            tool="nuclei",
            confidence=97,
            severity="info",
            host="example.com",
        )
        for index in range(3)
    ]

    inserted = insert_vulnerabilities_to_database(vulnerabilities, "org_test")

    assert inserted == 3
    mock_db_manager.assert_called_once_with()
    mock_cursor.executemany.assert_called_once()
    assert len(mock_cursor.executemany.call_args.args[1]) == 3
    mock_connection.commit.assert_called_once_with()
    mock_connection.rollback.assert_not_called()


# Regression tests for asmevents column-width handling. BBOT's "Source Module"
# column is event.module_sequence, an unbounded "a->b->c" discovery chain that
# used to abort the whole batch with MariaDB error 1406.
def _bbot_dataframe_with_module_chain(chain: str) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "Event type": ["URL"],
            "Event data": ["https://example.com/"],
            "IP Address": ["192.168.1.1"],
            "Source Module": [chain],
            "Scope Distance": ["0"],
            "Event Tags": ['["in-scope"]'],
        }
    )


def test_insert_bbot_clamps_long_module_sequence(mocker: MockerFixture):
    """A deep BBOT module chain must be clamped, not rejected by the database."""
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    chain = "->".join(["httpx", "excavate"] * 40)
    assert len(chain) > 255

    assert insert_bbot_to_db(_bbot_dataframe_with_module_chain(chain), "test_org") is True

    record = mock_cursor.executemany.call_args.args[1][0]
    source_module = record[3]
    assert len(source_module) == 255
    assert source_module == chain[:255]
    mock_connection.commit.assert_called_once()


def test_insert_bbot_keeps_module_sequence_that_fits(mocker: MockerFixture):
    """Values within the column width must be stored verbatim."""
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    chain = "httpx->excavate->httpx->excavate->httpx->excavate->httpx"
    assert 50 < len(chain) <= 255  # would have broken the old VARCHAR(50)

    insert_bbot_to_db(_bbot_dataframe_with_module_chain(chain), "test_org")

    assert mock_cursor.executemany.call_args.args[1][0][3] == chain


def test_insert_bbot_falls_back_to_row_inserts_on_batch_rejection(
    mocker: MockerFixture,
):
    """One unusable row must not discard an entire scan's ASM results."""
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    mock_cursor.executemany.side_effect = mysql.connector.Error("1406: Data too long")
    # Second of three rows stays unusable even on its own.
    mock_cursor.execute.side_effect = [
        None,  # USE `org_...`
        None,
        mysql.connector.Error("1406: Data too long"),
        None,
    ]

    dataframe = pd.DataFrame(
        {
            "Event type": ["URL", "URL", "URL"],
            "Event data": ["https://a/", "https://b/", "https://c/"],
            "IP Address": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            "Source Module": ["httpx", "httpx", "httpx"],
            "Scope Distance": ["0", "0", "0"],
            "Event Tags": ["[]", "[]", "[]"],
        }
    )

    assert insert_bbot_to_db(dataframe, "test_org") is True

    # Rolled back before retrying so partially inserted rows cannot duplicate.
    mock_connection.rollback.assert_called_once()
    # Three row-level retries on top of the initial USE statement.
    assert mock_cursor.execute.call_count == 4
    mock_connection.commit.assert_called_once()


def test_insert_bbot_discards_non_numeric_scope_distance(mocker: MockerFixture):
    """Scope distance is an INT column; unusable values become NULL."""
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    dataframe = _bbot_dataframe_with_module_chain("httpx")
    dataframe["Scope Distance"] = ["not-a-number"]

    insert_bbot_to_db(dataframe, "test_org")

    assert mock_cursor.executemany.call_args.args[1][0][4] is None


def test_asmevents_schema_definitions_agree_on_source_module_width():
    """init.sql and db_helper must not drift apart on the asmevents schema."""
    repo_root = Path(__file__).resolve().parents[2]
    init_sql = (repo_root / "sql" / "init.sql").read_text(encoding="utf-8")

    asmevents_statements = [
        statement
        for statement in ORG_SCHEMA_STATEMENTS
        if "CREATE TABLE IF NOT EXISTS asmevents" in statement
    ]
    assert len(asmevents_statements) == 1
    assert "source_module VARCHAR(255)" in asmevents_statements[0]
    assert "source_module VARCHAR(255)" in init_sql

    # Existing installs are widened by the additive migration list.
    assert any(
        "asmevents" in statement and "source_module VARCHAR(255)" in statement
        for statement in ORG_SCHEMA_MIGRATION_STATEMENTS
    )


# Regression tests for the other unbounded-scanner-output paths that could
# abort or silently discard a completed scan.
def test_prepare_cve_data_flattens_and_clamps(sample_cve):
    """capec arrives as a list from CIRCL and must not reach the driver as one."""
    vulnerability = Vulnerability(
        title="Test",
        affected_item="https://example.com/" + "a" * 400,
        tool="nuclei",
        confidence=90,
        severity="high",
        host="h" * 400,
    )
    vulnerability.cve = sample_cve
    sample_cve.capec = ["CAPEC-123", "CAPEC-456"]
    sample_cve.cwe = "CWE-" + "9" * 400

    prepared = prepare_cve_data(vulnerability)

    assert isinstance(prepared[12], str), "capec must be flattened to a string"
    assert "CAPEC-123" in prepared[12]
    assert len(prepared[6]) <= 255, "host is VARCHAR(255)"
    assert len(prepared[10]) <= 255, "cwe is VARCHAR(255)"
    # affected_item is TEXT and must therefore keep its full value.
    assert len(prepared[2]) > 255


def test_prepare_non_cve_data_clamps_severity_and_host():
    """OpenVAS puts a CVSS float in severity; scanner hosts are unbounded."""
    vulnerability = Vulnerability(
        title="Test",
        affected_item="https://example.com/",
        tool="t" * 400,
        confidence=75,
        severity="s" * 120,
        host="h" * 400,
    )

    prepared = prepare_non_cve_data(vulnerability)

    assert len(prepared[3]) <= 255, "tool is VARCHAR(255)"
    assert len(prepared[5]) <= 50, "severity is VARCHAR(50)"
    assert len(prepared[6]) <= 255, "host is VARCHAR(255)"


def test_vulnerability_batch_survives_one_bad_row(mocker: MockerFixture):
    """A rejected row must cost one finding, not the whole nuclei batch."""
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    mock_cursor.executemany.side_effect = mysql.connector.Error("1406: Data too long")
    mock_cursor.execute.side_effect = [
        None,  # USE `org_...`
        None,  # row 1 ok
        mysql.connector.Error("1406: Data too long"),  # row 2 rejected
    ]

    vulnerabilities = [
        Vulnerability(
            title=f"Finding {index}",
            affected_item="https://example.com/",
            tool="nuclei",
            confidence=90,
            severity="high",
            host="10.0.0.1",
        )
        for index in range(2)
    ]

    inserted = insert_vulnerabilities_to_database(vulnerabilities, "test_org")

    assert inserted == 1, "the good finding must still be persisted"
    mock_connection.commit.assert_called_once()


def test_insert_email_data_never_raises_into_the_scan(mocker: MockerFixture):
    """HIBP inserts run inside the BBOT pipeline and must not fail a scan."""
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor
    mock_cursor.executemany.side_effect = mysql.connector.Error("1406: Data too long")
    mock_cursor.execute.side_effect = mysql.connector.Error("1406: Data too long")

    assert insert_email_data(["a@example.com", "b@example.com"], "test_org") is False


def test_insert_email_data_clamps_long_addresses(mocker: MockerFixture):
    """email_input.email is VARCHAR(255) NOT NULL."""
    mock_connection = mocker.Mock()
    mock_cursor = mocker.Mock()
    mock_db_manager = mocker.patch("core.db_helper.DatabaseConnectionManager")
    mock_db_manager.return_value.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    assert insert_email_data(["x" * 400 + "@example.com"], "test_org") is True
    assert len(mock_cursor.executemany.call_args.args[1][0][0]) == 255


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2019-03-01", "2019-03-01"),
        ("2019-03-01T00:00:00Z", "2019-03-01"),
        ("", None),
        (None, None),
        ("not-a-date", None),
    ],
)
def test_coerce_optional_date(value, expected):
    """HIBP breach dates land in a DATE column and have changed shape before."""
    result = _coerce_optional_date(value)
    assert (result.isoformat() if result else None) == expected
