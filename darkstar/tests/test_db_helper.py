import pytest
from unittest.mock import patch, MagicMock
import pandas as pd
from ..core.db_helper import (
    insert_bbot_to_db,
    sanitize_string,
    flatten_list,
    convert_to_json,
    prepare_cve_data,
    prepare_non_cve_data,
)
from ..core.models.vulnerability import Vulnerability, CVE


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
        (123, 123),  # Non-string integer
        (None, None),  # None value
        ([], []),  # Non-string list
        ({"key": "value"}, {"key": "value"}),  # Non-string dict
    ],
)
def test_sanitize_string(input_value, expected):
    """Parametrized test for sanitize_string function."""
    assert sanitize_string(input_value) == expected


# Parametrized tests for flatten_list function
@pytest.mark.parametrize(
    "input_value,expected",
    [
        (["a", "b", "c"], "a, b, c"),  # List of strings
        ([1, 2, 3], "1, 2, 3"),  # List of numbers
        (["single"], "single"),  # Single item list
        ([], ""),  # Empty list
        ([True, False], "True, False"),  # List of booleans
        (["mixed", 123, True], "mixed, 123, True"),  # Mixed types
        ("not a list", "not a list"),  # String input
        (None, None),  # None value
        (123, 123),  # Integer input
        ({"key": "value"}, {"key": "value"}),  # Dict input
    ],
)
def test_flatten_list(input_value, expected):
    """Parametrized test for flatten_list function."""
    assert flatten_list(input_value) == expected


# Parametrized tests for convert_to_json function
@pytest.mark.parametrize(
    "input_value,expected",
    [
        ({"key": "value"}, '{"key": "value"}'),  # Simple dict
        ({"nested": {"key": "value"}}, '{"nested": {"key": "value"}}'),  # Nested dict
        ({}, "{}"),  # Empty dict
        (
            {"number": 123, "bool": True},
            '{"number": 123, "bool": true}',
        ),  # Mixed types in dict
        ("not a dict", "not a dict"),  # String input
        (None, None),  # None value
        (123, 123),  # Integer input
        (["list", "items"], ["list", "items"]),  # List input
        (True, True),  # Boolean input
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
@patch("darkstar.core.db_helper.sanitize_string")
@patch("darkstar.core.db_helper.flatten_list")
@patch("darkstar.core.db_helper.convert_to_json")
def test_prepare_cve_data_parametrized(
    mock_convert, mock_flatten, mock_sanitize, cve_data, vuln_data, expected_length
):
    """Parametrized test for prepare_cve_data with different CVE configurations."""
    # Set up mocks
    mock_sanitize.side_effect = lambda x: x  # Return the input unchanged
    mock_flatten.side_effect = lambda x: "flattened"
    mock_convert.side_effect = lambda x: "json_converted"

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
@patch("darkstar.core.db_helper.sanitize_string")
@patch("darkstar.core.db_helper.flatten_list")
def test_prepare_non_cve_data_parametrized(
    mock_flatten, mock_sanitize, vuln_data, expected_length
):
    """Parametrized test for prepare_non_cve_data with different vulnerability configurations."""
    # Set up mocks
    mock_sanitize.side_effect = lambda x: x  # Return the input unchanged
    mock_flatten.side_effect = lambda x: "flattened"

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
@patch("darkstar.core.db_helper.DatabaseConnectionManager")
def test_insert_bbot_to_db_parametrized(
    mock_db_manager, dataframe_data, org_name, expected_result
):
    """Parametrized test for insert_bbot_to_db with different DataFrame configurations."""
    # Set up mock connection manager and connection
    mock_connection = MagicMock()
    mock_cursor = MagicMock()
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
