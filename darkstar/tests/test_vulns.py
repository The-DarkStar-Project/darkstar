import pytest
from unittest.mock import patch, MagicMock
from darkstar.core.models.vulnerability import CVE, Vulnerability


class TestCVE:
    """Test cases for the CVE class."""

    @pytest.mark.parametrize(
        "subprocess_output,expected_result",
        [
            ("0.75", 0.75),
            ("0.25", 0.25),
            ("0.0", 0.0),
            ("1.0", 1.0),
            ("Not a number", "Unknown"),
            ("", "Unknown"),
            ("invalid", "Unknown"),
        ],
    )
    @patch("subprocess.run")
    def test_search_epss_by_cve(self, mock_run, subprocess_output, expected_result):
        """Test that search_epss_by_cve correctly parses subprocess output."""
        # Set up mock
        mock_process = MagicMock()
        mock_process.stdout = subprocess_output
        mock_run.return_value = mock_process

        # Call the function
        result = CVE.search_epss_by_cve("CVE-2023-1234")

        # Check the result
        assert result == expected_result

        # Verify subprocess was called correctly
        mock_run.assert_called_once_with(
            [
                "tools/scripts/search_epss",
                "data/epss_scores-current.csv",
                "CVE-2023-1234",
            ],
            capture_output=True,
            text=True,
        )


class TestVulnerability:
    """Test cases for the Vulnerability class."""

    @pytest.fixture
    def mock_cve_enricher(self):
        """Fixture that provides a mock CVE enricher."""
        with patch(
            "darkstar.core.models.vulnerability.Vulnerability.cve_enricher"
        ) as mock:
            mock_cve = CVE(cve="CVE-2023-1234")
            mock.return_value = mock_cve
            yield mock

    def test_vulnerability_initialization_with_cve(self, mock_cve_enricher):
        """Test that Vulnerability objects are correctly initialized with a CVE."""
        # Create vulnerability with CVE
        vuln = Vulnerability(
            title="Test Vulnerability",
            affected_item="test.com",
            tool="nuclei",
            confidence=90,
            severity="high",
            host="192.168.1.1",
            cve_number="CVE-2023-1234",
        )

        # Check that the cve attribute was set correctly
        assert hasattr(vuln, "cve")
        assert vuln.cve.cve == "CVE-2023-1234"

        # Check that the enricher was called with the correct argument
        mock_cve_enricher.assert_called_once_with("CVE-2023-1234")

    @pytest.fixture
    def mock_external_dependencies(self):
        """Fixture that mocks all external dependencies for CVE enrichment."""
        with (
            patch(
                "darkstar.core.models.vulnerability.CVE.search_epss_by_cve"
            ) as mock_epss,
            patch("darkstar.core.models.vulnerability.requests.get") as mock_get,
            patch("darkstar.core.models.vulnerability.pd.read_csv") as mock_read_csv,
        ):
            # Set up EPSS mock
            mock_epss.return_value = 0.75

            # Set up DataFrame mock for KEV data
            mock_df = MagicMock()
            mock_df_values = MagicMock()
            mock_df_values.values = ["CVE-2023-1234"]
            mock_df.__getitem__.return_value = mock_df_values
            mock_df.__contains__ = MagicMock(return_value=True)
            mock_read_csv.return_value = mock_df

            # Set up requests mock
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "solution": "Update to latest version",
                "impact": {"confidentiality": "high"},
                "access": {"vector": "network"},
                "references": ["ref1", "ref2"],
                "Published": "2023-01-01T12:00:00",
                "cvss": 8.5,
                "cwe": "CWE-79",
                "capec": "CAPEC-123",
                "summary": "Test summary",
            }
            mock_get.return_value = mock_response

            yield {
                "mock_epss": mock_epss,
                "mock_get": mock_get,
                "mock_read_csv": mock_read_csv,
                "mock_df": mock_df,
            }

    def test_cve_enricher_success(self, mock_external_dependencies):
        """Test that cve_enricher correctly enriches a CVE."""
        # Create a vulnerability instance
        vuln = Vulnerability(
            title="Test Vulnerability",
            affected_item="test.com",
            tool="nuclei",
            confidence=90,
            severity="high",
            host="192.168.1.1",
        )

        # Manually call enricher
        cve = vuln.cve_enricher("CVE-2023-1234")

        # Check that the enricher created a CVE with the correct attributes
        assert cve.cve == "CVE-2023-1234"
        assert cve.cvss == 8.5
        assert cve.epss == 0.75
        assert cve.summary == "Test summary"
        assert cve.cwe == "CWE-79"
        assert cve.references == ["ref1", "ref2"]
        assert cve.capec == "CAPEC-123"
        assert cve.solution == "Update to latest version"
        assert cve.impact == {"confidentiality": "high"}
        assert cve.access == {"vector": "network"}
        assert isinstance(cve.age, int)
        assert cve.kev is True

    @pytest.mark.parametrize(
        "status_code,json_response,expected_result",
        [
            (404, None, None),
            (500, None, None),
            (200, {}, None),  # Empty response
        ],
    )
    def test_cve_enricher_failure_cases(
        self, status_code, json_response, expected_result
    ):
        """Test that cve_enricher handles failure cases correctly."""
        with (
            patch(
                "darkstar.core.models.vulnerability.CVE.search_epss_by_cve"
            ) as mock_epss,
            patch("darkstar.core.models.vulnerability.requests.get") as mock_get,
            patch("darkstar.core.models.vulnerability.pd.read_csv") as mock_read_csv,
        ):
            # Set up mocks
            mock_epss.return_value = 0.5
            mock_df = MagicMock()
            mock_df.__contains__.return_value = False
            mock_read_csv.return_value = mock_df

            mock_response = MagicMock()
            mock_response.status_code = status_code
            if json_response is not None:
                mock_response.json.return_value = json_response
            else:
                mock_response.json.return_value = {}
            mock_get.return_value = mock_response

            # Create vulnerability and test enricher
            vuln = Vulnerability(
                title="Test",
                affected_item="test.com",
                tool="nuclei",
                confidence=90,
                severity="high",
                host="192.168.1.1",
            )

            result = vuln.cve_enricher("CVE-2023-9999")
            assert result == expected_result

    def test_vulnerability_with_empty_cve_number(self):
        """Test that empty CVE number doesn't trigger enrichment."""
        vuln = Vulnerability(
            title="Test Vulnerability",
            affected_item="test.com",
            tool="nuclei",
            confidence=90,
            severity="high",
            host="192.168.1.1",
            cve_number="",  # Empty string should not trigger enrichment
            summary="Manual summary",
        )

        # Should not have CVE attribute
        assert not hasattr(vuln, "cve")
        assert vuln.summary == "Manual summary"
