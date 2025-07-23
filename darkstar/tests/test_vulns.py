import unittest
from unittest.mock import patch, MagicMock
from modules.vulns import CVE, Vulnerability


class TestCVE(unittest.TestCase):
    """Test cases for the CVE class."""

    def test_cve_initialization(self):
        """Test that CVE objects are correctly initialized with all attributes."""
        cve = CVE(
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

        # Check that all attributes were set correctly
        self.assertEqual(cve.cve, "CVE-2023-1234")
        self.assertEqual(cve.cvss, 8.5)
        self.assertEqual(cve.epss, 0.5)
        self.assertEqual(cve.summary, "Test summary")
        self.assertEqual(cve.cwe, "CWE-79")
        self.assertEqual(cve.references, ["ref1", "ref2"])
        self.assertEqual(cve.capec, "CAPEC-123")
        self.assertEqual(cve.solution, "Test solution")
        self.assertEqual(cve.impact, {"confidentiality": "high"})
        self.assertEqual(cve.access, {"vector": "network"})
        self.assertEqual(cve.age, 30)
        self.assertEqual(cve.pocs, ["poc1", "poc2"])
        self.assertTrue(cve.kev)

    @patch("subprocess.run")
    def test_search_epss_by_cve(self, mock_run):
        """Test that search_epss_by_cve correctly parses subprocess output."""
        # Set up mock
        mock_process = MagicMock()
        mock_process.stdout = "0.75"
        mock_run.return_value = mock_process

        # Call the function
        result = CVE.search_epss_by_cve("CVE-2023-1234")

        # Check the result
        self.assertEqual(result, 0.75)

        # Test error handling
        mock_process.stdout = "Not a number"
        result = CVE.search_epss_by_cve("CVE-2023-1234")
        self.assertEqual(result, "Unknown")


class TestVulnerability(unittest.TestCase):
    """Test cases for the Vulnerability class."""

    def test_vulnerability_initialization_without_cve(self):
        """Test that Vulnerability objects are correctly initialized without a CVE."""
        vuln = Vulnerability(
            title="Test Vulnerability",
            affected_item="test.com",
            tool="nuclei",
            confidence=90,
            severity="high",
            host="192.168.1.1",
            summary="Test summary",
            impact="Test impact",
            solution="Test solution",
            poc="https://test.com/poc",
            references="https://test.com/ref",
            epss=0.3,
            cvss=7.5,
            cwe="CWE-352",
            capec="CAPEC-456",
        )

        # Check that all attributes were set correctly
        self.assertEqual(vuln.title, "Test Vulnerability")
        self.assertEqual(vuln.affected_item, "test.com")
        self.assertEqual(vuln.tool, "nuclei")
        self.assertEqual(vuln.confidence, 90)
        self.assertEqual(vuln.severity, "high")
        self.assertEqual(vuln.host, "192.168.1.1")
        self.assertEqual(vuln.summary, "Test summary")
        self.assertEqual(vuln.impact, "Test impact")
        self.assertEqual(vuln.solution, "Test solution")
        self.assertEqual(vuln.poc, "https://test.com/poc")
        self.assertEqual(vuln.references, "https://test.com/ref")
        self.assertEqual(vuln.epss, 0.3)
        self.assertEqual(vuln.cvss, 7.5)
        self.assertEqual(vuln.cwe, "CWE-352")
        self.assertEqual(vuln.capec, "CAPEC-456")

    @patch("modules.vulns.Vulnerability.cve_enricher")
    def test_vulnerability_initialization_with_cve(self, mock_enricher):
        """Test that Vulnerability objects are correctly initialized with a CVE."""
        # Set up mock
        mock_cve = CVE(cve="CVE-2023-1234")
        mock_enricher.return_value = mock_cve

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
        self.assertEqual(vuln.cve, mock_cve)

        # Check that the enricher was called with the correct argument
        mock_enricher.assert_called_once_with("CVE-2023-1234")

    @patch("modules.vulns.CVE.search_epss_by_cve")
    @patch("modules.vulns.requests.get")
    @patch("modules.vulns.pd.read_csv")
    def test_cve_enricher(self, mock_read_csv, mock_get, mock_search_epss):
        """Test that cve_enricher correctly enriches a CVE."""
        # Set up mocks
        mock_search_epss.return_value = 0.75

        # Create a mock DataFrame with proper 'in' check for the cveID column
        mock_df = MagicMock()
        mock_df_values = MagicMock()
        mock_df_values.values = ["CVE-2023-1234"]
        mock_df.__getitem__.return_value = mock_df_values
        mock_df.__contains__ = MagicMock(
            return_value=False
        )  # First check for direct column access
        mock_read_csv.return_value = mock_df

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

        # Create a vulnerability with CVE
        vuln = Vulnerability(
            title="Test Vulnerability",
            affected_item="test.com",
            tool="nuclei",
            confidence=90,
            severity="high",
            host="192.168.1.1",
            cve_number="",  # Empty string should not trigger enrichment
        )

        # Configure the mock to return True when 'CVE-2023-1234' is in cveID.values
        # This simulates that the CVE is in the KEV dataset
        def mock_contains(item):
            if item == "cveID":
                return True
            return False

        mock_df.__contains__.side_effect = mock_contains

        # Manually call enricher
        cve = vuln.cve_enricher("CVE-2023-1234")

        # Check that the enricher created a CVE with the correct attributes
        self.assertEqual(cve.cve, "CVE-2023-1234")
        self.assertEqual(cve.cvss, 8.5)
        self.assertEqual(cve.epss, 0.75)
        self.assertEqual(cve.summary, "Test summary")
        self.assertEqual(cve.cwe, "CWE-79")
        self.assertEqual(cve.references, ["ref1", "ref2"])
        self.assertEqual(cve.capec, "CAPEC-123")
        self.assertEqual(cve.solution, "Update to latest version")
        self.assertEqual(cve.impact, {"confidentiality": "high"})
        self.assertEqual(cve.access, {"vector": "network"})
        self.assertTrue(isinstance(cve.age, int))
        self.assertTrue(cve.kev)


if __name__ == "__main__":
    unittest.main()
