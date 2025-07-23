import unittest
from unittest.mock import patch, MagicMock
import pandas as pd
import json
from modules.db_helper import (
    insert_bbot_to_db,
    sanitize_string,
    flatten_list,
    convert_to_json,
    prepare_cve_data,
    prepare_non_cve_data,
)
from modules.vulns import Vulnerability, CVE


class TestDbHelper(unittest.TestCase):
    """Test cases for the database helper functions."""

    def test_sanitize_string(self):
        """Test that sanitize_string properly removes ANSI codes and trims strings."""
        # Test with ANSI escape codes
        ansi_string = "\x1b[31mRed text\x1b[0m"
        self.assertEqual(sanitize_string(ansi_string), "Red text")

        # Test with spaces
        space_string = "  text with spaces   "
        self.assertEqual(sanitize_string(space_string), "text with spaces")

        # Test with non-string
        non_string = 123
        self.assertEqual(sanitize_string(non_string), 123)

    def test_flatten_list(self):
        """Test that flatten_list correctly converts lists to comma-separated strings."""
        # Test with list of strings
        string_list = ["a", "b", "c"]
        self.assertEqual(flatten_list(string_list), "a, b, c")

        # Test with list of numbers
        number_list = [1, 2, 3]
        self.assertEqual(flatten_list(number_list), "1, 2, 3")

        # Test with non-list
        non_list = "not a list"
        self.assertEqual(flatten_list(non_list), "not a list")

    def test_convert_to_json(self):
        """Test that convert_to_json correctly serializes dictionaries to JSON strings."""
        # Test with dictionary
        test_dict = {"key": "value", "number": 123}
        self.assertEqual(convert_to_json(test_dict), json.dumps(test_dict))

        # Test with non-dictionary
        non_dict = "not a dict"
        self.assertEqual(convert_to_json(non_dict), "not a dict")

    @patch("modules.db_helper.sanitize_string")
    @patch("modules.db_helper.flatten_list")
    @patch("modules.db_helper.convert_to_json")
    def test_prepare_cve_data(self, mock_convert, mock_flatten, mock_sanitize):
        """Test that prepare_cve_data correctly processes CVE data."""
        # Set up mocks
        mock_sanitize.side_effect = lambda x: x  # Return the input unchanged
        mock_flatten.side_effect = lambda x: "flattened"
        mock_convert.side_effect = lambda x: "json_converted"

        # Create a test vulnerability with CVE
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

        vuln = Vulnerability(
            title="Test CVE",
            affected_item="test.com",
            tool="nuclei",
            confidence=90,
            severity="high",
            host="192.168.1.1",
        )
        vuln.cve = cve

        # Call the function
        result = prepare_cve_data(vuln)

        # Check that the result is a tuple with the correct length
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 19)

        # Check that the mocks were called
        mock_sanitize.assert_called()
        mock_flatten.assert_called()
        mock_convert.assert_called()

    @patch("modules.db_helper.sanitize_string")
    @patch("modules.db_helper.flatten_list")
    def test_prepare_non_cve_data(self, mock_flatten, mock_sanitize):
        """Test that prepare_non_cve_data correctly processes non-CVE data."""
        # Set up mocks
        mock_sanitize.side_effect = lambda x: x  # Return the input unchanged
        mock_flatten.side_effect = lambda x: "flattened"

        # Create a test non-CVE vulnerability
        vuln = Vulnerability(
            title="Test non-CVE",
            affected_item="test.com",
            tool="nuclei",
            confidence=90,
            severity="medium",
            host="192.168.1.1",
            summary="Test summary",
            impact="Test impact",
            solution="Test solution",
            poc=["poc1", "poc2"],
            references=["ref1", "ref2"],
            cvss=7.5,
            epss=0.3,
            cwe="CWE-352",
            capec="CAPEC-456",
        )

        # Call the function
        result = prepare_non_cve_data(vuln)

        # Check that the result is a tuple with the correct length
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 19)

        # Check that the mocks were called
        mock_sanitize.assert_called()
        mock_flatten.assert_called()

    @patch("modules.db_helper.mysql.connector.connect")
    def test_insert_bbot_to_db(self, mock_connect):
        """Test that insert_bbot_to_db correctly inserts data into the database."""
        # Set up mock connection
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_connection
        mock_connection.is_connected.return_value = True
        mock_connection.cursor.return_value = mock_cursor

        # Create test data
        test_data = pd.DataFrame(
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

        # Call the function
        insert_bbot_to_db(test_data, "test_org")

        # Check that the connection was used correctly
        mock_connect.assert_called_once()
        mock_cursor.execute.assert_called()
        mock_connection.commit.assert_called_once()
        mock_connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
