import unittest
import os
import sys
import pandas as pd
from unittest.mock import patch, MagicMock, mock_open

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.scanners import bbot, nuclei, nuclei_wordpress


class TestBbot(unittest.TestCase):
    """Test the bbot scanner class."""

    @patch("os.mkdir")
    @patch("os.path.exists")
    @patch("hashlib.md5")
    def test_bbot_initialization(self, mock_md5, mock_exists, mock_mkdir):
        """Test initializing the bbot scanner."""
        mock_exists.return_value = False
        mock_md5().hexdigest.return_value = "abc123"

        scanner = bbot("example.com", "test_org")

        self.assertEqual(scanner.target, "example.com")
        self.assertEqual(scanner.org_name, "test_org")
        self.assertEqual(scanner.folder, "/app/bbot_output")
        self.assertEqual(scanner.foldername, "abc123")
        mock_mkdir.assert_called_once_with("/app/bbot_output")

    @patch("modules.scanners.insert_vulnerability_to_database")
    def test_vulns_to_db(self, mock_insert):
        """Test adding vulnerabilities to the database."""
        scanner = bbot("example.com", "test_org")

        # Create a mock DataFrame with vulnerability findings
        data = {
            "Event type": ["VULNERABILITY", "FINDING"],
            "Event data": [
                "{'severity': 'high', 'host': 'example.com', 'url': 'https://example.com/vuln', 'description': 'Test vuln'}",
                "{'host': 'example.com', 'url': 'https://example.com/finding', 'description': 'Test finding'}",
            ],
            "IP Address": ["1.1.1.1", "2.2.2.2"],
            "Source Module": ["module1", "module2"],
            "Scope Distance": [0, 1],
            "Event Tags": ["tag1", "tag2"],
        }
        df = pd.DataFrame(data)

        # Call the method under test
        scanner.vulns_to_db(df)

        # Assert that the insert function was called twice (once per row)
        self.assertEqual(mock_insert.call_count, 2)

    @patch("modules.scanners.subprocess.run")
    @patch("modules.scanners.insert_bbot_to_db")
    @patch("builtins.open", new_callable=mock_open)
    @patch("modules.scanners.os.path.exists")
    def test_passive_scan(self, mock_exists, mock_open, mock_insert, mock_run):
        """Test running a passive bbot scan."""
        mock_exists.return_value = True
        scanner = bbot("example.com", "test_org")

        # Mock the prep_data method
        scanner.prep_data = MagicMock(return_value="mock_dataframe")

        # Call the passive scan method
        scanner.passive()

        # Verify bbot command was run with passive flags
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertEqual(args[0], "/root/.local/bin/bbot")
        self.assertEqual(args[2], "example.com")
        self.assertIn("passive", args[4])

        # Verify target name was written to file
        mock_open.assert_called_with(
            f"{scanner.folder}/{scanner.foldername}/TARGET_NAME", "w"
        )
        mock_open().write.assert_called_once_with("example.com")

        # Verify data was inserted into the database
        mock_insert.assert_called_once_with("mock_dataframe", org_name="test_org")


class TestNuclei(unittest.TestCase):
    """Test the Nuclei scanner class."""

    def test_nuclei_initialization(self):
        """Test initializing the Nuclei scanner."""
        scanner = nuclei("subdomains.txt", "test_org")
        self.assertEqual(scanner.file, "subdomains.txt")
        self.assertEqual(scanner.org_name, "test_org")

    @patch("modules.scanners.threading.Thread")
    def test_run_starts_thread(self, mock_thread):
        """Test that run starts a separate thread."""
        scanner = nuclei("subdomains.txt", "test_org")

        scanner.run()

        mock_thread.assert_called_once()
        mock_thread.return_value.start.assert_called_once()


class TestNucleiWordPress(unittest.TestCase):
    """Test the WordPress-specific Nuclei scanner."""

    def test_nuclei_wordpress_initialization(self):
        """Test initializing the WordPress Nuclei scanner."""
        scanner = nuclei_wordpress("example.com,test.com", "test_org")
        self.assertEqual(scanner.domains, "example.com,test.com")
        self.assertEqual(scanner.org_name, "test_org")

    def test_remove_ansi_codes(self):
        """Test ANSI code removal from strings."""
        scanner = nuclei_wordpress("example.com", "test_org")
        text_with_ansi = "\x1b[31mRed text\x1b[0m"
        clean_text = scanner.remove_ansi_codes(text_with_ansi)
        self.assertEqual(clean_text, "Red text")


if __name__ == "__main__":
    unittest.main()
