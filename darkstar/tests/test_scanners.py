import os
import sys
import pandas as pd
import pytest
from pytest_mock import MockerFixture

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.bbot import BBotScanner
from scanners.nuclei.standard import NucleiScanner
from scanners.nuclei.wordpress import WordPressNucleiScanner


class TestBBotScanner:
    """Test the BBotScanner class."""

    def test_bbot_initialization(self, mocker: MockerFixture):
        """Test initializing the bbot scanner."""
        mock_makedirs = mocker.patch("scanners.bbot.os.makedirs")
        mock_exists = mocker.patch("scanners.bbot.os.path.exists", return_value=False)
        mock_md5 = mocker.patch("scanners.bbot.hashlib.md5")
        mock_md5().hexdigest.return_value = "abc123"

        scanner = BBotScanner("example.com", "test_org")

        assert scanner.target == "example.com"
        assert scanner.org_name == "test_org"
        assert scanner.folder == "/app/bbot_output"
        assert scanner.foldername == "abc123"
        mock_makedirs.assert_called_once_with("/app/bbot_output", exist_ok=True)

    def test_vulns_to_db(self, mocker: MockerFixture):
        """Test adding vulnerabilities to the database."""
        mock_makedirs = mocker.patch("scanners.bbot.os.makedirs")
        mock_insert = mocker.patch("scanners.bbot.insert_vulnerability_to_database")

        scanner = BBotScanner("example.com", "test_org")

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
        assert mock_insert.call_count == 2

    def test_vulns_to_db_no_vulnerabilities(self, mocker: MockerFixture):
        """Test vulns_to_db with no vulnerabilities."""
        mock_makedirs = mocker.patch("scanners.bbot.os.makedirs")

        scanner = BBotScanner("example.com", "test_org")

        # Create DataFrame with no vulnerability data
        data = {
            "Event type": ["DNS_NAME", "URL"],
            "Event data": ["example.com", "https://example.com"],
            "IP Address": ["1.1.1.1", "1.1.1.1"],
            "Source Module": ["module1", "module2"],
            "Scope Distance": [0, 1],
            "Event Tags": ["tag1", "tag2"],
        }
        df = pd.DataFrame(data)

        # Should not raise any exceptions
        scanner.vulns_to_db(df)

    def test_passive_scan(self, mocker: MockerFixture):
        """Test running a passive bbot scan."""
        mock_makedirs = mocker.patch("scanners.bbot.os.makedirs")
        mock_popen = mocker.patch("scanners.bbot.subprocess.Popen")
        mock_insert = mocker.patch("scanners.bbot.insert_bbot_to_db")
        mock_open_func = mocker.mock_open()
        mocker.patch("builtins.open", mock_open_func)
        mock_exists = mocker.patch("scanners.bbot.os.path.exists", return_value=True)

        mock_process = mocker.Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process

        scanner = BBotScanner("example.com", "test_org")

        # Mock the prep_data method
        scanner.prep_data = mocker.Mock(return_value="mock_dataframe")

        # Call the passive scan method
        scanner.passive()

        # Verify bbot command was run
        mock_popen.assert_called_once()
        call_args = mock_popen.call_args[0][0]
        assert call_args[0] == "/root/.local/bin/bbot"
        assert call_args[2] == "example.com"
        assert "passive" in call_args[4]

        # Verify target name was written to file
        mock_open_func.assert_called_with(
            f"{scanner.folder}/{scanner.foldername}/TARGET_NAME", "w"
        )

        # Verify data was inserted into the database
        mock_insert.assert_called_once_with("mock_dataframe", org_name="test_org")

    @pytest.mark.parametrize(
        "scan_mode,expected_flags",
        [
            ("passive", "safe,passive,cloud-enum,email-enum,social-enum,code-enum"),
            ("normal", "cloud-enum,email-enum,social-enum,code-enum,web-basic"),
            (
                "attack_surface",
                "safe,passive,subdomain-enum,cloud-enum,email-enum,social-enum,code-enum,web-basic,affiliates",
            ),
            (
                "aggressive",
                "safe,passive,active,deadly,aggressive,web-thorough,cloud-enum,code-enum,affiliates",
            ),
        ],
    )
    def test_run_scan_modes(
        self,
        scan_mode,
        expected_flags,
        mocker: MockerFixture,
    ):
        """Test different scan modes with parametrized testing."""
        mock_makedirs = mocker.patch("scanners.bbot.os.makedirs")
        mock_popen = mocker.patch("scanners.bbot.subprocess.Popen")
        mock_insert = mocker.patch("scanners.bbot.insert_bbot_to_db")
        mock_open_func = mocker.mock_open()
        mocker.patch("builtins.open", mock_open_func)

        mock_process = mocker.Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process

        scanner = BBotScanner("example.com", "test_org")
        scanner.prep_data = mocker.Mock(return_value=pd.DataFrame())

        # Call the run method with different modes
        scanner.run(mode=scan_mode)

        # Verify the correct flags were used
        mock_popen.assert_called_once()
        call_args = mock_popen.call_args[0][0]
        assert expected_flags in call_args[4]


class TestNucleiScanner:
    """Test the NucleiScanner class."""

    def test_nuclei_initialization(self, mocker: MockerFixture):
        """Test initializing the Nuclei scanner."""
        mock_open_func = mocker.mock_open(read_data="example.com\ntest.com\n")
        mocker.patch("builtins.open", mock_open_func)

        scanner = NucleiScanner("subdomains.txt", "test_org")
        assert scanner.file == "subdomains.txt"
        assert scanner.org_name == "test_org"
        assert scanner.target_count == 2

    def test_nuclei_initialization_file_error(self, mocker: MockerFixture):
        """Test Nuclei scanner initialization with file error."""
        mocker.patch("builtins.open", side_effect=FileNotFoundError("File not found"))

        scanner = NucleiScanner("nonexistent.txt", "test_org")
        assert scanner.file == "nonexistent.txt"
        assert scanner.org_name == "test_org"
        assert scanner.target_count == 0

    def test_run_calls_parent_for_standard_nuclei(self, mocker: MockerFixture):
        """Test that standard NucleiScanner run method starts a thread."""
        mock_thread = mocker.patch("scanners.nuclei.base.threading.Thread")

        scanner = NucleiScanner("subdomains.txt", "test_org")

        scanner.run()

        mock_thread.assert_called_once()
        mock_thread.return_value.start.assert_called_once()

    @pytest.mark.parametrize(
        "output_line,expected_url",
        [
            ("[test-vuln] https://example.com/path", "https://example.com/path"),
            ("[test-vuln] http://test.com", "http://test.com"),
            ("[test-vuln] example.com:443", "example.com"),
            ("[test-vuln] invalid output", "unknown"),
        ],
    )
    def test_extract_url_from_output(self, output_line, expected_url):
        """Test URL extraction from Nuclei output."""
        scanner = NucleiScanner("subdomains.txt", "test_org")
        result = scanner.extract_url_from_output(output_line)
        assert result == expected_url

    @pytest.mark.parametrize(
        "output_line,expected_severity",
        [
            ("[test-vuln:critical] https://example.com", "critical"),
            ("[test-vuln:high] https://example.com", "high"),
            ("[test-vuln:medium] https://example.com", "medium"),
            ("[test-vuln:low] https://example.com", "low"),
            ("[test-vuln] https://example.com", "unknown"),
        ],
    )
    def test_extract_severity(self, output_line, expected_severity):
        """Test severity extraction from Nuclei output."""
        scanner = NucleiScanner("subdomains.txt", "test_org")
        result = scanner.extract_severity(output_line)
        assert result == expected_severity


class TestWordPressNucleiScanner:
    """Test the WordPress-specific Nuclei scanner."""

    def test_nuclei_wordpress_initialization_string(self):
        """Test initializing the WordPress Nuclei scanner with string domains."""
        scanner = WordPressNucleiScanner("example.com,test.com", "test_org")
        assert scanner.domains == "example.com,test.com"
        assert scanner.org_name == "test_org"

    def test_nuclei_wordpress_initialization_list(self):
        """Test initializing the WordPress Nuclei scanner with list domains."""
        scanner = WordPressNucleiScanner(["example.com", "test.com"], "test_org")
        assert scanner.domains == "example.com,test.com"
        assert scanner.org_name == "test_org"

    @pytest.mark.parametrize(
        "input_text,expected_output",
        [
            ("\x1b[31mRed text\x1b[0m", "Red text"),
            ("\x1b[32mGreen text\x1b[0m", "Green text"),
            ("Normal text", "Normal text"),
            ("\x1b[31m\x1b[1mBold Red\x1b[0m", "Bold Red"),
            ("", ""),
        ],
    )
    def test_remove_ansi_codes(self, input_text, expected_output):
        """Test ANSI code removal from strings."""
        scanner = WordPressNucleiScanner("example.com", "test_org")
        clean_text = scanner.remove_ansi_codes(input_text)
        assert clean_text == expected_output

    @pytest.mark.parametrize(
        "domains_input,expected_output",
        [
            ("example.com,test.com", "example.com,test.com"),
            ("https://example.com,http://test.com", "example.com,test.com"),
            ("https://example.com/,http://test.com/", "example.com,test.com"),
            (["https://example.com", "http://test.com"], "example.com,test.com"),
            ("", ""),
        ],
    )
    def test_clean_domain_list(self, domains_input, expected_output):
        """Test domain list cleaning functionality."""
        scanner = WordPressNucleiScanner("dummy", "test_org")
        result = scanner._clean_domain_list(domains_input)
        assert result == expected_output

    def test_clean_domain_list_invalid_input(self):
        """Test domain list cleaning with invalid input."""
        scanner = WordPressNucleiScanner("dummy", "test_org")
        result = scanner._clean_domain_list(123)  # Invalid input type
        assert result == ""

    def test_run_calls_scan_nuclei_directly(self, mocker: MockerFixture):
        """Test that WordPress scanner run method calls scan_nuclei directly (no threading)."""
        scanner = WordPressNucleiScanner("example.com", "test_org")

        # Mock the scan_nuclei method to avoid actual scanning
        mock_scan = mocker.patch.object(scanner, "scan_nuclei")
        scanner.run()
        mock_scan.assert_called_once()

    def test_run_with_empty_domains(self):
        """Test run method with empty domains."""
        scanner = WordPressNucleiScanner("", "test_org")

        # Should not raise an exception and should return early
        scanner.run()

    def test_find_first_path_with_nuclei(self, mocker: MockerFixture):
        """Test finding nuclei template files."""
        mock_subprocess_run = mocker.patch("scanners.nuclei.wordpress.subprocess.run")

        scanner = WordPressNucleiScanner("example.com", "test_org")

        # Mock subprocess return
        mock_result = mocker.Mock()
        mock_result.stdout = "/path/to/nuclei/template.yaml\n/another/path"
        mock_subprocess_run.return_value = mock_result

        result = scanner.find_first_path_with_nuclei("template-hash")
        assert result == "/path/to/nuclei/template.yaml"

    def test_find_first_path_with_nuclei_not_found(self, mocker: MockerFixture):
        """Test finding nuclei template files when not found."""
        mock_subprocess_run = mocker.patch("scanners.nuclei.wordpress.subprocess.run")

        scanner = WordPressNucleiScanner("example.com", "test_org")

        # Mock subprocess return with no nuclei paths
        mock_result = mocker.Mock()
        mock_result.stdout = "/path/to/other/file.yaml\n/another/path"
        mock_subprocess_run.return_value = mock_result

        result = scanner.find_first_path_with_nuclei("template-hash")
        assert result is None


# Integration test fixtures
@pytest.fixture
def sample_bbot_scanner(mocker: MockerFixture):
    """Fixture providing a sample BBotScanner instance."""
    mocker.patch("scanners.bbot.os.makedirs")
    return BBotScanner("example.com", "test_org")


@pytest.fixture
def sample_nuclei_scanner(mocker: MockerFixture):
    """Fixture providing a sample NucleiScanner instance."""
    mock_open_func = mocker.mock_open(read_data="example.com\n")
    mocker.patch("builtins.open", mock_open_func)
    return NucleiScanner("test_file.txt", "test_org")


@pytest.fixture
def sample_wordpress_scanner():
    """Fixture providing a sample WordPressNucleiScanner instance."""
    return WordPressNucleiScanner("example.com", "test_org")


class TestScannerIntegration:
    """Integration tests for scanner classes."""

    def test_scanner_org_name_consistency(
        self, sample_bbot_scanner, sample_nuclei_scanner, sample_wordpress_scanner
    ):
        """Test that all scanners maintain org_name consistency."""
        assert sample_bbot_scanner.org_name == "test_org"
        assert sample_nuclei_scanner.org_name == "test_org"
        assert sample_wordpress_scanner.org_name == "test_org"

    def test_ansi_code_removal_consistency(
        self, sample_nuclei_scanner, sample_wordpress_scanner
    ):
        """Test that ANSI code removal works consistently across scanners."""
        test_string = "\x1b[31mRed text\x1b[0m"

        nuclei_result = sample_nuclei_scanner.remove_ansi_codes(test_string)
        wordpress_result = sample_wordpress_scanner.remove_ansi_codes(test_string)

        assert nuclei_result == wordpress_result == "Red text"
