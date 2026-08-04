import json
import os
import sys
import pandas as pd
import pytest
from pytest_mock import MockerFixture

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.bbot import BBotScanner
from scanners.nuclei import NucleiScanner, NucleiMode
from scanners.asteroid_scanner import AsteroidScanner


class TestBBotScanner:
    """Test the BBotScanner class."""

    def test_bbot_initialization(self, mocker: MockerFixture):
        """Test initializing the bbot scanner."""
        mock_makedirs = mocker.patch("scanners.bbot.os.makedirs")
        mocker.patch("scanners.bbot.shutil.which", return_value=None)
        mocker.patch("scanners.bbot.secrets.token_hex", return_value="abc123")

        scanner = BBotScanner("example.com", "test_org")

        assert scanner.target == "example.com"
        assert scanner.org_name == "test_org"
        assert scanner.folder == "/app/bbot_output"
        assert scanner.foldername == "abc123"
        assert scanner.scan_dir == "/app/bbot_output/abc123"
        assert scanner.bbot_binary == "/root/.local/bin/bbot"
        mock_makedirs.assert_called_once_with("/app/bbot_output/abc123", exist_ok=True)

    def test_vulns_to_db(self, mocker: MockerFixture):
        """Test adding vulnerabilities to the database."""
        mocker.patch("scanners.bbot.os.makedirs")
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
        mocker.patch("scanners.bbot.os.makedirs")

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
        mocker.patch("scanners.bbot.os.makedirs")
        mock_popen = mocker.patch("scanners.bbot.subprocess.Popen")
        mock_insert = mocker.patch("scanners.bbot.insert_bbot_to_db")
        mock_open_func = mocker.mock_open()
        mocker.patch("builtins.open", mock_open_func)
        mocker.patch("scanners.bbot.os.path.exists", return_value=True)
        mocker.patch("scanners.bbot.os.path.isfile", return_value=True)

        mock_process = mocker.Mock()
        mock_process.communicate.return_value = ("", "")
        mock_process.returncode = 0
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
            f"{scanner.folder}/{scanner.foldername}/TARGET_NAME",
            "w",
            encoding="utf-8",
        )

        # Verify data was inserted into the database
        mock_insert.assert_called_once_with("mock_dataframe", org_name="test_org")

    @pytest.mark.parametrize(
        "scan_mode,expected_flags",
        [
            ("passive", "safe,passive,cloud-enum,email-enum,social-enum,code-enum"),
            ("normal", "safe,passive,subdomain-enum,cloud-enum,email-enum,social-enum,code-enum,web,affiliates"),
            ("attack_surface", "anubisdb"),
            (
                "aggressive",
                "safe,passive,subdomain-enum,active,loud,invasive,web-heavy,"
                "cloud-enum,email-enum,social-enum,code-enum,affiliates",
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
        mocker.patch("scanners.bbot.os.makedirs")
        mock_popen = mocker.patch("scanners.bbot.subprocess.Popen")
        mocker.patch("scanners.bbot.insert_bbot_to_db")
        mock_open_func = mocker.mock_open()
        mocker.patch("builtins.open", mock_open_func)
        mocker.patch("scanners.bbot.os.path.isfile", return_value=True)

        mock_process = mocker.Mock()
        mock_process.communicate.return_value = ("", "")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        scanner = BBotScanner("example.com", "test_org")
        scanner.prep_data = mocker.Mock(return_value=pd.DataFrame())

        # Call the run method with different modes
        scanner.run(mode=scan_mode)

        # Verify the correct flags were used
        mock_popen.assert_called_once()
        call_args = mock_popen.call_args[0][0]
        assert expected_flags in call_args
        if scan_mode == "attack_surface":
            excluded_modules = call_args[call_args.index("-em") + 1:call_args.index("-ef")]
            assert "trufflehog" in excluded_modules
            assert "gowitness" in excluded_modules
            assert "kreuzberg" in excluded_modules
            assert "extractous" not in call_args
            assert "http" in call_args
            assert "httpx" not in call_args
        if scan_mode == "aggressive":
            enabled_modules = call_args[call_args.index("-m") + 1]
            assert "webbrute" in enabled_modules
            assert "ffuf" not in enabled_modules
            assert "--allow-deadly" not in call_args

    def test_zero_exit_without_csv_surfaces_bbot_validation_error(
        self,
        mocker: MockerFixture,
    ):
        """BBOT 3 may return zero after rejecting invalid CLI arguments."""
        mocker.patch("scanners.bbot.os.makedirs")
        mocker.patch("scanners.bbot.os.path.isfile", return_value=False)
        mock_popen = mocker.patch("scanners.bbot.subprocess.Popen")
        mock_insert = mocker.patch("scanners.bbot.insert_bbot_to_db")

        mock_process = mocker.Mock()
        mock_process.communicate.return_value = ("", "Invalid flag: web-basic")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        scanner = BBotScanner("example.com", "test_org")

        with pytest.raises(RuntimeError, match="did not produce.*Invalid flag: web-basic"):
            scanner.normal()

        mock_insert.assert_not_called()

    def test_nonzero_bbot_exit_is_not_processed(self, mocker: MockerFixture):
        mocker.patch("scanners.bbot.os.makedirs")
        mocker.patch("scanners.bbot.os.path.isfile", return_value=False)
        mock_popen = mocker.patch("scanners.bbot.subprocess.Popen")
        mock_insert = mocker.patch("scanners.bbot.insert_bbot_to_db")

        mock_process = mocker.Mock()
        mock_process.communicate.return_value = ("", "dependency setup failed")
        mock_process.returncode = 2
        mock_popen.return_value = mock_process

        scanner = BBotScanner("example.com", "test_org")

        with pytest.raises(RuntimeError, match="exited with code 2.*dependency setup failed"):
            scanner.passive()

        mock_insert.assert_not_called()

    def test_bbot_environment_exposes_application_tzdata(self, tmp_path, mocker):
        timezone_path = tmp_path / "zoneinfo"
        timezone_path.mkdir()
        mocker.patch("scanners.bbot.os.environ.copy", return_value={})
        mocker.patch("scanners.bbot.files").return_value.joinpath.return_value = (
            timezone_path
        )

        environment = BBotScanner._bbot_environment()

        assert environment["PYTHONTZPATH"] == str(timezone_path)


class TestNucleiScanner:
    """Test the NucleiScanner class."""

    def test_nuclei_initialization(self, mocker: MockerFixture):
        """Test initializing the Nuclei scanner."""
        mock_open_func = mocker.mock_open(read_data="example.com\ntest.com\n")
        mocker.patch("builtins.open", mock_open_func)
        mocker.patch("os.path.exists", return_value=True)

        scanner = NucleiScanner("subdomains.txt", "test_org")
        assert scanner.target == "subdomains.txt"
        assert scanner.org_name == "test_org"
        assert scanner.target_count == 2

    def test_nuclei_initialization_no_file(self, mocker: MockerFixture):
        """Test Nuclei scanner initialization without an existing file."""
        mocker.patch("os.path.exists", return_value=False)

        scanner = NucleiScanner("testphp.vulnweb.com", "test_org")
        # A unique temp file is created instead of the fixed /tmp/targets.txt
        assert scanner.target.startswith("/tmp/nuclei_targets_")
        assert scanner._temp_target_file == scanner.target
        assert scanner.org_name == "test_org"
        assert scanner.target_count == 1

    def test_run_executes_without_redundant_nested_thread(self, mocker: MockerFixture):
        mocker.patch("scanners.nuclei.os.path.exists", return_value=True)
        mocker.patch("builtins.open", mocker.mock_open(read_data="example.com\n"))

        scanner = NucleiScanner("subdomains.txt", "test_org")
        mock_scan = mocker.patch.object(scanner, "scan_nuclei")

        scanner.run()

        mock_scan.assert_called_once_with()

    def test_scan_nuclei(self, mocker: MockerFixture):
        # Mock subprocess.Popen
        mock_popen = mocker.patch("scanners.nuclei.subprocess.Popen")
        mock_update = mocker.patch(
            "scanners.nuclei._update_nuclei_templates_if_due"
        )
        mocker.patch("scanners.nuclei.os.path.isdir", return_value=True)
        mocker.patch("scanners.nuclei._has_nuclei_templates", return_value=True)
        
        # Create mock process with proper stdout behavior
        mock_process = mocker.Mock()
        
        # Mock the JSON output as a string (what readline() would return)
        json_output = '''{
  "template": "dast/vulnerabilities/sqli/sqli-error-based.yaml",
  "template-url": "https://cloud.projectdiscovery.io/public/sqli-error-based",
  "template-id": "sqli-error-based",
  "info": {
    "name": "Error based SQL Injection",
    "author": ["geeknik", "pdteam"],
    "tags": ["sqli", "error", "dast"],
    "description": "Direct SQL Command Injection vulnerability",
    "severity": "critical"
  },
  "type": "http",
  "host": "testphp.vulnweb.com",
  "url": "http://testphp.vulnweb.com/search.php?test=query",
  "severity": "critical"
}'''
        
        # Mock readline to return the JSON output once, then empty string, then continue returning empty strings
        mock_process.stdout.readline.side_effect = [json_output, '', '', '', '']  # Add more empty strings
        mock_process.poll.side_effect = [None, 0]  # First call returns None (process running), second returns 0 (finished)
        mock_process.stderr.read.return_value = ""
        mock_process.wait.return_value = 0
        
        mock_popen.return_value = mock_process

        mock_insert = mocker.patch(
            "scanners.nuclei.insert_vulnerabilities_to_database",
            return_value=1,
        )

        scanner = NucleiScanner("subdomains.txt", "test_org")
        scanner.scan_nuclei()

        mock_update.assert_called_once_with("/root/nuclei-templates")
        scan_command = mock_popen.call_args.args[0]
        severity_filter = scan_command[scan_command.index("-s") + 1].split(",")
        assert "info" in severity_filter
        mock_insert.assert_called_once()
        
        findings, org_name = mock_insert.call_args.args
        assert len(findings) == 1
        vuln = findings[0]
        
        assert vuln.title == "Error based SQL Injection"
        assert vuln.affected_item == "http://testphp.vulnweb.com/search.php?test=query"
        assert vuln.tool == "nuclei"
        assert vuln.confidence == 97
        assert vuln.severity == "critical"
        assert vuln.host == "testphp.vulnweb.com"
        assert org_name == "test_org"

    def test_scan_nuclei_persists_informational_findings(
        self,
        mocker: MockerFixture,
    ):
        mock_popen = mocker.patch("scanners.nuclei.subprocess.Popen")
        mocker.patch("scanners.nuclei._update_nuclei_templates_if_due")
        mocker.patch("scanners.nuclei._has_nuclei_templates", return_value=True)

        output = json.dumps(
            {
                "template-id": "http-missing-security-headers",
                "info": {
                    "name": "HTTP Missing Security Headers",
                    "description": "A security response header is missing.",
                    "severity": "info",
                },
                "host": "testaspnet.vulnweb.com",
                "url": "http://testaspnet.vulnweb.com/",
                "severity": "info",
            }
        )
        process = mocker.Mock()
        process.stdout.readline.side_effect = [output, ""]
        process.poll.return_value = 0
        process.stderr.read.return_value = ""
        process.wait.return_value = 0
        mock_popen.return_value = process
        mock_insert = mocker.patch(
            "scanners.nuclei.insert_vulnerabilities_to_database",
            return_value=1,
        )

        scanner = NucleiScanner("subdomains.txt", "test_org")
        scanner.scan_nuclei()

        mock_insert.assert_called_once()
        findings, org_name = mock_insert.call_args.args
        assert org_name == "test_org"
        vulnerability = findings[0]
        assert vulnerability.severity == "info"
        assert vulnerability.title == "HTTP Missing Security Headers"
        assert vulnerability.host == "testaspnet.vulnweb.com"

    def test_empty_template_directory_does_not_launch_nuclei(
        self,
        mocker: MockerFixture,
    ):
        mocker.patch("scanners.nuclei._update_nuclei_templates_if_due")
        mock_popen = mocker.patch("scanners.nuclei.subprocess.Popen")
        mocker.patch("scanners.nuclei._has_nuclei_templates", return_value=False)

        scanner = NucleiScanner("subdomains.txt", "test_org")
        with pytest.raises(RuntimeError, match="No Nuclei YAML templates"):
            scanner.scan_nuclei()

        mock_popen.assert_not_called()

    def test_nonzero_nuclei_exit_fails_the_stage(self, mocker: MockerFixture):
        mocker.patch("scanners.nuclei._update_nuclei_templates_if_due")
        mocker.patch("scanners.nuclei._has_nuclei_templates", return_value=True)
        process = mocker.Mock()
        process.stdout.readline.return_value = ""
        process.poll.return_value = 2
        process.stderr.read.return_value = "template parse failure"
        process.wait.return_value = 2
        mocker.patch("scanners.nuclei.subprocess.Popen", return_value=process)

        scanner = NucleiScanner("subdomains.txt", "test_org")
        with pytest.raises(RuntimeError, match="Nuclei exited with code 2"):
            scanner.scan_nuclei()

    def test_template_update_skips_recent_shared_update(self, tmp_path, mocker):
        from scanners.nuclei import (
            NUCLEI_UPDATE_MARKER,
            _update_nuclei_templates_if_due,
        )

        marker = tmp_path / NUCLEI_UPDATE_MARKER
        marker.touch()
        os.utime(marker, (100, 100))
        mock_run = mocker.patch("scanners.nuclei.subprocess.run")

        updated = _update_nuclei_templates_if_due(
            str(tmp_path), interval=60, now=120
        )

        assert updated is False
        mock_run.assert_not_called()

    def test_template_update_marks_success_for_other_scanners(self, tmp_path, mocker):
        from scanners.nuclei import (
            NUCLEI_UPDATE_MARKER,
            _update_nuclei_templates_if_due,
        )

        mock_run = mocker.patch("scanners.nuclei.subprocess.run")
        mock_run.return_value.returncode = 0

        updated = _update_nuclei_templates_if_due(
            str(tmp_path), interval=60, now=120
        )

        assert updated is True
        assert (tmp_path / NUCLEI_UPDATE_MARKER).exists()
        command = mock_run.call_args.args[0]
        assert command[-2:] == [str(tmp_path), "-silent"]

    def test_template_directory_requires_yaml(self, tmp_path):
        from scanners.nuclei import (
            _has_nuclei_templates,
            _select_nuclei_templates_dir,
        )

        assert not _has_nuclei_templates(str(tmp_path))
        (tmp_path / "README.md").write_text("metadata only", encoding="utf-8")
        assert not _has_nuclei_templates(str(tmp_path))

        network_dir = tmp_path / "network"
        network_dir.mkdir()
        (network_dir / "service.yaml").write_text("id: service", encoding="utf-8")
        assert _has_nuclei_templates(str(tmp_path))

        assert _select_nuclei_templates_dir(str(tmp_path)) == str(tmp_path)

    def test_empty_existing_template_directory_uses_recovery_path(self, tmp_path):
        from scanners.nuclei import _select_nuclei_templates_dir

        templates_dir = tmp_path / "nuclei-templates"
        templates_dir.mkdir()
        (templates_dir / "README.md").write_text("metadata only", encoding="utf-8")

        selected = _select_nuclei_templates_dir(str(templates_dir))

        assert selected == f"{templates_dir}-darkstar"
        assert not os.path.exists(selected)


class TestAsteroidScanner:
    """Test the AsteroidScanner class."""

    def test_asteroid_initialization_single_target(self, mocker: MockerFixture):
        """Test initializing the asteroid scanner with a single target."""
        _mock_makedirs = mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch(
            "scanners.asteroid_scanner.os.path.exists", return_value=False
        )

        scanner = AsteroidScanner("example.com", "test_org")

        assert scanner.target == "example.com"
        assert scanner.org_name == "test_org"
        assert scanner.output_dir == "/app/asteroid_output"
        assert scanner.list_of_targets == ["http://example.com"]
        _mock_makedirs.assert_called_once_with("/app/asteroid_output")

    def test_asteroid_initialization_multiple_targets(self, mocker: MockerFixture):
        """Test initializing the asteroid scanner with multiple comma-separated targets."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)

        scanner = AsteroidScanner(
            "example.com, test.com, https://secure.com", "test_org"
        )

        assert scanner.target == "example.com, test.com, https://secure.com"
        assert scanner.list_of_targets == [
            "http://example.com",
            "http://test.com",
            "https://secure.com",
        ]

    def test_asteroid_initialization_file_target(self, mocker: MockerFixture):
        """Test initializing the asteroid scanner with a file containing targets."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=True)
        mock_open = mocker.mock_open(
            read_data="example.com\ntest.com\nhttps://secure.com\n"
        )
        mocker.patch("builtins.open", mock_open)

        scanner = AsteroidScanner("targets.txt", "test_org")

        assert scanner.target == "targets.txt"
        assert scanner.list_of_targets == [
            "http://example.com",
            "http://test.com",
            "https://secure.com",
        ]

    def test_asteroid_initialization_directory_exists(self, mocker: MockerFixture):
        """Test initialization when output directory already exists."""
        mock_makedirs = mocker.patch("scanners.asteroid_scanner.os.makedirs")

        # Mock os.path.exists to return True for the output directory, False for target file check
        def mock_exists(path):
            if path == "/app/asteroid_output":
                return True
            return False

        mocker.patch(
            "scanners.asteroid_scanner.os.path.exists", side_effect=mock_exists
        )

        AsteroidScanner("example.com", "test_org")

        mock_makedirs.assert_not_called()

    @pytest.mark.parametrize(
        "input_target,expected_output",
        [
            ("example.com", ["http://example.com"]),
            ("https://example.com", ["https://example.com"]),
            ("http://example.com", ["http://example.com"]),
            ("example.com,test.com", ["http://example.com", "http://test.com"]),
            (
                "https://example.com,http://test.com",
                ["https://example.com", "http://test.com"],
            ),
            (
                "example.com, test.com , secure.com",
                ["http://example.com", "http://test.com", "http://secure.com"],
            ),
        ],
    )
    def test_process_target_string_inputs(
        self, input_target, expected_output, mocker: MockerFixture
    ):
        """Test target processing with various string inputs."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)

        scanner = AsteroidScanner(input_target, "test_org")
        assert scanner.list_of_targets == expected_output

    def test_process_target_file_input(self, mocker: MockerFixture):
        """Test target processing with file input."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=True)
        mock_open = mocker.mock_open(
            read_data="example.com\n\ntest.com\nhttps://secure.com\n\n"
        )
        mocker.patch("builtins.open", mock_open)

        scanner = AsteroidScanner("targets.txt", "test_org")

        # Should skip empty lines and process non-empty ones
        assert scanner.list_of_targets == [
            "http://example.com",
            "http://test.com",
            "https://secure.com",
        ]

    def test_vulns_to_db_single_target(self, mocker: MockerFixture):
        """Test vulnerability database insertion for single target."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)
        mock_insert = mocker.patch(
            "scanners.asteroid_scanner.insert_vulnerability_to_database"
        )
        mock_vulnerability = mocker.patch("scanners.asteroid_scanner.Vulnerability")

        # Mock JSON file content
        vuln_data = [
            {"id": "1", "name": "Test Vuln 1", "severity": "high"},
            {"id": "2", "name": "Test Vuln 2", "severity": "medium"},
        ]
        mock_open = mocker.mock_open()
        mocker.patch("builtins.open", mock_open)
        mocker.patch("scanners.asteroid_scanner.json.load", return_value=vuln_data)

        scanner = AsteroidScanner("https://example.com", "test_org")
        scanner.vulns_to_db()

        # Should call insert_vulnerability_to_database for each vulnerability.
        # Vulnerability objects are now created via from_dict(), not the constructor.
        assert mock_insert.call_count == 2
        assert mock_vulnerability.from_dict.call_count == 2

    def test_vulns_to_db_multiple_targets(self, mocker: MockerFixture):
        """Test vulnerability database insertion for multiple targets."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)
        mock_insert = mocker.patch(
            "scanners.asteroid_scanner.insert_vulnerability_to_database"
        )
        mock_vulnerability = mocker.patch("scanners.asteroid_scanner.Vulnerability")

        # Mock JSON file content for multiple targets
        vuln_data = [{"id": "1", "name": "Test Vuln", "severity": "high"}]
        mock_open = mocker.mock_open()
        mocker.patch("builtins.open", mock_open)
        mocker.patch("scanners.asteroid_scanner.json.load", return_value=vuln_data)

        scanner = AsteroidScanner("example.com,test.com", "test_org")
        scanner.vulns_to_db()

        # Should process both targets (2 targets × 1 vuln each = 2 calls)
        assert mock_insert.call_count == 2
        assert mock_vulnerability.from_dict.call_count == 2

    def test_normal_scan_mode(self, mocker: MockerFixture):
        """Test running asteroid scanner in normal mode."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)
        mock_asteroid_class = mocker.patch("scanners.asteroid_scanner.Asteroid")
        mocker.patch("scanners.asteroid_scanner.os.getenv", return_value="test_api_key")

        scanner = AsteroidScanner("example.com", "test_org")
        scanner.normal()

        # Verify Asteroid was initialized with correct parameters for normal mode
        mock_asteroid_class.assert_called_once_with(
            target="example.com",
            output_dir="/app/asteroid_output",
            specific_modules="katana,gau,extensioninspector,vulnscan,retirejs",
            rerun=True,
            module_args={"search_vulns_api_key": "test_api_key"},
        )
        mock_asteroid_class.return_value.run.assert_called_once()

    def test_aggressive_scan_mode(self, mocker: MockerFixture):
        """Test running asteroid scanner in aggressive mode."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)
        mock_asteroid_class = mocker.patch("scanners.asteroid_scanner.Asteroid")
        mocker.patch("scanners.asteroid_scanner.os.getenv", return_value="test_api_key")

        scanner = AsteroidScanner("example.com", "test_org")
        scanner.aggressive()

        # Verify Asteroid was initialized with correct parameters for aggressive mode
        mock_asteroid_class.assert_called_once_with(
            target="example.com",
            output_dir="/app/asteroid_output",
            specific_modules="katana,feroxbuster,gau,arjun,directorylisting,sensitivefiles,trufflehog,extensioninspector,vulnscan,retirejs,nuclei,fileupload",
            rerun=True,
            module_args={"forms": True, "search_vulns_api_key": "test_api_key"},
        )
        mock_asteroid_class.return_value.run.assert_called_once()

    @pytest.mark.parametrize(
        "mode,expected_method",
        [
            ("normal", "normal"),
            ("aggressive", "aggressive"),
        ],
    )
    def test_run_with_valid_modes(self, mode, expected_method, mocker: MockerFixture):
        """Test run method with valid scan modes."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)

        scanner = AsteroidScanner("example.com", "test_org")

        # Mock the specific scan methods and vulns_to_db
        mock_normal = mocker.patch.object(scanner, "normal")
        mock_aggressive = mocker.patch.object(scanner, "aggressive")
        mock_vulns_to_db = mocker.patch.object(scanner, "vulns_to_db")

        scanner.run(mode)

        if expected_method == "normal":
            mock_normal.assert_called_once()
            mock_aggressive.assert_not_called()
        else:
            mock_aggressive.assert_called_once()
            mock_normal.assert_not_called()

        mock_vulns_to_db.assert_called_once()

    def test_run_with_invalid_mode(self, mocker: MockerFixture):
        """Test run method with invalid scan mode."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)

        scanner = AsteroidScanner("example.com", "test_org")

        with pytest.raises(
            ValueError, match="Invalid mode. Use 'normal' or 'aggressive'."
        ):
            scanner.run("invalid_mode")

    def test_normal_mode_with_missing_api_key(self, mocker: MockerFixture):
        """Test normal mode when API key environment variable is missing."""
        mocker.patch("scanners.asteroid_scanner.os.makedirs")
        mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)
        mock_asteroid_class = mocker.patch("scanners.asteroid_scanner.Asteroid")
        mocker.patch("scanners.asteroid_scanner.os.getenv", return_value="")

        scanner = AsteroidScanner("example.com", "test_org")
        scanner.normal()

        # Should still work with empty API key
        mock_asteroid_class.assert_called_once()
        call_args = mock_asteroid_class.call_args[1]
        assert call_args["module_args"]["search_vulns_api_key"] == ""


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
    return NucleiScanner("example.com", "test_org", mode=NucleiMode.WORDPRESS)


@pytest.fixture
def sample_asteroid_scanner(mocker: MockerFixture):
    """Fixture providing a sample AsteroidScanner instance."""
    mocker.patch("scanners.asteroid_scanner.os.makedirs")
    mocker.patch("scanners.asteroid_scanner.os.path.exists", return_value=False)
    return AsteroidScanner("example.com", "test_org")


class TestScannerIntegration:
    """Integration tests for scanner classes."""

    def test_scanner_org_name_consistency(
        self,
        sample_bbot_scanner,
        sample_nuclei_scanner,
        sample_wordpress_scanner,
        sample_asteroid_scanner,
    ):
        """Test that all scanners maintain org_name consistency."""
        assert sample_bbot_scanner.org_name == "test_org"
        assert sample_nuclei_scanner.org_name == "test_org"
        assert sample_wordpress_scanner.org_name == "test_org"
        assert sample_asteroid_scanner.org_name == "test_org"

    def test_target_processing_consistency(self, sample_asteroid_scanner):
        """Test that AsteroidScanner processes targets consistently."""
        # Test that targets are properly formatted with http prefix
        assert all(
            target.startswith(("http://", "https://"))
            for target in sample_asteroid_scanner.list_of_targets
        )

    def test_output_directory_creation(
        self, sample_asteroid_scanner, mocker: MockerFixture
    ):
        """Test that AsteroidScanner creates output directories consistently."""
        assert sample_asteroid_scanner.output_dir == "/app/asteroid_output"


@pytest.mark.parametrize("mode", ["passive", "normal", "aggressive", "attack_surface"])
def test_every_bbot_mode_is_time_bounded(mode, mocker):
    """A wedged BBOT module must not hang a scan forever in any mode."""
    mocker.patch("scanners.bbot.os.makedirs")
    scanner = BBotScanner(target="example.com", org_name="test_org")
    run_command = mocker.patch.object(scanner, "_run_bbot_command", return_value=0)
    process_result = mocker.patch.object(scanner, "_process_scan_result")

    getattr(scanner, mode)()

    timeout = run_command.call_args.kwargs.get("timeout_seconds")
    assert timeout is not None, f"{mode} runs without a timeout"
    assert timeout > 0
    # A timeout must still ingest whatever BBOT produced before it was killed.
    assert process_result.call_args.kwargs.get("allow_timeout_partial") is True


@pytest.mark.parametrize("mode", ["passive", "normal"])
def test_non_aggressive_modes_exclude_unbounded_modules(mode, mocker):
    """Downloads, checkouts and screenshots belong in aggressive mode only.

    Measured: `normal` with these modules had not finished after 3600s on a
    mid-sized domain; without them it completes in 858s for the same nine
    FINDINGs.
    """
    mocker.patch("scanners.bbot.os.makedirs")
    scanner = BBotScanner(target="example.com", org_name="test_org")
    run_command = mocker.patch.object(scanner, "_run_bbot_command", return_value=0)
    mocker.patch.object(scanner, "_process_scan_result")

    getattr(scanner, mode)()
    command = run_command.call_args.args[0]

    for module in ("trufflehog", "git_clone", "gowitness", "filedownload"):
        assert module in command, f"{mode} must exclude {module}"
    assert "web-screenshots" in command
    # Plain subdomain brute forcing stays: it is cheap and these modes ask for
    # subdomain enumeration explicitly.
    assert "dnsbrute" not in command


def test_aggressive_mode_keeps_the_heavy_modules(mocker):
    """Aggressive is the mode that is allowed to be slow and loud."""
    mocker.patch("scanners.bbot.os.makedirs")
    scanner = BBotScanner(target="example.com", org_name="test_org")
    run_command = mocker.patch.object(scanner, "_run_bbot_command", return_value=0)
    mocker.patch.object(scanner, "_process_scan_result")

    scanner.aggressive()
    command = run_command.call_args.args[0]

    assert "trufflehog" not in command
    assert "gowitness" not in command
    # ... and it gets a ceiling that reflects that, not the lean one.
    assert run_command.call_args.kwargs["timeout_seconds"] > 3600
