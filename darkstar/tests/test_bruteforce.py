import pytest
from pytest_mock import MockerFixture
import asyncio
import json
import tempfile
from pathlib import Path
from tools.bruteforce.hydrapy import HydraAttack, HydraConfig, AttackResult
from tools.bruteforce.integration import (
    process_scan_results_with_hydra,
    get_hydra_protocol,
    process_bruteforce_results,
)
from colorama import Fore, Style


@pytest.fixture
def hydra_attack():
    """Create HydraAttack instance with temporary directory to avoid file creation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        attack = HydraAttack(output_dir=tmp_dir)
        yield attack


@pytest.fixture
def mock_process(mocker: MockerFixture):
    """Create a proper async mock process for testing."""
    process = mocker.Mock()  # Use mocker.Mock as base

    # Mock process attributes
    process.returncode = 0

    # Mock stdout and stderr streams with AsyncMock for async methods
    process.stdout = mocker.Mock()
    process.stderr = mocker.Mock()

    # Set up async methods with AsyncMock
    process.stdout.readline = mocker.AsyncMock(return_value=b"")
    process.stderr.readline = mocker.AsyncMock(return_value=b"")
    process.wait = mocker.AsyncMock(return_value=0)

    # Keep synchronous methods as regular Mock (these should NOT be awaited)
    process.terminate = mocker.Mock(return_value=None)
    process.kill = mocker.Mock(return_value=None)

    return process


# Test IP validation
@pytest.mark.parametrize(
    "ip,expected",
    [
        ("192.168.1.1", True),
        ("256.256.256.256", False),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", True),
        ("invalid_ip", False),
        ("127.0.0.", False),
    ],
)
def test_validate_ip(hydra_attack, ip, expected):
    assert hydra_attack.validate_ip(ip) == expected


# Test hostname validation
@pytest.mark.parametrize(
    "hostname,expected",
    [
        ("example.com", True),
        ("sub.example.com", True),
        ("invalid..com", False),
        ("a" * 256, False),
        ("-invalid.com", False),
    ],
)
def test_validate_hostname(hydra_attack, hostname, expected):
    assert hydra_attack.validate_hostname(hostname) == expected


# Test target validation
@pytest.mark.parametrize(
    "ip,hostname,expected",
    [
        ("192.168.1.1", None, "192.168.1.1"),
        (None, "example.com", "example.com"),
        ("invalid", None, None),
        (None, "invalid..com", None),
        (None, None, None),
    ],
)
def test_validate_target(hydra_attack, ip, hostname, expected):
    assert hydra_attack.validate_target(ip, hostname) == expected


# Test credential parsing
@pytest.mark.parametrize(
    "line,expected",
    [
        (
            "[21][ftp] host: 127.0.0.1   login: admin   password: 123456",
            {
                "port": "21",
                "username": "admin",
                "password": "123456",
            },
        ),
        (
            "[161][snmp] host: 127.0.0.1 password: public",
            {"port": "161", "password": "public"},
        ),
        ("invalid line", None),
    ],
)
def test_parse_credentials(hydra_attack, line, expected):
    result = hydra_attack._parse_credentials(line)
    if expected is None:
        assert result is None
    else:
        # Remove timestamp for comparison since it will always be different
        actual_timestamp = result.pop("timestamp", None)
        assert actual_timestamp is not None
        assert result == expected  # Compare the rest of the fields


# Test command building
@pytest.mark.parametrize(
    "target,protocol,login_file,password_file,tasks,port,stop_on_success,expected_command",
    [
        (
            "example.com",
            "ftp",
            "logins.txt",
            "passwords.txt",
            16,
            21,
            True,
            [
                "hydra",
                "-P",
                "passwords.txt",
                "-t",
                "16",
                "-q",
                "-I",
                "-L",
                "logins.txt",
                "-f",
                "-s",
                "21",
                "ftp://example.com",
            ],
        ),
        (
            "127.0.0.1",
            "snmp",
            None,
            None,
            8,
            None,
            False,
            [
                "hydra",
                "-P",
                str(HydraConfig().get_default_wordlist_path("snmp", "passwords")),
                "-t",
                "8",
                "-q",
                "-I",
                "snmp://127.0.0.1",
            ],
        ),
    ],
)
def test_build_command(
    hydra_attack,
    target,
    protocol,
    login_file,
    password_file,
    tasks,
    port,
    stop_on_success,
    expected_command,
):
    """Test _build_command method with various parameters."""
    command = hydra_attack._build_command(
        target, protocol, login_file, password_file, tasks, port, stop_on_success
    )
    assert command == expected_command, f"Expected {expected_command}, got {command}"


# Test save results - now properly isolated
def test_save_results(hydra_attack):
    """Test save_results method with proper isolation using temporary directory."""
    target = "example.com"
    protocol = "ftp"
    credentials = [{"username": "admin", "password": "password"}]
    start_time = 1000.0
    end_time = 1010.0
    status = "success"
    port = "21"

    result = AttackResult(
        target=target,
        protocol=protocol,
        credentials=credentials,
        start_time=start_time,
        end_time=end_time,
        status=status,
        port=port,
    )

    hydra_attack.save_results(result)

    # Check if file was created in temporary directory
    result_files = list(
        Path(hydra_attack.results_dir).glob(
            f"attack_{result.protocol}_{result.target}_*.json"
        )
    )
    assert len(result_files) == 1

    # Verify content
    with open(result_files[0]) as f:
        saved_data = json.load(f)
        assert saved_data["target"] == target
        assert saved_data["protocol"] == protocol
        assert saved_data["port"] == port
        assert saved_data["credentials"] == credentials
        assert saved_data["duration"] == end_time - start_time
        assert saved_data["status"] == status
        assert saved_data["error"] is None
        assert "timestamp" in saved_data


@pytest.mark.asyncio
async def test_process_hydra_output(hydra_attack, mocker: MockerFixture):
    """Test process_hydra_output method with proper isolation."""
    # Create a mock process output
    mock_output = [
        b"[21][ftp] host: 192.217.238.3   login: sysadmin   password: 654321\n",
    ]
    mock_process = mocker.AsyncMock()
    mock_process.stdout.readline = mocker.AsyncMock(
        side_effect=mock_output + [b""]
    )  # End of stream
    mock_process.stderr.readline = mocker.AsyncMock(return_value=b"")
    mock_process.terminate = mocker.Mock(return_value=None)

    stream = mock_process.stdout
    results = []
    hydra_attack.stop_on_success = False
    await hydra_attack.process_hydra_output(stream, False, mock_process, results)
    # Check if results were processed correctly
    assert len(results) == 1
    assert results[0]["port"] == "21"
    assert results[0]["username"] == "sysadmin"
    assert results[0]["password"] == "654321"
    assert "timestamp" in results[0]


@pytest.mark.asyncio
async def test_run_attack_success(hydra_attack, mocker: MockerFixture):
    """Test successful attack with complete file operation mocking."""
    # Create a proper mock process using the same pattern as the fixture
    mock_process = mocker.Mock()
    mock_process.returncode = 0

    # Mock stdout and stderr with regular Mock, but their methods with AsyncMock
    mock_process.stdout = mocker.Mock()
    mock_process.stderr = mocker.Mock()

    # Configure async methods
    mock_process.stdout.readline = mocker.AsyncMock(
        side_effect=[
            b"[21][ftp] host: 127.0.0.1   login: admin   password: 123456\n",
            b"",  # End of stream
        ]
    )
    mock_process.stderr.readline = mocker.AsyncMock(return_value=b"")
    mock_process.wait = mocker.AsyncMock(return_value=0)

    # Keep synchronous methods as regular Mock
    mock_process.terminate = mocker.Mock(return_value=None)
    mock_process.kill = mocker.Mock(return_value=None)

    mock_exec = mocker.patch(
        "asyncio.create_subprocess_exec", return_value=mock_process
    )

    result = await hydra_attack.run_attack(ip="127.0.0.1", protocol="ftp", port=21)

    assert result.status == "success"
    assert len(result.credentials) == 1
    assert result.target == "127.0.0.1"
    assert result.protocol == "ftp"
    assert mock_exec.called

    # Verify that a results file was created in the temporary directory
    result_files = list(Path(hydra_attack.results_dir).glob("attack_*.json"))
    assert len(result_files) == 1


@pytest.mark.asyncio
async def test_run_attack_timeout(hydra_attack, mocker: MockerFixture):
    """Test attack timeout with proper file isolation."""
    # Create mock process using the same pattern
    mock_process = mocker.Mock()
    mock_process.returncode = None

    # Mock stdout and stderr with regular Mock
    mock_process.stdout = mocker.Mock()
    mock_process.stderr = mocker.Mock()

    # Configure async methods to raise TimeoutError
    mock_process.stdout.readline = mocker.AsyncMock(side_effect=asyncio.TimeoutError())
    mock_process.stderr.readline = mocker.AsyncMock(side_effect=asyncio.TimeoutError())
    mock_process.wait = mocker.AsyncMock(return_value=0)

    # Keep synchronous methods as regular Mock
    mock_process.terminate = mocker.Mock(return_value=None)
    mock_process.kill = mocker.Mock(return_value=None)

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    result = await hydra_attack.run_attack(ip="127.0.0.1", protocol="ftp", timeout=1)

    assert result.status == "timeout"
    assert result.error is not None
    assert len(result.credentials) == 0

    # Verify that a results file was still created (even for timeouts)
    result_files = list(Path(hydra_attack.results_dir).glob("attack_*.json"))
    assert len(result_files) == 1


@pytest.mark.asyncio
async def test_run_attack_hydra_not_found(hydra_attack, mocker: MockerFixture):
    """Test hydra not found error with proper file isolation."""
    mocker.patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError())

    result = await hydra_attack.run_attack(ip="127.0.0.1", protocol="ftp")

    assert result.status == "failed"
    assert "Hydra is not installed" in result.error

    # The actual behavior: no results file is created when FileNotFoundError occurs
    # because save_results is not called in the exception handler
    result_files = list(Path(hydra_attack.results_dir).glob("attack_*.json"))
    assert len(result_files) == 0


def test_hydra_config_wordlist_creation(hydra_attack):
    """Test HydraConfig wordlist creation with temporary directories."""
    config = HydraConfig()
    config.DEFAULT_WORDLISTS_DIR = Path(hydra_attack.results_dir) / "wordlists"
    config.DEFAULT_WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)

    # Test custom wordlist creation
    words = ["admin", "root", "user"]
    output_path = config.DEFAULT_WORDLISTS_DIR / "test_logins.txt"
    config.create_custom_wordlist(words, output_path)

    assert output_path.exists()
    with open(output_path) as f:
        content = f.read().strip()
        assert content == "admin\nroot\nuser"


# Tests for integration module
class TestIntegration:
    """Test the integration module functions."""

    @pytest.mark.parametrize(
        "service,expected_protocol",
        [
            ("ftp", "ftp"),
            ("ssh", "ssh"),
            ("smtp", "smtp"),
            ("snmp", "snmp"),
            ("netbios-ssn", "smb"),
            ("microsoft-ds", "smb"),
            ("mongodb", "mongodb"),
            ("mysql", "mysql"),
            ("postgresql", "postgres"),
            ("ftpd", "ftp"),
            ("sshd", "ssh"),
            ("smtpd", "smtp"),
            ("snmpd", "snmp"),
            ("samba", "smb"),
            ("cifs", "smb"),
            ("mariadb", "mysql"),
            ("postgres", "postgres"),
            ("pgsql", "postgres"),
            ("http", None),  # Not supported
            ("https", None),  # Not supported
            ("", None),  # Empty string
            (None, None),  # None input
            ("ftp extra info", "ftp"),  # Service with extra info
        ],
    )
    def test_get_hydra_protocol(self, service, expected_protocol):
        """Test service to protocol mapping."""
        result = get_hydra_protocol(service)
        assert result == expected_protocol

    @pytest.mark.asyncio
    async def test_process_scan_results_with_hydra_no_services(
        self, mocker: MockerFixture
    ):
        """Test processing scan results with no services found."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")

        # Empty scan results
        scan_results = []

        result = await process_scan_results_with_hydra(scan_results)

        assert result == {}
        mock_logger.info.assert_called_with("No services found for bruteforcing")

    @pytest.mark.asyncio
    async def test_process_scan_results_with_hydra_no_supported_services(
        self, mocker: MockerFixture
    ):
        """Test processing scan results with no supported services."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")
        mock_makedirs = mocker.patch("tools.bruteforce.integration.os.makedirs")
        mock_hydra_class = mocker.patch("tools.bruteforce.integration.HydraAttack")

        # Mock HydraAttack instance
        mock_hydra_instance = mocker.Mock()
        mock_hydra_class.return_value = mock_hydra_instance

        # Scan results with unsupported services
        scan_results = [
            {
                "scan_results": {
                    "ip_results": {
                        "192.168.1.1": {
                            "ports": [
                                {"port": 80, "service": "http"},
                                {"port": 443, "service": "https"},
                            ]
                        }
                    }
                }
            }
        ]

        result = await process_scan_results_with_hydra(scan_results)

        assert result == {}
        mock_logger.info.assert_called_with(
            "No supported services found for bruteforcing"
        )

    @pytest.mark.asyncio
    async def test_process_scan_results_with_hydra_success(self, mocker: MockerFixture):
        """Test successful processing of scan results with supported services."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")
        mock_makedirs = mocker.patch("tools.bruteforce.integration.os.makedirs")
        mock_hydra_class = mocker.patch("tools.bruteforce.integration.HydraAttack")

        # Mock AttackResult objects
        mock_attack_result_1 = mocker.Mock()
        mock_attack_result_1.target = "192.168.1.1"
        mock_attack_result_1.port = 21
        mock_attack_result_1.protocol = "ftp"
        mock_attack_result_1.status = "success"
        mock_attack_result_1.credentials = [{"username": "admin", "password": "123456"}]
        mock_attack_result_1.error = None

        mock_attack_result_2 = mocker.Mock()
        mock_attack_result_2.target = "192.168.1.1"
        mock_attack_result_2.port = 22
        mock_attack_result_2.protocol = "ssh"
        mock_attack_result_2.status = "failed"
        mock_attack_result_2.credentials = []
        mock_attack_result_2.error = "No valid credentials found"

        # Mock HydraAttack instance
        mock_hydra_instance = mocker.Mock()
        mock_hydra_class.return_value = mock_hydra_instance

        # Mock run_hydra_attack to return our mock results
        async def mock_run_hydra_attack_side_effect(
            sem, hydra, ip, protocol, port, timeout
        ):
            if protocol == "ftp":
                return mock_attack_result_1
            else:
                return mock_attack_result_2

        mock_run_hydra_attack = mocker.patch(
            "tools.bruteforce.integration.run_hydra_attack",
            side_effect=mock_run_hydra_attack_side_effect,
        )

        # Scan results with supported services
        scan_results = [
            {
                "scan_results": {
                    "ip_results": {
                        "192.168.1.1": {
                            "ports": [
                                {"port": 21, "service": "ftp"},
                                {"port": 22, "service": "ssh"},
                            ]
                        }
                    }
                }
            }
        ]

        result = await process_scan_results_with_hydra(
            scan_results, org_name="test_org"
        )

        # Verify output directory creation
        mock_makedirs.assert_called_once_with(
            "scan_results/test_org/bruteforce", exist_ok=True
        )

        # Verify HydraAttack was instantiated with correct output directory
        mock_hydra_class.assert_called_once_with(
            output_dir="scan_results/test_org/bruteforce"
        )

        # Verify results structure
        assert "192.168.1.1" in result
        assert len(result["192.168.1.1"]) == 2

        # Check first attack result (success)
        ftp_result = result["192.168.1.1"][0]
        assert ftp_result["port"] == 21
        assert ftp_result["protocol"] == "ftp"
        assert ftp_result["status"] == "success"
        assert ftp_result["credentials"] == [
            {"username": "admin", "password": "123456"}
        ]
        assert ftp_result["error"] is None

        # Check second attack result (failed)
        ssh_result = result["192.168.1.1"][1]
        assert ssh_result["port"] == 22
        assert ssh_result["protocol"] == "ssh"
        assert ssh_result["status"] == "failed"
        assert ssh_result["credentials"] == []
        assert ssh_result["error"] == "No valid credentials found"

        # Verify logging
        mock_logger.info.assert_any_call(
            "Found supported service for bruteforcing: 192.168.1.1:21 - ftp -> ftp"
        )
        mock_logger.info.assert_any_call(
            "Found supported service for bruteforcing: 192.168.1.1:22 - ssh -> ssh"
        )
        mock_logger.info.assert_any_call(
            "Starting 2 Hydra attacks on supported services"
        )

    @pytest.mark.asyncio
    async def test_process_scan_results_with_hydra_with_exceptions(
        self, mocker: MockerFixture
    ):
        """Test processing scan results when some attacks raise exceptions."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")
        mock_makedirs = mocker.patch("tools.bruteforce.integration.os.makedirs")
        mock_hydra_class = mocker.patch("tools.bruteforce.integration.HydraAttack")

        # Mock one successful result and one exception
        mock_attack_result = mocker.Mock()
        mock_attack_result.target = "192.168.1.1"
        mock_attack_result.port = 21
        mock_attack_result.protocol = "ftp"
        mock_attack_result.status = "success"
        mock_attack_result.credentials = [{"username": "admin", "password": "123456"}]
        mock_attack_result.error = None

        test_exception = Exception("Connection timeout")

        # Mock HydraAttack instance
        mock_hydra_instance = mocker.Mock()
        mock_hydra_class.return_value = mock_hydra_instance

        # Mock run_hydra_attack to return success for first call, raise exception for second
        async def mock_run_hydra_attack_side_effect(
            sem, hydra, ip, protocol, port, timeout
        ):
            if protocol == "ftp":
                return mock_attack_result
            else:
                raise test_exception

        mock_run_hydra_attack = mocker.patch(
            "tools.bruteforce.integration.run_hydra_attack",
            side_effect=mock_run_hydra_attack_side_effect,
        )

        # Scan results with two services
        scan_results = [
            {
                "scan_results": {
                    "ip_results": {
                        "192.168.1.1": {
                            "ports": [
                                {"port": 21, "service": "ftp"},
                                {"port": 22, "service": "ssh"},
                            ]
                        }
                    }
                }
            }
        ]

        result = await process_scan_results_with_hydra(scan_results)

        # Verify results structure
        assert "192.168.1.1" in result
        assert len(result["192.168.1.1"]) == 2

        # Check successful attack result
        ftp_result = result["192.168.1.1"][0]
        assert ftp_result["port"] == 21
        assert ftp_result["protocol"] == "ftp"
        assert ftp_result["status"] == "success"

        # Check failed attack result (from exception)
        ssh_result = result["192.168.1.1"][1]
        assert ssh_result["port"] == 22
        assert ssh_result["protocol"] == "ssh"
        assert ssh_result["status"] == "error"
        assert ssh_result["error"] == "Connection timeout"

        # Verify error logging
        mock_logger.error.assert_called_once_with(
            "Error in Hydra attack on 192.168.1.1:22 (ssh): Connection timeout"
        )

    @pytest.mark.asyncio
    async def test_process_scan_results_with_hydra_multiple_ips(
        self, mocker: MockerFixture
    ):
        """Test processing scan results with multiple IP addresses."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")
        mock_makedirs = mocker.patch("tools.bruteforce.integration.os.makedirs")
        mock_hydra_class = mocker.patch("tools.bruteforce.integration.HydraAttack")

        # Mock attack results for different IPs
        mock_result_1 = mocker.Mock()
        mock_result_1.target = "192.168.1.1"
        mock_result_1.port = 21
        mock_result_1.protocol = "ftp"
        mock_result_1.status = "success"
        mock_result_1.credentials = [{"username": "admin", "password": "123456"}]
        mock_result_1.error = None

        mock_result_2 = mocker.Mock()
        mock_result_2.target = "192.168.1.2"
        mock_result_2.port = 22
        mock_result_2.protocol = "ssh"
        mock_result_2.status = "failed"
        mock_result_2.credentials = []
        mock_result_2.error = "Authentication failed"

        # Mock HydraAttack instance
        mock_hydra_instance = mocker.Mock()
        mock_hydra_class.return_value = mock_hydra_instance

        # Mock run_hydra_attack to return appropriate results based on IP
        async def mock_run_hydra_attack_side_effect(
            sem, hydra, ip, protocol, port, timeout
        ):
            if ip == "192.168.1.1":
                return mock_result_1
            else:
                return mock_result_2

        mock_run_hydra_attack = mocker.patch(
            "tools.bruteforce.integration.run_hydra_attack",
            side_effect=mock_run_hydra_attack_side_effect,
        )

        # Scan results with multiple IPs
        scan_results = [
            {
                "scan_results": {
                    "ip_results": {
                        "192.168.1.1": {"ports": [{"port": 21, "service": "ftp"}]},
                        "192.168.1.2": {"ports": [{"port": 22, "service": "ssh"}]},
                    }
                }
            }
        ]

        result = await process_scan_results_with_hydra(scan_results)

        # Verify both IPs are in results
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert len(result["192.168.1.1"]) == 1
        assert len(result["192.168.1.2"]) == 1

        # Check results for first IP
        assert result["192.168.1.1"][0]["status"] == "success"
        assert result["192.168.1.1"][0]["protocol"] == "ftp"

        # Check results for second IP
        assert result["192.168.1.2"][0]["status"] == "failed"
        assert result["192.168.1.2"][0]["protocol"] == "ssh"

    @pytest.mark.asyncio
    async def test_process_scan_results_with_hydra_custom_parameters(
        self, mocker: MockerFixture
    ):
        """Test processing scan results with custom concurrent_limit and timeout."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")
        mock_makedirs = mocker.patch("tools.bruteforce.integration.os.makedirs")
        mock_hydra_class = mocker.patch("tools.bruteforce.integration.HydraAttack")

        # Mock successful result
        mock_attack_result = mocker.Mock()
        mock_attack_result.target = "192.168.1.1"
        mock_attack_result.port = 21
        mock_attack_result.protocol = "ftp"
        mock_attack_result.status = "success"
        mock_attack_result.credentials = []
        mock_attack_result.error = None

        # Mock HydraAttack instance
        mock_hydra_instance = mocker.Mock()
        mock_hydra_class.return_value = mock_hydra_instance

        # Mock run_hydra_attack
        async def mock_run_hydra_attack_side_effect(
            sem, hydra, ip, protocol, port, timeout
        ):
            return mock_attack_result

        mock_run_hydra_attack = mocker.patch(
            "tools.bruteforce.integration.run_hydra_attack",
            side_effect=mock_run_hydra_attack_side_effect,
        )

        # Scan results with one service
        scan_results = [
            {
                "scan_results": {
                    "ip_results": {
                        "192.168.1.1": {"ports": [{"port": 21, "service": "ftp"}]}
                    }
                }
            }
        ]

        # Test with custom parameters
        result = await process_scan_results_with_hydra(
            scan_results, concurrent_limit=5, timeout=600, org_name="custom_org"
        )

        # Verify custom org_name is used in output directory
        mock_makedirs.assert_called_once_with(
            "scan_results/custom_org/bruteforce", exist_ok=True
        )
        mock_hydra_class.assert_called_once_with(
            output_dir="scan_results/custom_org/bruteforce"
        )

        # Verify the attack was launched (we can't easily test semaphore limit and timeout
        # without more complex mocking, but we can verify the function was called)
        assert result is not None
        assert "192.168.1.1" in result

    @pytest.mark.asyncio
    async def test_process_scan_results_invalid_format(self, mocker: MockerFixture):
        """Test processing scan results with invalid format."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")

        # Invalid scan results format
        scan_results = [
            "invalid_string",
            {"invalid": "format"},
            {"scan_results": {"invalid": "format"}},
            {"scan_results": {"ip_results": {}}},  # Empty ip_results
        ]

        result = await process_scan_results_with_hydra(scan_results)

        assert result == {}
        mock_logger.info.assert_called_with("No services found for bruteforcing")

    @pytest.mark.asyncio
    async def test_process_scan_results_mixed_services(self, mocker: MockerFixture):
        """Test processing scan results with mix of supported and unsupported services."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")
        mock_makedirs = mocker.patch("tools.bruteforce.integration.os.makedirs")
        mock_hydra_class = mocker.patch("tools.bruteforce.integration.HydraAttack")

        # Mock successful result for supported services
        mock_attack_result_1 = mocker.Mock()
        mock_attack_result_1.target = "192.168.1.1"
        mock_attack_result_1.port = 21
        mock_attack_result_1.protocol = "ftp"
        mock_attack_result_1.status = "success"
        mock_attack_result_1.credentials = []
        mock_attack_result_1.error = None

        mock_attack_result_2 = mocker.Mock()
        mock_attack_result_2.target = "192.168.1.1"
        mock_attack_result_2.port = 22
        mock_attack_result_2.protocol = "ssh"
        mock_attack_result_2.status = "failed"
        mock_attack_result_2.credentials = []
        mock_attack_result_2.error = "No credentials found"

        # Mock HydraAttack instance
        mock_hydra_instance = mocker.Mock()
        mock_hydra_class.return_value = mock_hydra_instance

        # Mock run_hydra_attack to return appropriate results
        async def mock_run_hydra_attack_side_effect(
            sem, hydra, ip, protocol, port, timeout
        ):
            if protocol == "ftp":
                return mock_attack_result_1
            else:
                return mock_attack_result_2

        mock_run_hydra_attack = mocker.patch(
            "tools.bruteforce.integration.run_hydra_attack",
            side_effect=mock_run_hydra_attack_side_effect,
        )

        # Scan results with mix of supported and unsupported services
        scan_results = [
            {
                "scan_results": {
                    "ip_results": {
                        "192.168.1.1": {
                            "ports": [
                                {"port": 21, "service": "ftp"},  # Supported
                                {"port": 80, "service": "http"},  # Not supported
                                {"port": 443, "service": "https"},  # Not supported
                                {"port": 22, "service": "ssh"},  # Supported
                            ]
                        }
                    }
                }
            }
        ]

        result = await process_scan_results_with_hydra(scan_results)

        # Should only log supported services
        mock_logger.info.assert_any_call(
            "Found supported service for bruteforcing: 192.168.1.1:21 - ftp -> ftp"
        )
        mock_logger.info.assert_any_call(
            "Found supported service for bruteforcing: 192.168.1.1:22 - ssh -> ssh"
        )

        # Should have results for both supported services
        assert result is not None
        assert "192.168.1.1" in result
        assert len(result["192.168.1.1"]) == 2

    def test_process_bruteforce_results_empty(self, mocker: MockerFixture):
        """Test process_bruteforce_results with empty results."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")

        # Test with None
        result = process_bruteforce_results(None)

        expected_result = {"credentials_found": False, "credentials_by_host": {}}
        assert result == expected_result
        mock_logger.info.assert_any_call(
            f"{Fore.YELLOW}[!] No bruteforce results available.{Style.RESET_ALL}"
        )

        # Test with empty dict
        result = process_bruteforce_results({})

        assert result == expected_result
        mock_logger.info.assert_any_call(
            f"{Fore.YELLOW}[!] No bruteforce results available.{Style.RESET_ALL}"
        )

    def test_process_bruteforce_results_no_credentials_found(
        self, mocker: MockerFixture
    ):
        """Test process_bruteforce_results when no credentials are found."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")

        # Bruteforce results with failed attacks
        bruteforce_results = {
            "192.168.1.1": [
                {
                    "port": 21,
                    "protocol": "ftp",
                    "status": "failed",
                    "credentials": [],
                    "error": "No valid credentials found",
                },
                {
                    "port": 22,
                    "protocol": "ssh",
                    "status": "timeout",
                    "credentials": [],
                    "error": "Connection timeout",
                },
            ]
        }

        result = process_bruteforce_results(bruteforce_results)

        expected_result = {"credentials_found": False, "credentials_by_host": {}}
        assert result == expected_result

        # Verify logging
        mock_logger.info.assert_any_call(
            f"{Fore.YELLOW}[!] No credentials were found during bruteforce attacks.{Style.RESET_ALL}"
        )
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}Bruteforce attacks completed on 1 targets"
        )

    def test_process_bruteforce_results_credentials_found_username_password(
        self, mocker: MockerFixture
    ):
        """Test process_bruteforce_results with successful username/password credentials."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")

        from tools.bruteforce.integration import process_bruteforce_results

        # Bruteforce results with successful attacks
        bruteforce_results = {
            "192.168.1.1": [
                {
                    "port": 21,
                    "protocol": "ftp",
                    "status": "success",
                    "credentials": [
                        {"username": "admin", "password": "123456"},
                        {"username": "user", "password": "password"},
                    ],
                    "error": None,
                }
            ],
            "192.168.1.2": [
                {
                    "port": 22,
                    "protocol": "ssh",
                    "status": "success",
                    "credentials": [{"username": "root", "password": "toor"}],
                    "error": None,
                }
            ],
        }

        result = process_bruteforce_results(bruteforce_results)

        expected_result = {
            "credentials_found": True,
            "credentials_by_host": {
                "192.168.1.1": [
                    {
                        "username": "admin",
                        "password": "123456",
                        "port": 21,
                        "protocol": "ftp",
                    },
                    {
                        "username": "user",
                        "password": "password",
                        "port": 21,
                        "protocol": "ftp",
                    },
                ],
                "192.168.1.2": [
                    {
                        "username": "root",
                        "password": "toor",
                        "port": 22,
                        "protocol": "ssh",
                    }
                ],
            },
        }
        assert result == expected_result

        # Verify logging
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}Found credentials for {Fore.YELLOW}192.168.1.1:21 (ftp):{Style.RESET_ALL}"
        )
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}    Username: {Fore.CYAN}admin{Fore.GREEN} Password: {Fore.CYAN}123456{Style.RESET_ALL}"
        )
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}    Username: {Fore.CYAN}user{Fore.GREEN} Password: {Fore.CYAN}password{Style.RESET_ALL}"
        )
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}Found credentials for {Fore.YELLOW}192.168.1.2:22 (ssh):{Style.RESET_ALL}"
        )
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}    Username: {Fore.CYAN}root{Fore.GREEN} Password: {Fore.CYAN}toor{Style.RESET_ALL}"
        )
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}Bruteforce attacks completed on 2 targets"
        )

    def test_process_bruteforce_results_snmp_community_strings(
        self, mocker: MockerFixture
    ):
        """Test process_bruteforce_results with SNMP community strings."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")

        from tools.bruteforce.integration import process_bruteforce_results

        # Bruteforce results with SNMP credentials (only password field)
        bruteforce_results = {
            "192.168.1.1": [
                {
                    "port": 161,
                    "protocol": "snmp",
                    "status": "success",
                    "credentials": [{"password": "public"}, {"password": "private"}],
                    "error": None,
                }
            ]
        }

        result = process_bruteforce_results(bruteforce_results)

        expected_result = {
            "credentials_found": True,
            "credentials_by_host": {
                "192.168.1.1": [
                    {"community_string": "public", "port": 161, "protocol": "snmp"},
                    {"community_string": "private", "port": 161, "protocol": "snmp"},
                ]
            },
        }
        assert result == expected_result

        # Verify logging
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}Found credentials for {Fore.YELLOW}192.168.1.1:161 (snmp):{Style.RESET_ALL}"
        )
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}    Community string: {Fore.CYAN}public{Style.RESET_ALL}"
        )
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}    Community string: {Fore.CYAN}private{Style.RESET_ALL}"
        )

    def test_process_bruteforce_results_mixed_success_failure(
        self, mocker: MockerFixture
    ):
        """Test process_bruteforce_results with mixed success and failure results."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")

        from tools.bruteforce.integration import process_bruteforce_results

        # Mixed results with some successes and some failures
        bruteforce_results = {
            "192.168.1.1": [
                {
                    "port": 21,
                    "protocol": "ftp",
                    "status": "success",
                    "credentials": [{"username": "admin", "password": "123456"}],
                    "error": None,
                },
                {
                    "port": 22,
                    "protocol": "ssh",
                    "status": "failed",
                    "credentials": [],
                    "error": "No valid credentials found",
                },
            ]
        }

        result = process_bruteforce_results(bruteforce_results)

        expected_result = {
            "credentials_found": True,
            "credentials_by_host": {
                "192.168.1.1": [
                    {
                        "username": "admin",
                        "password": "123456",
                        "port": 21,
                        "protocol": "ftp",
                    }
                ]
            },
        }
        assert result == expected_result

        # Should only log successful credentials, not failed attempts
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}Found credentials for {Fore.YELLOW}192.168.1.1:21 (ftp):{Style.RESET_ALL}"
        )

    def test_process_bruteforce_results_success_but_empty_credentials(
        self, mocker: MockerFixture
    ):
        """Test process_bruteforce_results with success status but empty credentials."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")

        from tools.bruteforce.integration import process_bruteforce_results

        # Success status but no credentials found
        bruteforce_results = {
            "192.168.1.1": [
                {
                    "port": 21,
                    "protocol": "ftp",
                    "status": "success",
                    "credentials": [],  # Empty credentials
                    "error": None,
                }
            ]
        }

        result = process_bruteforce_results(bruteforce_results)

        expected_result = {"credentials_found": False, "credentials_by_host": {}}
        assert result == expected_result

        # Should log no credentials found since credentials list is empty
        mock_logger.info.assert_any_call(
            f"{Fore.YELLOW}[!] No credentials were found during bruteforce attacks.{Style.RESET_ALL}"
        )

    def test_process_bruteforce_results_malformed_credentials(
        self, mocker: MockerFixture
    ):
        """Test process_bruteforce_results with malformed credential data."""
        mock_logger = mocker.patch("tools.bruteforce.integration.logger")

        from tools.bruteforce.integration import process_bruteforce_results

        # Malformed credentials (missing required fields)
        bruteforce_results = {
            "192.168.1.1": [
                {
                    "port": 21,
                    "protocol": "ftp",
                    "status": "success",
                    "credentials": [
                        {"username": "admin"},  # Missing password
                        {"password": "123456"},  # Missing username
                        {"other_field": "value"},  # Neither username nor password
                    ],
                    "error": None,
                }
            ]
        }

        result = process_bruteforce_results(bruteforce_results)

        # Should process only the password-only credential (SNMP style)
        expected_result = {
            "credentials_found": True,
            "credentials_by_host": {
                "192.168.1.1": [
                    {"community_string": "123456", "port": 21, "protocol": "ftp"}
                ]
            },
        }
        assert result == expected_result

        # Should log the found credential
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}Found credentials for {Fore.YELLOW}192.168.1.1:21 (ftp):{Style.RESET_ALL}"
        )
        mock_logger.info.assert_any_call(
            f"{Fore.GREEN}    Community string: {Fore.CYAN}123456{Style.RESET_ALL}"
        )
