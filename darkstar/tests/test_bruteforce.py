import pytest
from unittest.mock import patch, Mock, AsyncMock
import asyncio
import json
import tempfile
from pathlib import Path
from darkstar.tools.bruteforce.hydrapy import HydraAttack, HydraConfig, AttackResult


@pytest.fixture
def hydra_attack():
    """Create HydraAttack instance with temporary directory to avoid file creation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        attack = HydraAttack(output_dir=tmp_dir)
        yield attack

@pytest.fixture
def mock_process():
    """Create a proper async mock process for testing."""
    process = Mock()  # Use regular Mock as base

    # Mock process attributes
    process.returncode = 0

    # Mock stdout and stderr streams with AsyncMock for async methods
    process.stdout = Mock()
    process.stderr = Mock()

    # Set up async methods with AsyncMock
    process.stdout.readline = AsyncMock(return_value=b"")
    process.stderr.readline = AsyncMock(return_value=b"")
    process.wait = AsyncMock(return_value=0)

    # Keep synchronous methods as regular Mock (these should NOT be awaited)
    process.terminate = Mock(return_value=None)
    process.kill = Mock(return_value=None)

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
                "-P", "passwords.txt",
                "-t", "16",
                "-q",
                "-I",
                "-L", "logins.txt",
                "-f",
                "-s", "21",
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
                "-P", str(HydraConfig().get_default_wordlist_path("snmp", "passwords")),
                "-t", "8",
                "-q",
                "-I",
                "snmp://127.0.0.1"
            ],
        ),
    ]
)
def test_build_command(hydra_attack, target, protocol, login_file, password_file, tasks, port, stop_on_success, expected_command):
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
    result_files = list(Path(hydra_attack.results_dir).glob(f"attack_{result.protocol}_{result.target}_*.json"))
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
async def test_process_hydra_output(hydra_attack):
    """Test process_hydra_output method with proper isolation."""
    # Create a mock process output
    mock_output = [
        b"[21][ftp] host: 192.217.238.3   login: sysadmin   password: 654321\n",
    ]
    mock_process = AsyncMock()
    mock_process.stdout.readline = AsyncMock(side_effect=mock_output + [b""])  # End of stream
    mock_process.stderr.readline = AsyncMock(return_value=b"")
    mock_process.terminate = Mock(return_value=None)

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
async def test_run_attack_success(hydra_attack):
    """Test successful attack with complete file operation mocking."""
    # Create a proper mock process using the same pattern as the fixture
    mock_process = Mock()
    mock_process.returncode = 0
    
    # Mock stdout and stderr with regular Mock, but their methods with AsyncMock
    mock_process.stdout = Mock()
    mock_process.stderr = Mock()
    
    # Configure async methods
    mock_process.stdout.readline = AsyncMock(side_effect=[
        b"[21][ftp] host: 127.0.0.1   login: admin   password: 123456\n",
        b""  # End of stream
    ])
    mock_process.stderr.readline = AsyncMock(return_value=b"")
    mock_process.wait = AsyncMock(return_value=0)
    
    # Keep synchronous methods as regular Mock
    mock_process.terminate = Mock(return_value=None)
    mock_process.kill = Mock(return_value=None)

    with patch("asyncio.create_subprocess_exec", return_value=mock_process) as mock_exec:
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
async def test_run_attack_timeout(hydra_attack):
    """Test attack timeout with proper file isolation."""
    # Create mock process using the same pattern
    mock_process = Mock()
    mock_process.returncode = None
    
    # Mock stdout and stderr with regular Mock
    mock_process.stdout = Mock()
    mock_process.stderr = Mock()
    
    # Configure async methods to raise TimeoutError
    mock_process.stdout.readline = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_process.stderr.readline = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_process.wait = AsyncMock(return_value=0)
    
    # Keep synchronous methods as regular Mock
    mock_process.terminate = Mock(return_value=None)
    mock_process.kill = Mock(return_value=None)

    with patch("asyncio.create_subprocess_exec", return_value=mock_process):
        result = await hydra_attack.run_attack(ip="127.0.0.1", protocol="ftp", timeout=1)

        assert result.status == "timeout"
        assert result.error is not None
        assert len(result.credentials) == 0

        # Verify that a results file was still created (even for timeouts)
        result_files = list(Path(hydra_attack.results_dir).glob("attack_*.json"))
        assert len(result_files) == 1


@pytest.mark.asyncio
async def test_run_attack_hydra_not_found(hydra_attack):
    """Test hydra not found error with proper file isolation."""
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
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


if __name__ == "__main__":
    pytest.main([__file__])
