import pytest
from unittest.mock import patch, Mock, mock_open
import asyncio
import json
import tempfile
from pathlib import Path
from ..tools.bruteforce.hydrapy import HydraAttack, HydraConfig, AttackResult


@pytest.fixture
def hydra_attack():
    """Create HydraAttack instance with temporary directory to avoid file creation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        attack = HydraAttack(output_dir=tmp_dir)
        yield attack


@pytest.fixture
def hydra_config():
    return HydraConfig()


@pytest.fixture
def mock_process():
    # Create a completely synchronous mock that mimics async behavior
    process = Mock()

    # Create mock streams with custom async methods
    stdout_mock = Mock()
    stderr_mock = Mock()

    # Create custom coroutine functions that return actual coroutines without AsyncMock
    async def mock_stdout_readline():
        return b""

    async def mock_stderr_readline():
        return b""

    async def mock_wait():
        return 0

    # Assign the coroutine functions directly
    stdout_mock.readline = mock_stdout_readline
    stderr_mock.readline = mock_stderr_readline

    process.stdout = stdout_mock
    process.stderr = stderr_mock
    process.returncode = 0

    # Use regular Mock for synchronous methods
    process.terminate = Mock(return_value=None)
    process.kill = Mock(return_value=None)
    process.wait = mock_wait

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
def test_build_command(hydra_attack):
    target = "example.com"
    protocol = "ftp"
    login_file = "logins.txt"
    password_file = "passwords.txt"
    tasks = 16
    port = 21
    stop_on_success = True

    command = hydra_attack._build_command(
        target, protocol, login_file, password_file, tasks, port, stop_on_success
    )

    assert command[0] == "hydra"
    assert "-P" in command
    assert str(password_file) in command
    assert "-t" in command
    assert str(tasks) in command
    assert "-f" in command
    assert "-s" in command
    assert str(port) in command
    assert f"{protocol}://{target}" in command


# Test save results - now properly isolated
def test_save_results():
    """Test save_results method with proper isolation using temporary directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        hydra_attack = HydraAttack(output_dir=tmp_dir)

        result = AttackResult(
            target="example.com",
            protocol="ftp",
            credentials=[{"username": "admin", "password": "password"}],
            start_time=1000.0,
            end_time=1010.0,
            status="success",
            port="21",
        )

        hydra_attack.save_results(result)

        # Check if file was created in temporary directory
        result_files = list(Path(tmp_dir).glob("attack_*.json"))
        assert len(result_files) == 1

        # Verify content
        with open(result_files[0]) as f:
            saved_data = json.load(f)
            assert saved_data["target"] == "example.com"
            assert saved_data["protocol"] == "ftp"
            assert saved_data["port"] == "21"
            assert len(saved_data["credentials"]) == 1


@pytest.mark.asyncio
async def test_run_attack_success():
    """Test successful attack with complete file operation mocking."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        hydra_attack = HydraAttack(output_dir=tmp_dir)

        # Create a mock process
        mock_process = Mock()
        mock_process.returncode = 0

        # Create proper async mock functions for the test
        async def mock_stdout_readline():
            # First call returns credential line, second call returns empty to end loop
            if not hasattr(mock_stdout_readline, "call_count"):
                mock_stdout_readline.call_count = 0
            mock_stdout_readline.call_count += 1

            if mock_stdout_readline.call_count == 1:
                return b"[21][ftp] host: 127.0.0.1   login: admin   password: 123456\n"
            else:
                return b""

        async def mock_stderr_readline():
            return b""

        async def mock_wait():
            return 0

        # Set up mock streams
        stdout_mock = Mock()
        stderr_mock = Mock()
        stdout_mock.readline = mock_stdout_readline
        stderr_mock.readline = mock_stderr_readline

        mock_process.stdout = stdout_mock
        mock_process.stderr = stderr_mock
        mock_process.terminate = Mock(return_value=None)
        mock_process.kill = Mock(return_value=None)
        mock_process.wait = mock_wait

        with patch("asyncio.create_subprocess_exec", return_value=mock_process) as mock_exec:
            result = await hydra_attack.run_attack(ip="127.0.0.1", protocol="ftp", port=21)

            assert result.status == "success"
            assert len(result.credentials) == 1
            assert result.target == "127.0.0.1"
            assert result.protocol == "ftp"
            assert mock_exec.called

            # Verify that a results file was created in the temporary directory
            result_files = list(Path(tmp_dir).glob("attack_*.json"))
            assert len(result_files) == 1


@pytest.mark.asyncio
async def test_run_attack_timeout():
    """Test attack timeout with proper file isolation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        hydra_attack = HydraAttack(output_dir=tmp_dir)

        mock_process = Mock()
        mock_process.returncode = None

        async def mock_timeout_readline():
            raise asyncio.TimeoutError()

        async def mock_wait():
            return 0

        stdout_mock = Mock()
        stderr_mock = Mock()
        stdout_mock.readline = mock_timeout_readline
        stderr_mock.readline = mock_timeout_readline

        mock_process.stdout = stdout_mock
        mock_process.stderr = stderr_mock
        mock_process.terminate = Mock(return_value=None)
        mock_process.kill = Mock(return_value=None)
        mock_process.wait = mock_wait

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await hydra_attack.run_attack(
                ip="127.0.0.1", protocol="ftp", timeout=1
            )

            assert result.status == "timeout"
            assert result.error is not None
            assert len(result.credentials) == 0

            # Verify that a results file was still created (even for timeouts)
            result_files = list(Path(tmp_dir).glob("attack_*.json"))
            assert len(result_files) == 1


@pytest.mark.asyncio
async def test_run_attack_hydra_not_found():
    """Test hydra not found error with proper file isolation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        hydra_attack = HydraAttack(output_dir=tmp_dir)

        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
            result = await hydra_attack.run_attack(ip="127.0.0.1", protocol="ftp")

            assert result.status == "failed"
            assert "Hydra is not installed" in result.error

            # The actual behavior: no results file is created when FileNotFoundError occurs
            # because save_results is not called in the exception handler
            result_files = list(Path(tmp_dir).glob("attack_*.json"))
            assert len(result_files) == 0


def test_hydra_config_wordlist_creation():
    """Test HydraConfig wordlist creation with temporary directories."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Override the default wordlists directory for testing
        config = HydraConfig()
        config.DEFAULT_WORDLISTS_DIR = Path(tmp_dir) / "wordlists"
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
