import stat
import sys

import pytest

from darkstar import scanner_bootstrap
from darkstar.scanner_attach import (
    _attach_command,
    _env_file_attach_command,
    _scanner_env,
    _write_env_file,
)
from darkstar.scanner_worker import ScannerWorker, _split_capabilities


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, ["*"]),
        ("", ["*"]),
        ("nuclei, zap ,openvas", ["nuclei", "zap", "openvas"]),
        (" , , ", ["*"]),
    ],
)
def test_split_capabilities(raw, expected):
    assert _split_capabilities(raw) == expected


def test_worker_build_command_for_mode_scan(monkeypatch):
    monkeypatch.setenv("DARKSTAR_WORKER_ENV_FILE", "/app/.env")
    worker = ScannerWorker(
        orchestrator_url="http://darkstar-web:8080/",
        token="dscan_test",
        name="local",
        capabilities=["*"],
    )

    command = worker.build_command(
        {
            "id": 42,
            "targets": "fallback.example",
            "org_db_name": "tenant_db",
            "payload": {
                "targets": "example.com,api.example.com",
                "mode": 3,
                "bruteforce": True,
                "bruteforce_timeout": 120,
            },
        }
    )

    assert command[:6] == [
        sys.executable,
        "-m",
        "darkstar.main",
        "-t",
        "example.com,api.example.com",
        "-d",
    ]
    assert "tenant_db" in command
    assert ["-m", "3"] == command[command.index("-m", 3):command.index("-m", 3) + 2]
    assert "--bruteforce" in command
    assert ["--bruteforce-timeout", "120"] == command[
        command.index("--bruteforce-timeout"):command.index("--bruteforce-timeout") + 2
    ]
    assert ["-env", "/app/.env"] == command[-2:]


def test_worker_build_command_for_single_scanner(monkeypatch):
    monkeypatch.delenv("DARKSTAR_WORKER_ENV_FILE", raising=False)
    worker = ScannerWorker(
        orchestrator_url="http://darkstar-web:8080",
        token="dscan_test",
        name="local",
        capabilities=["nuclei"],
    )

    command = worker.build_command(
        {
            "id": 42,
            "targets": "fallback.example",
            "org_db_name": "tenant_db",
            "payload": {"scanner": "nuclei"},
        }
    )

    assert ["-t", "fallback.example"] == command[command.index("-t"):command.index("-t") + 2]
    assert ["-s", "nuclei"] == command[command.index("-s"):command.index("-s") + 2]
    assert "--bruteforce" not in command


def test_attach_command_includes_network_and_database_env(monkeypatch):
    monkeypatch.setenv("DB_HOST", "mariadb")
    monkeypatch.setenv("DB_NAME", "darkstar")
    monkeypatch.setenv("DB_USER", "data_miner")
    monkeypatch.setenv("DB_PASSWORD", "")

    command = _attach_command(
        {"node_id": "node-123", "token": "dscan_test", "name": "office", "max_parallel_jobs": 2},
        orchestrator_url="http://darkstar.local:8080/",
        image="darkstar:test",
        network="darkstar_vuln_net",
    )

    assert "--network darkstar_vuln_net" in command
    assert "--name darkstar-scanner-node-123" in command
    assert "DARKSTAR_ORCHESTRATOR_URL=http://darkstar.local:8080" in command
    assert "DARKSTAR_WORKER_MAX_PARALLEL=2" in command
    assert "DB_PASSWORD=''" in command
    assert command.endswith("darkstar:test python3 -m darkstar.scanner_worker")


def test_attach_command_can_reference_secret_env_file_without_printing_secrets(tmp_path):
    node = {"node_id": "node-123", "token": "dscan_secret", "name": "office", "max_parallel_jobs": 2}
    env_path = tmp_path / "scanner.env"

    written_path = _write_env_file(env_path, _scanner_env(node, "http://darkstar.local:8080/"))
    command = _env_file_attach_command(
        node["node_id"],
        image="darkstar:test",
        network="darkstar_vuln_net",
        env_file=written_path,
    )

    assert f"--env-file {written_path}" in command
    assert "dscan_secret" not in command
    assert "DB_PASSWORD" not in command
    assert "DARKSTAR_SCANNER_TOKEN" not in command
    assert "DARKSTAR_SCANNER_TOKEN=dscan_secret" in written_path.read_text()
    assert stat.S_IMODE(written_path.stat().st_mode) == 0o600


def test_bootstrap_prefers_explicit_env_token(monkeypatch, tmp_path):
    monkeypatch.setenv("DARKSTAR_SCANNER_TOKEN", "dscan_env")

    def _fail(*_args, **_kwargs):  # pragma: no cover - must not be called
        raise AssertionError("should not create a node when a token is set")

    monkeypatch.setattr(scanner_bootstrap, "create_scanner_node", _fail)
    monkeypatch.setattr(scanner_bootstrap, "authenticate_scanner_node", _fail)

    token = scanner_bootstrap.provision_token("local-scanner", tmp_path / "t.token")

    assert token == "dscan_env"
    assert not (tmp_path / "t.token").exists()


def test_bootstrap_reuses_valid_cached_token(monkeypatch, tmp_path):
    monkeypatch.delenv("DARKSTAR_SCANNER_TOKEN", raising=False)
    token_file = tmp_path / "local-scanner.token"
    token_file.write_text("dscan_cached\n")

    monkeypatch.setattr(scanner_bootstrap, "authenticate_scanner_node", lambda token: {"node_id": "n1"} if token == "dscan_cached" else None)

    def _fail(*_args, **_kwargs):  # pragma: no cover - must not be called
        raise AssertionError("should not create a node when cache is valid")

    monkeypatch.setattr(scanner_bootstrap, "create_scanner_node", _fail)

    assert scanner_bootstrap.provision_token("local-scanner", token_file) == "dscan_cached"


def test_bootstrap_creates_and_caches_when_no_valid_token(monkeypatch, tmp_path):
    monkeypatch.delenv("DARKSTAR_SCANNER_TOKEN", raising=False)
    token_file = tmp_path / "local-scanner.token"
    token_file.write_text("dscan_revoked\n")

    monkeypatch.setattr(scanner_bootstrap, "authenticate_scanner_node", lambda token: None)
    created = {}

    def _create(name, capabilities=None, max_parallel_jobs=1):
        created["args"] = (name, capabilities, max_parallel_jobs)
        return {"node_id": "n2", "token": "dscan_new"}

    monkeypatch.setattr(scanner_bootstrap, "create_scanner_node", _create)

    token = scanner_bootstrap.provision_token("local-scanner", token_file, max_parallel_jobs=2)

    assert token == "dscan_new"
    assert token_file.read_text().strip() == "dscan_new"
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert created["args"] == ("local-scanner", ["*"], 2)
