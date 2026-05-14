import sys

import pytest

from darkstar.scanner_attach import _attach_command
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
    assert "DARKSTAR_ORCHESTRATOR_URL='http://darkstar.local:8080'" in command
    assert "DARKSTAR_WORKER_MAX_PARALLEL='2'" in command
    assert "DB_PASSWORD=''" in command
    assert command.endswith("darkstar:test python3 -m darkstar.scanner_worker")
