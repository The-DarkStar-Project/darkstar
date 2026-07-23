import os
import stat
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_darkstar_asteroid_install_script_runs_with_stubbed_installers(tmp_path):
    script = PROJECT_ROOT / "darkstar/scanners/asteroid-install.sh"
    fake_bin = tmp_path / "bin"
    fake_home = tmp_path / "home"
    log_file = tmp_path / "commands.log"
    fake_bin.mkdir()
    fake_home.mkdir()

    command_stub = """#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$INSTALL_LOG"
exit 0
"""
    for command in ["apt-get", "add-apt-repository", "pip3", "pipx"]:
        _write_executable(fake_bin / command, command_stub)

    _write_executable(
        fake_bin / "dpkg-query",
        """#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$INSTALL_LOG"
exit 1
""",
    )

    curl_stub = """#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$INSTALL_LOG"
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then
        shift
        : > "$1"
        exit 0
    fi
    shift
done
exit 1
"""
    _write_executable(fake_bin / "curl", curl_stub)
    _write_executable(fake_bin / "sha256sum", command_stub)
    _write_executable(
        fake_bin / "tar",
        """#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$INSTALL_LOG"
destination=
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-C" ]; then
        shift
        destination="$1"
    fi
    shift
done
mkdir -p "$destination"
touch "$destination/feroxbuster" "$destination/trufflehog"
exit 0
""",
    )

    env = os.environ.copy()
    env.update(
        {
            "COLUMNS": "60",
            "HOME": str(fake_home),
            "INSTALL_LOG": str(log_file),
            "PATH": f"{fake_bin}:{env['PATH']}",
        }
    )

    result = subprocess.run(
        ["bash", str(script)],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )

    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, output
    assert "dashes: command not found" not in output

    command_log = log_file.read_text(encoding="utf-8")
    assert "apt-get update" in command_log
    assert (
        "apt-get install -y --no-install-recommends "
        "python3 curl unzip software-properties-common gnupg sudo git"
        in command_log
    )
    assert "add-apt-repository -y ppa:mozillateam/ppa" in command_log
    assert "pip3 install --no-cache-dir -r requirements.txt" in command_log
    assert (
        "pip3 install --no-cache-dir -r modules/50-vulnscan/requirements.txt"
        in command_log
    )
    assert "pipx install arjun==2.2.7" in command_log
    assert "pipx install wappalyzer==2.0.2" in command_log
    assert "sha256sum --check" in command_log
