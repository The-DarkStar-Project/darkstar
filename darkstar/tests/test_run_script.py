import os
from pathlib import Path
import shutil
import subprocess


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _write_success_command(path: Path) -> None:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)


def _write_recording_docker(path: Path) -> None:
    path.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DARKSTAR_TEST_DOCKER_LOG\"\nexit 0\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_run_script_bootstraps_a_fresh_checkout(tmp_path):
    """A new checkout should get its env file and pass readiness checks."""
    shutil.copy2(REPOSITORY_ROOT / "run.sh", tmp_path / "run.sh")
    shutil.copy2(REPOSITORY_ROOT / ".env.example", tmp_path / ".env.example")
    asteroid_dir = tmp_path / "darkstar" / "scanners" / "asteroid"
    asteroid_dir.mkdir(parents=True)
    (asteroid_dir / "asteroid.py").touch()

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_recording_docker(fake_bin / "docker")
    _write_success_command(fake_bin / "curl")

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    docker_log = tmp_path / "docker.log"
    env["DARKSTAR_TEST_DOCKER_LOG"] = str(docker_log)
    completed = subprocess.run(
        ["bash", "run.sh"],
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr

    # .env is a copy of .env.example, except that the session secret must be
    # generated: left on the shipped placeholder, the app signs cookies with an
    # ephemeral key and every restart logs all users out.
    def env_pairs(path):
        pairs = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                pairs[key.strip()] = value.strip().strip("'\"")
        return pairs

    written = env_pairs(tmp_path / ".env")
    shipped = env_pairs(tmp_path / ".env.example")

    session_secret = written.pop("WEB_SESSION_SECRET")
    shipped.pop("WEB_SESSION_SECRET")
    assert written == shipped, "run.sh must not rewrite anything but the secret"
    assert len(session_secret) >= 32
    assert session_secret not in {
        "",
        "darkstar-dev-secret-change-me",
        "change-me-in-production",
        "changeme",
        "change-me",
    }
    assert "Darkstar web app is ready" in completed.stdout
    assert "OpenVAS API is ready" in completed.stdout
    assert "Darkstar installation is ready" in completed.stdout
    docker_calls = docker_log.read_text(encoding="utf-8")
    assert "compose --progress plain --profile darkstar build darkstar openvas-api" in docker_calls
    assert "compose --profile darkstar up -d --no-build" in docker_calls
    assert "up -d --build" not in docker_calls


def test_run_script_has_valid_bash_syntax():
    completed = subprocess.run(
        ["bash", "-n", str(REPOSITORY_ROOT / "run.sh")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
