"""
Create scanner attach tokens from the orchestrator host.

Usage:
    python3 -m darkstar.scanner_attach create --name edge-office --url http://darkstar.local:8080
"""

from __future__ import annotations

import argparse
import os
import shlex
from pathlib import Path

from .core.db_helper import create_scanner_node


def _scanner_env(node: dict, orchestrator_url: str) -> dict[str, str]:
    return {
        "DARKSTAR_ORCHESTRATOR_URL": orchestrator_url.rstrip("/"),
        "DARKSTAR_SCANNER_TOKEN": node["token"],
        "DARKSTAR_SCANNER_NAME": node["name"],
        "DARKSTAR_WORKER_MAX_PARALLEL": str(node["max_parallel_jobs"]),
        "DB_HOST": os.environ.get("DB_HOST", "mariadb"),
        "DB_NAME": os.environ.get("DB_NAME", "darkstar"),
        "DB_USER": os.environ.get("DB_USER", "data_miner"),
        "DB_PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "PYTHONPATH": "/app:/app/darkstar",
    }


def _write_env_file(path: str | os.PathLike[str], values: dict[str, str]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        for key, value in values.items():
            clean_value = str(value).replace("\n", "")
            handle.write(f"{key}={clean_value}\n")
    os.chmod(target, 0o600)
    return target


def _attach_command(
    node: dict,
    orchestrator_url: str,
    image: str,
    network: str | None,
    env_file: str | os.PathLike[str] | None = None,
) -> str:
    network_arg = f"--network {shlex.quote(network)} " if network else ""
    if env_file:
        env_args = f"--env-file {shlex.quote(str(env_file))}"
    else:
        env_values = _scanner_env(node, orchestrator_url)
        env_args = " ".join(
            f"-e {key}={shlex.quote(value)}"
            for key, value in env_values.items()
        )
    container_name = f"darkstar-scanner-{node['node_id']}"
    return (
        "docker run -d "
        f"--name {shlex.quote(container_name)} "
        "--restart unless-stopped "
        f"{network_arg}"
        f"{env_args} "
        f"{shlex.quote(image)} python3 -m darkstar.scanner_worker"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Create Darkstar scanner attach tokens")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create", help="Create a scanner node and print its attach command")
    create.add_argument("--name", required=True)
    create.add_argument("--url", default=os.environ.get("DARKSTAR_PUBLIC_URL", "http://darkstar.local:8080"))
    create.add_argument("--image", default=os.environ.get("DARKSTAR_SCANNER_IMAGE", "darkstar-darkstar-web"))
    create.add_argument("--network", default=os.environ.get("DARKSTAR_SCANNER_NETWORK"))
    create.add_argument("--max-parallel-jobs", type=int, default=1)
    create.add_argument(
        "--env-file",
        help="Write scanner secrets to this 0600 env file and reference it from docker run",
    )
    args = parser.parse_args()

    if args.command == "create":
        node = create_scanner_node(args.name, capabilities=["*"], max_parallel_jobs=args.max_parallel_jobs)
        env_file = args.env_file or f"darkstar-scanner-{node['node_id']}.env"
        env_path = _write_env_file(env_file, _scanner_env(node, args.url))
        print(f"Scanner node: {node['node_id']}")
        print(f"Secret env file: {env_path} (mode 0600)")
        print()
        command_node = {
            "node_id": node["node_id"],
            "name": node["name"],
            "max_parallel_jobs": node["max_parallel_jobs"],
        }
        command = _attach_command(command_node, args.url, args.image, args.network, env_file=env_path)
        print(command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
