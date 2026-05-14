"""
Create scanner attach tokens from the orchestrator host.

Usage:
    python3 -m darkstar.scanner_attach create --name edge-office --url http://darkstar.local:8080
"""

from __future__ import annotations

import argparse
import os

from .core.db_helper import create_scanner_node


def _attach_command(node: dict, orchestrator_url: str, image: str, network: str | None) -> str:
    network_arg = f"--network {network} " if network else ""
    db_env = {
        "DB_HOST": os.environ.get("DB_HOST", "mariadb"),
        "DB_NAME": os.environ.get("DB_NAME", "darkstar"),
        "DB_USER": os.environ.get("DB_USER", "data_miner"),
        "DB_PASSWORD": os.environ.get("DB_PASSWORD", ""),
    }
    env_args = " ".join(
        [
            f"-e DARKSTAR_ORCHESTRATOR_URL='{orchestrator_url.rstrip('/')}'",
            f"-e DARKSTAR_SCANNER_TOKEN='{node['token']}'",
            f"-e DARKSTAR_SCANNER_NAME='{node['name']}'",
            f"-e DARKSTAR_WORKER_MAX_PARALLEL='{node['max_parallel_jobs']}'",
            f"-e DB_HOST='{db_env['DB_HOST']}'",
            f"-e DB_NAME='{db_env['DB_NAME']}'",
            f"-e DB_USER='{db_env['DB_USER']}'",
            f"-e DB_PASSWORD='{db_env['DB_PASSWORD']}'",
            "-e PYTHONPATH='/app:/app/darkstar'",
        ]
    )
    return (
        "docker run -d "
        f"--name darkstar-scanner-{node['node_id']} "
        "--restart unless-stopped "
        f"{network_arg}"
        f"{env_args} "
        f"{image} python3 -m darkstar.scanner_worker"
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
    args = parser.parse_args()

    if args.command == "create":
        node = create_scanner_node(args.name, capabilities=["*"], max_parallel_jobs=args.max_parallel_jobs)
        print(f"Scanner node: {node['node_id']}")
        print(f"Attach token: {node['token']}")
        print()
        print(_attach_command(node, args.url, args.image, args.network))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
