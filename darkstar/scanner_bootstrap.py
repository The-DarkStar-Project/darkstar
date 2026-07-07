"""
Provision a scanner token for the bundled single-node worker.

The default docker compose stack ships a local scanner worker so that scans run
out of the box instead of sitting "Queued for scanner workers" forever. That
worker needs a ``dscan_...`` token, but tokens are only shown once at creation
time (they are stored hashed). This module bridges that gap:

* if ``DARKSTAR_SCANNER_TOKEN`` is set, use it as-is (distributed/remote workers)
* otherwise reuse a cached token when it still authenticates
* otherwise create a fresh scanner node and cache its token

The resolved token is printed to stdout so the container entrypoint can capture
it. Distributed workers on separate hosts still use ``scanner_attach`` with an
explicit token and never rely on this module.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .core.db_helper import authenticate_scanner_node, create_scanner_node


DEFAULT_TOKEN_FILE = "/var/lib/darkstar-scanner/local-scanner.token"
DEFAULT_NODE_NAME = "local-scanner"


def _read_cached_token(path: Path) -> str | None:
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


def _write_cached_token(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    os.chmod(path, 0o600)


def provision_token(name: str, token_file: Path, max_parallel_jobs: int = 1) -> str:
    """Return a usable scanner token, creating and caching one if needed."""
    env_token = (os.environ.get("DARKSTAR_SCANNER_TOKEN") or "").strip()
    if env_token:
        return env_token

    cached = _read_cached_token(token_file)
    if cached and authenticate_scanner_node(cached):
        return cached

    node = create_scanner_node(name, capabilities=["*"], max_parallel_jobs=max_parallel_jobs)
    _write_cached_token(token_file, node["token"])
    return node["token"]


def main() -> int:
    name = (os.environ.get("DARKSTAR_SCANNER_NAME") or DEFAULT_NODE_NAME).strip() or DEFAULT_NODE_NAME
    token_file = Path(os.environ.get("DARKSTAR_SCANNER_TOKEN_FILE") or DEFAULT_TOKEN_FILE)
    try:
        max_parallel = int(os.environ.get("DARKSTAR_WORKER_MAX_PARALLEL", "1") or "1")
    except ValueError:
        max_parallel = 1
    try:
        token = provision_token(name, token_file, max_parallel_jobs=max_parallel)
    except Exception as exc:  # pragma: no cover - surfaced to the container log
        print(f"scanner bootstrap failed: {exc}", file=sys.stderr, flush=True)
        return 1
    # Only the token goes to stdout so the caller can capture it cleanly.
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
