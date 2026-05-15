"""
Scanner-only worker for the Darkstar orchestrator.

This process runs inside scanner containers. It has no frontend and no tenant
auth surface: it claims queued scan jobs from the orchestrator API, executes the
existing scanner runner, streams logs back, and marks the job complete.
"""

from __future__ import annotations

import argparse
import os
import select
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import requests


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent


def _split_capabilities(value: str | None) -> list[str]:
    if not value:
        return ["*"]
    return [item.strip() for item in value.split(",") if item.strip()] or ["*"]


class ScannerWorker:
    def __init__(
        self,
        orchestrator_url: str,
        token: str,
        name: str,
        capabilities: list[str],
        max_parallel_jobs: int = 1,
        poll_seconds: int = 5,
        lease_seconds: int = 900,
    ):
        self.orchestrator_url = orchestrator_url.rstrip("/")
        self.token = token
        self.name = name
        self.capabilities = capabilities
        self.max_parallel_jobs = max(1, max_parallel_jobs)
        self.poll_seconds = max(1, poll_seconds)
        self.lease_seconds = max(60, lease_seconds)
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        self.active_threads: dict[int, threading.Thread] = {}
        self.stop_event = threading.Event()

    def _api(self, method: str, path: str, **kwargs) -> Any:
        response = self.session.request(
            method,
            f"{self.orchestrator_url}{path}",
            timeout=30,
            **kwargs,
        )
        response.raise_for_status()
        if response.content:
            return response.json()
        return {}

    def heartbeat(self, status: str = "online") -> None:
        self._api(
            "POST",
            "/api/scanner-workers/heartbeat",
            json={
                "capabilities": self.capabilities,
                "status": status,
            },
        )

    def claim(self) -> dict | None:
        payload = self._api(
            "POST",
            "/api/scanner-workers/jobs/claim",
            json={
                "capabilities": self.capabilities,
                "lease_seconds": self.lease_seconds,
            },
        )
        return payload.get("job")

    def send_logs(self, job_id: int, messages: list[str], level: str = "info") -> bool:
        payload = self._api(
            "POST",
            f"/api/scanner-workers/jobs/{job_id}/logs",
            json={
                "messages": messages,
                "level": level,
                "lease_seconds": self.lease_seconds,
            },
        )
        return bool(payload.get("stop_requested"))

    def complete(self, job_id: int, status: str, error_message: str | None = None) -> None:
        self._api(
            "POST",
            f"/api/scanner-workers/jobs/{job_id}/complete",
            json={
                "status": status,
                "error_message": error_message,
            },
        )

    def build_command(self, job: dict) -> list[str]:
        payload = job.get("payload") or {}
        command = [
            sys.executable,
            "-m",
            "darkstar.main",
            "-t",
            payload.get("targets") or job["targets"],
            "-d",
            job["org_db_name"],
        ]
        mode = payload.get("mode")
        scanner = payload.get("scanner")
        if mode is not None:
            command.extend(["-m", str(mode)])
        if scanner:
            command.extend(["-s", str(scanner)])
        if payload.get("bruteforce"):
            command.append("--bruteforce")
        command.extend(["--bruteforce-timeout", str(payload.get("bruteforce_timeout") or 300)])

        env_file = os.environ.get("DARKSTAR_WORKER_ENV_FILE")
        if env_file:
            command.extend(["-env", env_file])
        return command

    def _terminate_process_group(self, process: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except ProcessLookupError:
            return
        except Exception:
            process.terminate()

    def run_job(self, job: dict) -> None:
        job_id = int(job["id"])
        command = self.build_command(job)
        log_prefix = f"[{self.name}]"
        all_output: list[str] = []
        stop_requested = False
        process: subprocess.Popen | None = None

        try:
            self.send_logs(job_id, [f"{log_prefix} starting: {' '.join(command)}"])
            env = os.environ.copy()
            env["PYTHONPATH"] = f"{PROJECT_ROOT}{os.pathsep}{BASE_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=str(PROJECT_ROOT),
                env=env,
                start_new_session=True,
            )

            batch: list[str] = []
            last_flush = time.monotonic()
            assert process.stdout is not None
            while process.poll() is None:
                ready, _, _ = select.select([process.stdout], [], [], 3)
                if ready:
                    line = process.stdout.readline()
                    if not line:
                        continue
                    line = line.rstrip("\n")
                    if line:
                        all_output.append(line)
                        batch.append(line)

                should_flush = bool(batch) and (len(batch) >= 25 or (time.monotonic() - last_flush) >= 3)
                should_heartbeat = not batch and (time.monotonic() - last_flush) >= 10
                if should_flush or should_heartbeat:
                    stop_requested = self.send_logs(job_id, batch) or stop_requested
                    batch = []
                    last_flush = time.monotonic()
                if stop_requested and process.poll() is None:
                    self._terminate_process_group(process)

            for line in process.stdout:
                line = line.rstrip("\n")
                if line:
                    all_output.append(line)
                    batch.append(line)

            if batch:
                stop_requested = self.send_logs(job_id, batch) or stop_requested

            return_code = process.wait()
            if stop_requested:
                self.complete(job_id, "stopped", "Scan stopped by user")
            elif return_code == 0:
                self.complete(job_id, "completed")
            else:
                error_message = "\n".join(all_output[-20:]) if all_output else f"Scanner exited with code {return_code}"
                self.complete(job_id, "failed", error_message[:4000])
        except Exception as exc:
            if process and process.poll() is None:
                self._terminate_process_group(process)
            try:
                self.complete(job_id, "failed", str(exc)[:4000])
            except Exception as complete_exc:
                print(f"Failed to mark scanner job {job_id} failed: {complete_exc}", file=sys.stderr, flush=True)
        finally:
            self.active_threads.pop(job_id, None)

    def run_forever(self) -> None:
        print(f"Darkstar scanner worker '{self.name}' connected to {self.orchestrator_url}", flush=True)
        while not self.stop_event.is_set():
            try:
                self.heartbeat("busy" if self.active_threads else "online")
                while len(self.active_threads) < self.max_parallel_jobs:
                    job = self.claim()
                    if not job:
                        break
                    job_id = int(job["id"])
                    thread = threading.Thread(target=self.run_job, args=(job,), daemon=True)
                    self.active_threads[job_id] = thread
                    thread.start()
            except Exception as exc:
                print(f"Worker loop error: {exc}", flush=True)
            time.sleep(self.poll_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a Darkstar scanner worker")
    parser.add_argument("--orchestrator-url", default=os.environ.get("DARKSTAR_ORCHESTRATOR_URL"))
    parser.add_argument("--token", default=os.environ.get("DARKSTAR_SCANNER_TOKEN"))
    parser.add_argument("--name", default=os.environ.get("DARKSTAR_SCANNER_NAME", "darkstar-scanner"))
    parser.add_argument("--capabilities", default=os.environ.get("DARKSTAR_SCANNER_CAPABILITIES", "*"))
    parser.add_argument("--max-parallel-jobs", type=int, default=int(os.environ.get("DARKSTAR_WORKER_MAX_PARALLEL", "1")))
    parser.add_argument("--poll-seconds", type=int, default=int(os.environ.get("DARKSTAR_WORKER_POLL_SECONDS", "5")))
    args = parser.parse_args()

    if not args.orchestrator_url:
        print("DARKSTAR_ORCHESTRATOR_URL is required", file=sys.stderr)
        return 2
    if not args.token:
        print("DARKSTAR_SCANNER_TOKEN is required", file=sys.stderr)
        return 2

    worker = ScannerWorker(
        orchestrator_url=args.orchestrator_url,
        token=args.token,
        name=args.name,
        capabilities=_split_capabilities(args.capabilities),
        max_parallel_jobs=args.max_parallel_jobs,
        poll_seconds=args.poll_seconds,
    )
    worker.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
