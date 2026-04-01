import logging
import os
import subprocess
import sys
import threading
import json
import asyncio
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from dotenv import load_dotenv

# Global reference to event loop for async operations from threads
_event_loop = None

from .core.db_helper import (
    create_scan_record,
    ensure_organization,
    get_latest_vulnerabilities,
    get_scan_history,
    get_vulnerability_stats,
    update_scan_status,
    insert_scan_log,
    insert_scan_logs_batch,
    get_scan_logs,
    get_vulnerabilities_filtered,
    get_unique_hosts,
    get_unique_tools,
)

logger = logging.getLogger("webapp")
logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
WEB_DIR = BASE_DIR / "web"

if (PROJECT_ROOT / ".env").exists():
    load_dotenv(PROJECT_ROOT / ".env")

app = FastAPI(title="Darkstar Dashboard", version="1.0.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("WEB_SESSION_SECRET", "darkstar-dev-secret-change-me"),
    same_site="lax",
)
app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))


@app.on_event("startup")
async def startup_event():
    """Capture event loop for thread-safe async operations."""
    global _event_loop
    _event_loop = asyncio.get_event_loop()
    logger.info("Darkstar webapp started")


# WebSocket connection manager for real-time debug output
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, list[WebSocket]] = defaultdict(list)

    async def connect(self, websocket: WebSocket, scan_id: int):
        await websocket.accept()
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, scan_id: int, websocket: WebSocket):
        if scan_id not in self.active_connections:
            return
        if websocket in self.active_connections[scan_id]:
            self.active_connections[scan_id].remove(websocket)
        if not self.active_connections[scan_id]:
            del self.active_connections[scan_id]

    def has_connections(self, scan_id: int) -> bool:
        return bool(self.active_connections.get(scan_id))

    async def broadcast(self, scan_id: int, message: dict):
        disconnected = []
        for connection in self.active_connections[scan_id]:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.debug(f"Error sending message to websocket: {e}")
                disconnected.append(connection)
        
        for conn in disconnected:
            self.disconnect(scan_id, conn)

manager = ConnectionManager()

ALLOWED_SCANNERS = {
    "bbot_passive",
    "bbot_normal",
    "bbot_aggressive",
    "bbot_attack_surface",
    "rustscan",
    "nuclei",
    "nucleinetwork",
    "wordpressnuclei",
    "openvas",
    "asteroid_normal",
    "asteroid_aggressive",
}


class LoginRequest(BaseModel):
    organization: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=128)


class ScanStartRequest(BaseModel):
    targets: str = Field(min_length=1)
    mode: int | None = Field(default=None)
    scanner: str | None = Field(default=None)
    scan_name: str | None = Field(default=None, max_length=255)
    bruteforce: bool = False
    bruteforce_timeout: int = Field(default=300, ge=10, le=3600)


def _get_org_db(request: Request) -> str:
    org_db = request.session.get("org_db")
    if not org_db:
        raise HTTPException(status_code=401, detail="Login required")
    return org_db


def _run_scan_job(scan_id: int, org_db: str, payload: ScanStartRequest):
    """Run scan with real-time output streaming to WebSocket clients."""
    try:
        update_scan_status(org_db, scan_id, "running")
        logger.info(f"Starting scan {scan_id} for org {org_db}")
        
        command = [
            sys.executable,
            "-m",
            "darkstar.main",
            "-t",
            payload.targets,
            "-d",
            org_db,
        ]

        if payload.mode is not None:
            command.extend(["-m", str(payload.mode)])
        if payload.scanner:
            command.extend(["-s", payload.scanner])
        if payload.bruteforce:
            command.append("--bruteforce")
        command.extend(["--bruteforce-timeout", str(payload.bruteforce_timeout)])

        env_path = PROJECT_ROOT / ".env"
        if env_path.exists():
            command.extend(["-env", str(env_path)])

        logger.info(f"Scan command: {' '.join(command)}")
        env_dict = os.environ.copy()
        # Include both the project root (for `import darkstar`) and the
        # darkstar package directory (for legacy `from core.X import` paths
        # used inside the scanner modules).
        env_dict["PYTHONPATH"] = f"{PROJECT_ROOT}{os.pathsep}{BASE_DIR}"

        # Use Popen for real-time output streaming
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(PROJECT_ROOT),
            env=env_dict,
        )

        # Stream output in real-time
        all_output = []
        log_batch: list[str] = []
        batch_size = 25
        for line in process.stdout:
            line = line.rstrip('\n')
            if not line:
                continue
            all_output.append(line)

            # Batch log inserts to reduce DB transaction overhead
            log_batch.append(line)
            if len(log_batch) >= batch_size:
                insert_scan_logs_batch(org_db, scan_id, log_batch, "info")
                log_batch.clear()

            # Broadcast to WebSocket clients
            if manager.has_connections(scan_id) and _event_loop:
                try:
                    asyncio.run_coroutine_threadsafe(
                        manager.broadcast(scan_id, {
                            "type": "log",
                            "level": "info",
                            "message": line,
                            "timestamp": datetime.utcnow().isoformat(),
                        }),
                        _event_loop,
                    )
                except Exception as e:
                    logger.warning(f"WebSocket broadcast error for scan {scan_id}: {e}")

        if log_batch:
            insert_scan_logs_batch(org_db, scan_id, log_batch, "info")

        returncode = process.wait()
        logger.info(f"Scan {scan_id} process exited with code {returncode}")

        if returncode != 0:
            error_msg = "\n".join(all_output[-20:]) if all_output else "Scan failed"
            logger.error(f"Scan {scan_id} failed: {error_msg}")
            update_scan_status(org_db, scan_id, "failed", error_message=error_msg[:4000])
            if manager.has_connections(scan_id) and _event_loop:
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast(scan_id, {
                        "type": "error",
                        "message": f"Scan failed with code {returncode}",
                        "timestamp": datetime.utcnow().isoformat(),
                    }),
                    _event_loop,
                )
            return

        update_scan_status(org_db, scan_id, "completed")
        logger.info(f"Scan {scan_id} completed successfully")
        if manager.has_connections(scan_id) and _event_loop:
            asyncio.run_coroutine_threadsafe(
                manager.broadcast(scan_id, {
                    "type": "completed",
                    "message": "Scan completed successfully",
                    "timestamp": datetime.utcnow().isoformat(),
                }),
                _event_loop,
            )
    except subprocess.TimeoutExpired:
        logger.error(f"Scan {scan_id} timed out after 1 hour")
        update_scan_status(org_db, scan_id, "failed", error_message="Scan timed out (>1 hour)")
    except Exception as exc:
        logger.exception(f"Scan {scan_id} failed for {org_db}")
        update_scan_status(org_db, scan_id, "failed", error_message=str(exc)[:4000])


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "logged_in": bool(request.session.get("org_db")),
            "organization": request.session.get("organization", ""),
        },
    )


@app.get("/logo_darkstar.png")
def logo():
    candidate_paths = [
        PROJECT_ROOT / "logo_darkstar.png",
        BASE_DIR / "logo_darkstar.png",
    ]
    for logo_path in candidate_paths:
        if logo_path.exists():
            return FileResponse(logo_path)
    raise HTTPException(status_code=404, detail="Logo not found")


@app.get("/api/me")
def me(request: Request):
    org_db = request.session.get("org_db")
    return {
        "authenticated": bool(org_db),
        "organization": request.session.get("organization"),
        "org_db": org_db,
    }


@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request):
    try:
        org_db, created_now = ensure_organization(body.organization, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    request.session["organization"] = body.organization
    request.session["org_db"] = org_db
    return {
        "ok": True,
        "organization": body.organization,
        "org_db": org_db,
        "created": created_now,
    }


@app.post("/api/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/api/vulnerabilities")
def vulnerabilities(request: Request, limit: int = 200):
    org_db = _get_org_db(request)
    return {"items": get_latest_vulnerabilities(org_db, limit=limit)}


@app.get("/api/assets")
def assets(request: Request, limit: int = 100):
    org_db = _get_org_db(request)
    # Future: query asmevents table for discovered assets
    # For now, return empty list
    return {"items": []}


@app.get("/api/scans")
def scans(request: Request, limit: int = 50):
    org_db = _get_org_db(request)
    return {"items": get_scan_history(org_db, limit=limit)}


@app.get("/api/stats")
def stats(request: Request):
    org_db = _get_org_db(request)
    return get_vulnerability_stats(org_db)


@app.post("/api/scans/start")
def start_scan(request: Request, body: ScanStartRequest):
    org_db = _get_org_db(request)

    # Avoid overlapping scans in the same org; concurrent runs can contend for shared outputs.
    recent_scans = get_scan_history(org_db, limit=20)
    if any(scan.get("status") in {"queued", "running"} for scan in recent_scans):
        raise HTTPException(
            status_code=409,
            detail="Another scan is already running for this organization",
        )

    has_mode = body.mode is not None
    has_scanner = bool(body.scanner)

    if has_mode == has_scanner:
        raise HTTPException(
            status_code=400,
            detail="Provide either mode or scanner, but not both",
        )

    if body.mode is not None and body.mode not in {1, 2, 3, 4}:
        raise HTTPException(status_code=400, detail="Mode must be one of 1,2,3,4")

    if body.scanner and body.scanner not in ALLOWED_SCANNERS:
        raise HTTPException(status_code=400, detail="Unsupported scanner")

    targets = body.targets.strip()
    if not targets:
        raise HTTPException(status_code=400, detail="Targets cannot be empty")

    scan_name = body.scan_name or f"Scan {body.mode or body.scanner}"
    scan_id = create_scan_record(
        org_db,
        scan_name=scan_name,
        scan_mode=str(body.mode or body.scanner),
        targets=targets,
    )

    thread = threading.Thread(
        target=_run_scan_job,
        args=(scan_id, org_db, body),
        daemon=True,
    )
    thread.start()

    return {"ok": True, "scan_id": scan_id, "status": "queued"}


@app.get("/api/vulnerabilities/filtered")
def get_filtered_vulnerabilities(
    request: Request,
    severity: str | None = None,
    host: str | None = None,
    tool: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    """Get vulnerabilities with filtering and pagination."""
    org_db = _get_org_db(request)
    items, total = get_vulnerabilities_filtered(org_db, severity, host, tool, limit, offset)
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/scans/{scan_id}/logs")
def get_scan_logs_api(request: Request, scan_id: int, limit: int = 500):
    """Get execution logs for a specific scan."""
    org_db = _get_org_db(request)
    logs = get_scan_logs(org_db, scan_id, limit)
    return {"items": logs}


@app.get("/api/filters/hosts")
def get_hosts_filter(request: Request):
    """Get unique hosts for filtering."""
    org_db = _get_org_db(request)
    hosts = get_unique_hosts(org_db)
    return {"items": hosts}


@app.get("/api/filters/tools")
def get_tools_filter(request: Request):
    """Get unique tools for filtering."""
    org_db = _get_org_db(request)
    tools = get_unique_tools(org_db)
    return {"items": tools}


@app.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: int):
    """WebSocket endpoint for real-time scan debug output."""
    await manager.connect(websocket, scan_id)
    try:
        # Note: In production, verify org_db from session
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                # Keep the connection open; server pushes are one-way.
                continue
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
    finally:
        manager.disconnect(scan_id, websocket)
