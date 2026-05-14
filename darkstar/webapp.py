import logging
import os
import re
import signal
import subprocess
import sys
import threading
import json
import asyncio
import base64
import csv
import hmac
import io
import smtplib
import secrets
import struct
import time
import requests
import zipfile
from email.message import EmailMessage
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from dotenv import load_dotenv

# Global reference to event loop for async operations from threads
_event_loop = None

from .core.db_helper import (
    authenticate_api_key,
    authenticate_endpoint_agent,
    authenticate_scanner_node,
    cancel_queued_scanner_job,
    claim_next_scanner_job,
    complete_scanner_job,
    authenticate_user,
    create_api_key,
    create_endpoint_enrollment_token,
    create_scanner_node,
    create_or_update_user,
    create_scan_record,
    create_scan_schedule,
    delete_user,
    delete_endpoint_agent,
    delete_scan_schedule,
    delete_revoked_scanner_node,
    ensure_org_database_schema,
    ensure_organization,
    get_due_scan_schedules,
    get_bbot_potential_targets,
    get_endpoint_agent,
    get_endpoint_overview,
    get_endpoint_vulnerability,
    get_endpoint_vuln_cache_entries,
    get_grouped_vulnerabilities,
    get_latest_vulnerabilities,
    get_m365_graph_settings,
    get_m365_secure_score,
    get_notification_settings,
    get_organization_auth_settings,
    get_organization_role,
    get_attack_surface_overview,
    get_oversight_summary,
    get_platform_auth_settings,
    get_scan_record,
    get_scan_history,
    get_scan_schedule,
    get_scan_schedules,
    get_scanner_node_record,
    get_scanner_job_for_scan,
    get_sso_settings_by_org_name,
    get_scoring_overview,
    get_vulnerability_stats,
    get_vulnerability_detail,
    get_vulnerability_export_rows,
    list_api_keys,
    list_endpoint_agents,
    list_endpoint_enrollment_tokens,
    list_endpoint_software,
    list_endpoint_vulnerabilities,
    list_available_scanner_nodes,
    list_scanner_nodes,
    update_scan_status,
    update_notification_settings,
    insert_scan_log,
    insert_scan_logs_batch,
    get_scan_logs,
    get_vulnerabilities_filtered,
    get_unique_hosts,
    get_unique_tools,
    list_users_for_org,
    get_user_by_id,
    get_user_membership,
    list_organizations,
    list_user_memberships,
    list_users,
    mark_organization_login,
    mark_interrupted_scans,
    mark_orphaned_scans_without_queue,
    mark_user_login,
    mark_schedule_run,
    recalculate_vulnerability_scores,
    requeue_expired_scanner_jobs,
    register_endpoint_agent,
    replace_endpoint_vulnerabilities,
    remove_user_membership,
    request_scanner_job_stop,
    revoke_api_key,
    revoke_endpoint_agent,
    revoke_endpoint_enrollment_token,
    revoke_scanner_node,
    enqueue_scanner_job,
    extend_scanner_job_lease,
    heartbeat_scanner_node,
    set_scan_schedule_enabled,
    update_mfa_secret,
    update_organization_auth_requirements,
    update_platform_auth_settings,
    update_user_mfa_secret,
    update_m365_graph_settings,
    update_sso_settings,
    upsert_m365_secure_score_data,
    upsert_endpoint_inventory,
    upsert_endpoint_vuln_cache_entries,
)
from .core.endpoint_vuln import (
    hydrate_osv_finding,
    osv_cache_key_id,
    osv_package_key,
    query_osv_cache_results,
)
from .core.endpoint_vendor_vuln import match_vendor_vulnerabilities

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
    global _event_loop, scheduler_started
    _event_loop = asyncio.get_event_loop()
    try:
        for organization in list_organizations():
            ensure_org_database_schema(organization["org_db_name"])
            if os.environ.get("DARKSTAR_LEGACY_DIRECT_SCANS", "").lower() in {"1", "true", "yes"}:
                interrupted = mark_interrupted_scans(
                    organization["org_db_name"],
                    "Scan interrupted because the web service restarted",
                )
                if interrupted:
                    logger.warning(
                        "Marked %d interrupted scan(s) as failed for %s",
                        interrupted,
                        organization["org_db_name"],
                    )
            orphaned = mark_orphaned_scans_without_queue(
                organization["org_db_name"],
                "Scan has no distributed queue job after orchestrator restart",
            )
            if orphaned:
                logger.warning(
                    "Marked %d orphaned scan(s) as failed for %s",
                    orphaned,
                    organization["org_db_name"],
                )
    except Exception as exc:
        logger.info(f"Organization schema warmup skipped: {exc}")
    if not scheduler_started:
        scheduler_started = True
        threading.Thread(target=_scheduler_loop, daemon=True).start()
    logger.info("Darkstar webapp started")


def _scheduler_loop():
    """Simple in-process periodic scanner scheduler."""
    logger.info("Darkstar scheduler loop started")
    while True:
        try:
            expired = requeue_expired_scanner_jobs()
            if expired:
                logger.warning("Requeued %d scanner job(s) after expired worker leases", expired)
            for organization in list_organizations():
                org_db = organization["org_db_name"]
                due_schedules = get_due_scan_schedules(org_db)
                if not due_schedules:
                    continue
                for schedule in due_schedules:
                    payload = ScanStartRequest(
                        targets=schedule["targets"],
                        mode=int(schedule["scan_mode"]) if schedule.get("scan_mode") and str(schedule["scan_mode"]).isdigit() else None,
                        scanner=schedule.get("scanner"),
                        scan_name=schedule.get("scan_name"),
                        bruteforce=bool(schedule.get("bruteforce")),
                        bruteforce_timeout=int(schedule.get("bruteforce_timeout") or 300),
                        preferred_node_id=schedule.get("preferred_node_id"),
                    )
                    try:
                        scan_id = _queue_scan(org_db, payload, schedule_id=schedule["id"], allow_overlap=False)
                    except HTTPException as exc:
                        if exc.status_code == 409:
                            logger.info(
                                "Scheduled scan %s skipped for now because an identical scan is active",
                                schedule["id"],
                            )
                            continue
                        raise
                    mark_schedule_run(org_db, schedule["id"])
                    logger.info(f"Scheduled scan {scan_id} queued for {org_db}")
        except Exception as exc:
            logger.warning(f"Scheduler loop error: {exc}")
        time.sleep(60)


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
scan_processes: dict[int, subprocess.Popen] = {}
scan_processes_lock = threading.Lock()
scheduler_started = False

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
    "retirejs",
    "vulnscan",
    "nikto",
    "wapiti",
    "zap",
    "dalfox",
    "testssl",
}


class LoginRequest(BaseModel):
    email: str | None = Field(default=None, max_length=255)
    organization: str | None = Field(default=None, min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=128)


class SelectOrganizationRequest(BaseModel):
    org_db: str = Field(min_length=3, max_length=64)


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class SsoSettingsRequest(BaseModel):
    enabled: bool = False
    issuer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    allowed_domain: str | None = None


class ApiKeyRequest(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    role: str = Field(default="security_analyst", max_length=32)


class ScannerNodeRequest(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    capabilities: list[str] | None = None
    max_parallel_jobs: int = Field(default=1, ge=1, le=32)


class ScannerHeartbeatRequest(BaseModel):
    capabilities: list[str] | None = None
    status: str = Field(default="online", max_length=32)


class ScannerClaimRequest(BaseModel):
    capabilities: list[str] | None = None
    lease_seconds: int = Field(default=900, ge=60, le=7200)


class ScannerLogRequest(BaseModel):
    messages: list[str] = Field(default_factory=list)
    level: str = Field(default="info", max_length=20)
    lease_seconds: int = Field(default=900, ge=60, le=7200)


class ScannerCompleteRequest(BaseModel):
    status: str = Field(max_length=32)
    error_message: str | None = Field(default=None, max_length=4000)


class EndpointEnrollmentRequest(BaseModel):
    name: str = Field(default="Endpoint enrollment", max_length=255)
    expires_days: int | None = Field(default=30, ge=1, le=3650)


class EndpointRegisterRequest(BaseModel):
    organization: str = Field(min_length=3, max_length=64)
    enrollment_token: str = Field(min_length=16, max_length=256)
    hostname: str = Field(default="unknown", max_length=255)
    os: dict = Field(default_factory=dict)
    agent_version: str | None = Field(default=None, max_length=64)
    metadata: dict = Field(default_factory=dict)


class EndpointInventoryRequest(BaseModel):
    os: dict = Field(default_factory=dict)
    software: list[dict] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class AuthPolicyRequest(BaseModel):
    mfa_required: bool = False
    sso_required: bool = False


class AdminUserRequest(BaseModel):
    email: str = Field(max_length=255)
    password: str | None = Field(default=None, max_length=128)
    display_name: str | None = Field(default=None, max_length=255)
    org_db: str = Field(min_length=3, max_length=64)
    role: str = Field(default="viewer", max_length=32)


class OrgUserRequest(BaseModel):
    email: str = Field(max_length=255)
    password: str | None = Field(default=None, max_length=128)
    display_name: str | None = Field(default=None, max_length=255)
    role: str = Field(default="viewer", max_length=32)


class ScanStartRequest(BaseModel):
    targets: str = Field(min_length=1)
    mode: int | None = Field(default=None)
    scanner: str | None = Field(default=None)
    preferred_node_id: str | None = Field(default=None, max_length=64)
    scan_name: str | None = Field(default=None, max_length=255)
    bruteforce: bool = False
    bruteforce_timeout: int = Field(default=300, ge=10, le=3600)


class ScheduleRequest(ScanStartRequest):
    interval_minutes: int = Field(default=1440, ge=10, le=5256000)
    start_at: str | None = None
    end_at: str | None = None


class NotificationSettingsRequest(BaseModel):
    enabled: bool = False
    recipients: str | None = None
    min_severity: str = "high"
    notify_on_success: bool = True
    notify_on_failure: bool = True


class M365GraphSettingsRequest(BaseModel):
    enabled: bool = False
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


class ScheduleEnabledRequest(BaseModel):
    enabled: bool


def _password_policy_error(password: str | None) -> str | None:
    if not password:
        return None
    if len(password) < 8:
        return "Password must be at least 8 characters."
    checks = [
        (r"[a-z]", "one lowercase letter"),
        (r"[A-Z]", "one uppercase letter"),
        (r"\d", "one number"),
        (r"[^A-Za-z0-9]", "one special character"),
    ]
    missing = [label for pattern, label in checks if not re.search(pattern, password)]
    if missing:
        return "Password must include " + ", ".join(missing) + "."
    return None


def _validate_user_password(password: str | None):
    error = _password_policy_error(password)
    if error:
        raise HTTPException(status_code=400, detail=error)


def _require_current_user_mfa_enabled(request: Request):
    user_id = _current_user_id(request)
    if user_id:
        user = get_user_by_id(user_id) or {}
        if not user.get("mfa_enabled"):
            raise HTTPException(
                status_code=400,
                detail="Enable MFA for your own account before requiring MFA by policy.",
            )
        return
    org_db = _get_org_db(request)
    settings = get_organization_auth_settings(org_db)
    if not settings.get("mfa_enabled"):
        raise HTTPException(
            status_code=400,
            detail="Enable MFA for the current account before requiring MFA by policy.",
        )


def _require_sso_configured_for_enforcement(org_db: str):
    settings = get_organization_auth_settings(org_db, include_secrets=True)
    if not (
        settings.get("sso_enabled")
        and settings.get("sso_issuer")
        and settings.get("sso_client_id")
        and settings.get("sso_client_secret")
    ):
        raise HTTPException(
            status_code=400,
            detail="Configure and enable SSO with issuer, client ID and client secret before requiring SSO.",
        )


def _generate_totp_secret() -> str:
    """Generate a base32 TOTP secret without adding runtime dependencies."""
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp_code(secret: str, timestep: int | None = None) -> str:
    padded_secret = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret)
    counter = int((timestep or time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    offset = digest[-1] & 0x0F
    token = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{token % 1_000_000:06d}"


def _verify_totp(secret: str | None, code: str) -> bool:
    if not secret:
        return False
    clean_code = "".join(ch for ch in code if ch.isdigit())
    if len(clean_code) != 6:
        return False
    now = int(time.time())
    return any(hmac.compare_digest(_totp_code(secret, now + (offset * 30)), clean_code) for offset in (-1, 0, 1))


def _otpauth_uri(organization: str, secret: str) -> str:
    label = f"Darkstar:{organization}"
    return f"otpauth://totp/{label}?{urlencode({'secret': secret, 'issuer': 'Darkstar', 'algorithm': 'SHA1', 'digits': 6, 'period': 30})}"


def _qr_data_uri(payload: str) -> str | None:
    try:
        import qrcode
        import qrcode.image.svg
    except Exception:
        logger.warning("qrcode package not installed; MFA setup will show otpauth URI only")
        return None

    output = io.BytesIO()
    image = qrcode.make(payload, image_factory=qrcode.image.svg.SvgImage)
    image.save(output)
    encoded = base64.b64encode(output.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def _extract_bearer_token(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        return None
    return authorization.split(" ", 1)[1].strip()


def _get_org_db(request: Request) -> str:
    org_db = request.session.get("org_db")
    if org_db:
        return org_db

    token = _extract_bearer_token(request)
    api_context = authenticate_api_key(token) if token else None
    if api_context:
        request.state.api_org_db = api_context["org_db_name"]
        request.state.api_role = api_context.get("role") or "tenant_admin"
        request.state.api_organization = api_context.get("org_name")
        return api_context["org_db_name"]

    raise HTTPException(status_code=401, detail="Login or Bearer API key required")


def _get_role(request: Request) -> str:
    if getattr(request.state, "api_role", None):
        return request.state.api_role
    role = request.session.get("role")
    if role:
        return role
    org_db = request.session.get("org_db")
    return get_organization_role(org_db) if org_db else "viewer"


def _get_scanner_node(request: Request) -> dict:
    token = _extract_bearer_token(request)
    node = authenticate_scanner_node(token) if token else None
    if not node:
        raise HTTPException(status_code=401, detail="Valid scanner Bearer token required")
    return node


def _get_endpoint_agent_context(request: Request) -> dict:
    token = _extract_bearer_token(request)
    agent = authenticate_endpoint_agent(token) if token else None
    if not agent:
        raise HTTPException(status_code=401, detail="Valid endpoint agent Bearer token required")
    return agent


ROLE_RANK = {
    "viewer": 10,
    "security_analyst": 50,
    "tenant_admin": 80,
    "platform_admin": 100,
}


def _role_rank(role: str | None) -> int:
    return ROLE_RANK.get(role or "viewer", 0)


def _scanner_attach_command(node: dict, request: Request | None = None) -> str:
    base_url = os.environ.get("DARKSTAR_PUBLIC_URL")
    if not base_url and request is not None:
        base_url = str(request.base_url).rstrip("/")
    base_url = base_url or "http://darkstar.local:8080"
    image = os.environ.get("DARKSTAR_SCANNER_IMAGE", "darkstar-darkstar-web")
    container_name = f"darkstar-scanner-{node['node_id']}"
    db_host = os.environ.get("DB_HOST", "mariadb")
    db_name = os.environ.get("DB_NAME", "darkstar")
    db_user = os.environ.get("DB_USER", "data_miner")
    db_password = os.environ.get("DB_PASSWORD", "")
    return (
        "docker run -d "
        f"--name {container_name} "
        "--restart unless-stopped "
        f"-e DARKSTAR_ORCHESTRATOR_URL='{base_url}' "
        f"-e DARKSTAR_SCANNER_TOKEN='{node['token']}' "
        f"-e DARKSTAR_SCANNER_NAME='{node.get('name') or node['node_id']}' "
        f"-e DB_HOST='{db_host}' "
        f"-e DB_NAME='{db_name}' "
        f"-e DB_USER='{db_user}' "
        f"-e DB_PASSWORD='{db_password}' "
        "-e PYTHONPATH='/app:/app/darkstar' "
        f"{image} python3 -m darkstar.scanner_worker"
    )


def _endpoint_install_command(org_db: str, token: str, request: Request | None = None) -> str:
    base_url = os.environ.get("DARKSTAR_PUBLIC_URL")
    if not base_url and request is not None:
        base_url = str(request.base_url).rstrip("/")
    base_url = base_url or "http://darkstar.local:8080"
    return (
        "python3 -m darkstar.endpoint_agent "
        f"--url '{base_url}' "
        f"--org '{org_db}' "
        f"--enrollment-token '{token}' "
        "--interval 3600"
    )


def _endpoint_os_info_from_agent(agent: dict | None) -> dict:
    agent = agent or {}
    metadata = {}
    raw_metadata = agent.get("metadata_json")
    if raw_metadata:
        try:
            metadata = json.loads(raw_metadata) if isinstance(raw_metadata, str) else raw_metadata
        except Exception:
            metadata = {}
    metadata_os = metadata.get("os") if isinstance(metadata.get("os"), dict) else {}
    return {
        **metadata_os,
        "platform": agent.get("os_platform") or metadata.get("platform") or metadata_os.get("platform"),
        "name": agent.get("os_name") or metadata.get("name") or metadata_os.get("name"),
        "version": agent.get("os_version") or metadata.get("version") or metadata_os.get("version"),
        "arch": agent.get("os_arch") or metadata.get("arch") or metadata_os.get("arch"),
        "build": agent.get("os_build") or metadata.get("build") or metadata_os.get("build"),
        "codename": (
            metadata.get("codename")
            or metadata.get("version_codename")
            or metadata_os.get("codename")
            or metadata_os.get("version_codename")
        ),
    }


def _endpoint_cve_key(value) -> str:
    identifier = str(value or "")
    match = re.search(r"CVE-\d{4}-\d{4,}", identifier, flags=re.IGNORECASE)
    return match.group(0).upper() if match else identifier


def _dedupe_endpoint_findings(findings: list[dict]) -> list[dict]:
    preferred = {}
    for finding in findings or []:
        key = (finding.get("software_key"), _endpoint_cve_key(finding.get("cve")))
        current = preferred.get(key)
        if not current:
            preferred[key] = finding
            continue
        current_score = int(current.get("confidence") or 0)
        new_score = int(finding.get("confidence") or 0)
        if finding.get("source") != "OSV" and current.get("source") == "OSV":
            new_score += 10
        if new_score > current_score:
            preferred[key] = finding
    return list(preferred.values())


def _match_endpoint_vulnerabilities(
    org_db: str,
    software: list[dict],
    os_info: dict | None = None,
) -> tuple[list[dict], dict]:
    """Match endpoint inventory with tenant-local package/version cache."""
    findings = []
    matcher_stats = {"matcher": "osv_purl_exact_version_cached+vendor", "candidates": 0, "cache_hits": 0, "cache_misses": 0}
    if os.environ.get("ENDPOINT_OSV_MATCHING", "true").lower() not in {"0", "false", "no"}:
        candidates = []
        representatives: dict[str, dict] = {}
        queries: dict[str, dict] = {}
        for item in software or []:
            key = osv_package_key(item)
            if not key:
                continue
            cache_id = osv_cache_key_id(key)
            candidates.append((item, cache_id))
            representatives.setdefault(cache_id, item)
            queries[cache_id] = key

        matcher_stats["candidates"] = len(candidates)
        if candidates:
            cached = get_endpoint_vuln_cache_entries(org_db, list(queries.values()))
            missing_ids = [cache_id for cache_id in representatives if cache_id not in cached]
            fetched = {}
            if missing_ids:
                fetched = query_osv_cache_results([representatives[cache_id] for cache_id in missing_ids])
                upsert_endpoint_vuln_cache_entries(
                    org_db,
                    [
                        {"query": queries[cache_id], "findings": fetched.get(cache_id, [])}
                        for cache_id in missing_ids
                        if cache_id in fetched
                    ],
                )

            combined = {**cached, **fetched}
            for item, cache_id in candidates:
                for finding in combined.get(cache_id, []):
                    findings.append(hydrate_osv_finding(item, finding))
            matcher_stats.update({
                "cache_hits": len(cached),
                "cache_misses": len(missing_ids),
                "cache_writes": len(fetched),
            })

    vendor_findings = []
    if os.environ.get("ENDPOINT_VENDOR_MATCHING", "true").lower() not in {"0", "false", "no"}:
        vendor_findings = match_vendor_vulnerabilities(software or [], os_info or {})
        findings.extend(vendor_findings)

    findings = _dedupe_endpoint_findings(findings)
    matcher_stats["vendor_findings"] = len(vendor_findings)
    matcher_stats["findings_after_dedupe"] = len(findings)
    return findings, matcher_stats


def _require_min_role(request: Request, min_role: str):
    _get_org_db(request)
    if _role_rank(_get_role(request)) < _role_rank(min_role):
        raise HTTPException(status_code=403, detail=f"{min_role} role required")


def _current_user_id(request: Request) -> int | None:
    user_id = request.session.get("user_id")
    return int(user_id) if user_id else None


def _require_platform_admin(request: Request):
    _get_org_db(request)
    if _get_role(request) != "platform_admin":
        raise HTTPException(status_code=403, detail="Platform admin role required")


def _finish_user_login(request: Request, user: dict, membership: dict, auth_method: str, created: bool = False) -> dict:
    """Finalize a user session for one selected organization."""
    request.session.clear()
    request.session["user_id"] = user["id"]
    request.session["user_email"] = user["email"]
    request.session["organization"] = membership["org_name"]
    request.session["org_db"] = membership["org_db_name"]
    request.session["role"] = membership["role"]
    request.session["auth_method"] = auth_method
    mark_user_login(user["id"])
    mark_organization_login(membership["org_db_name"])
    return {
        "ok": True,
        "organization": membership["org_name"],
        "org_db": membership["org_db_name"],
        "role": membership["role"],
        "user": get_user_by_id(user["id"]),
        "created": created,
    }


def _org_choices_response(user: dict, memberships: list[dict]) -> dict:
    """Return a login response that asks the frontend to pick an organization."""
    return {
        "ok": True,
        "organization_required": True,
        "user": user,
        "organizations": [
            {
                "org_name": membership["org_name"],
                "org_db": membership["org_db_name"],
                "role": membership["role"],
                "mfa_required": bool(membership.get("mfa_required")),
                "sso_required": bool(membership.get("sso_required")),
            }
            for membership in memberships
        ],
    }


def _mfa_setup_response(request: Request, user: dict, membership: dict) -> dict:
    """Start mandatory MFA setup before completing login."""
    secret = user.get("mfa_secret") or _generate_totp_secret()
    otpauth_url = _otpauth_uri(user["email"], secret)
    update_user_mfa_secret(user["id"], secret, enabled=False)
    request.session.clear()
    request.session["pending_mfa_setup"] = {
        "user_id": user["id"],
        "org_db": membership["org_db_name"],
        "organization": membership["org_name"],
        "role": membership["role"],
    }
    return {
        "ok": True,
        "mfa_setup_required": True,
        "secret": secret,
        "otpauth_url": otpauth_url,
        "qr_data_uri": _qr_data_uri(otpauth_url),
        "organization": membership["org_name"],
    }


def _start_user_login(request: Request, user: dict, membership: dict) -> dict:
    """Apply MFA policy and either complete login or return the next auth step."""
    if membership.get("sso_required") and membership.get("role") != "platform_admin":
        raise HTTPException(status_code=403, detail="SSO is required for this organization")
    full_user = get_user_by_id(user["id"], include_secrets=True) or user
    mfa_required = bool(get_platform_auth_settings().get("mfa_required") or membership.get("mfa_required"))
    if full_user.get("mfa_enabled"):
        request.session.clear()
        request.session["pending_mfa"] = {
            "user_id": full_user["id"],
            "org_db": membership["org_db_name"],
            "organization": membership["org_name"],
            "role": membership["role"],
        }
        return {"ok": True, "mfa_required": True, "organization": membership["org_name"]}
    if mfa_required:
        return _mfa_setup_response(request, full_user, membership)
    return _finish_user_login(request, user, membership, auth_method="password")


def _validate_scan_payload(body: ScanStartRequest):
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

    if not body.targets.strip():
        raise HTTPException(status_code=400, detail="Targets cannot be empty")

    if body.preferred_node_id:
        node = get_scanner_node_record(body.preferred_node_id)
        if not node or node.get("revoked_at"):
            raise HTTPException(status_code=400, detail="Selected scanner appliance is not available")


def _scan_signature(mode: int | None, scanner: str | None, targets: str) -> tuple[str, str]:
    scan_kind = str(mode if mode is not None else scanner or "").strip().lower()
    normalized_targets = ",".join(
        sorted(
            {
                item.strip().lower().rstrip("/")
                for item in str(targets or "").split(",")
                if item.strip()
            }
        )
    )
    return scan_kind, normalized_targets


def _active_scan_conflict(org_db: str, body: ScanStartRequest) -> dict | None:
    requested_kind, requested_targets = _scan_signature(body.mode, body.scanner, body.targets)
    requested_node = body.preferred_node_id or ""
    for scan in get_scan_history(org_db, limit=100):
        if scan.get("status") not in {"queued", "running", "stopping"}:
            continue
        active_kind, active_targets = _scan_signature(None, scan.get("scan_mode"), scan.get("targets") or "")
        queue_job = get_scanner_job_for_scan(org_db, int(scan.get("id") or 0))
        active_node = (queue_job or {}).get("preferred_node_id") or ""
        if active_kind == requested_kind and active_targets == requested_targets and active_node == requested_node:
            return scan
    return None


def _queue_scan(org_db: str, body: ScanStartRequest, schedule_id: int | None = None, allow_overlap: bool = False) -> int:
    """Create a scan record and enqueue it for scanner workers."""
    _validate_scan_payload(body)
    if not allow_overlap:
        conflicting_scan = _active_scan_conflict(org_db, body)
        if conflicting_scan:
            raise HTTPException(
                status_code=409,
                detail=(
                    "An identical scan is already queued or running "
                    f"(scan {conflicting_scan.get('id')}). Different scanners or targets can run in parallel."
                ),
            )

    targets = body.targets.strip()
    scan_name = body.scan_name or f"Scan {body.mode or body.scanner}"
    scan_id = create_scan_record(
        org_db,
        scan_name=scan_name,
        scan_mode=str(body.mode or body.scanner),
        targets=targets,
    )
    payload = body.dict()
    scanner = body.scanner if body.scanner else None
    enqueue_scanner_job(
        org_db,
        scan_id,
        scan_name=scan_name,
        scan_mode=str(body.mode or body.scanner),
        scanner=scanner,
        targets=targets,
        payload=payload,
        schedule_id=schedule_id,
        preferred_node_id=body.preferred_node_id,
    )
    if body.preferred_node_id:
        insert_scan_log(org_db, scan_id, f"Queued for selected scanner appliance {body.preferred_node_id}", "info")
    else:
        insert_scan_log(org_db, scan_id, "Queued for scanner workers", "info")

    if schedule_id:
        # Keep this small and local to avoid widening the helper API for one field.
        from .core.db_helper import DatabaseConnectionManager, _use_org_database
        with DatabaseConnectionManager() as connection:
            cursor = connection.cursor()
            _use_org_database(cursor, org_db)
            cursor.execute("UPDATE scans SET schedule_id = %s WHERE id = %s", (schedule_id, scan_id))
            connection.commit()
            cursor.close()

    return scan_id


def _severity_reaches_threshold(severity_breakdown: dict, min_severity: str) -> bool:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}
    threshold = order.get((min_severity or "high").lower(), 3)
    return any(count and order.get(sev, 0) >= threshold for sev, count in (severity_breakdown or {}).items())


def _send_email_notification(org_db: str, subject: str, body: str, settings: dict):
    """Send a plain-text email if SMTP is configured."""
    if not settings.get("enabled") or not settings.get("recipients"):
        return
    smtp_host = os.environ.get("SMTP_HOST")
    if not smtp_host:
        logger.info("SMTP_HOST not configured; skipping notification email")
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.environ.get("SMTP_FROM", "darkstar@localhost")
    message["To"] = settings["recipients"]
    message.set_content(body)

    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    use_tls = os.environ.get("SMTP_TLS", "true").lower() in {"1", "true", "yes"}

    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as smtp:
        if use_tls:
            smtp.starttls()
        if smtp_user and smtp_password:
            smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)


def _notify_scan_finished(org_db: str, scan_id: int, status: str):
    try:
        settings = get_notification_settings(org_db)
        if status == "completed" and not settings.get("notify_on_success"):
            return
        if status in {"failed", "stopped"} and not settings.get("notify_on_failure"):
            return
        stats = get_vulnerability_stats(org_db)
        if status == "completed" and not _severity_reaches_threshold(
            stats.get("severity_breakdown", {}),
            settings.get("min_severity") or "high",
        ):
            return
        subject = f"Darkstar scan {scan_id} {status}"
        body = (
            f"Scan {scan_id} for {org_db} finished with status {status}.\n\n"
            f"Total vulnerabilities: {stats.get('total_vulnerabilities', 0)}\n"
            f"Severity breakdown: {json.dumps(stats.get('severity_breakdown', {}), indent=2)}\n"
        )
        _send_email_notification(org_db, subject, body, settings)
    except Exception as exc:
        logger.warning(f"Failed to send scan notification for {scan_id}: {exc}")


def _resolve_m365_graph_credentials(org_db: str) -> dict:
    settings = get_m365_graph_settings(org_db, include_secret=True)
    tenant_id = settings.get("tenant_id") or os.environ.get("M365_TENANT_ID") or os.environ.get("MICROSOFT_GRAPH_TENANT_ID")
    client_id = settings.get("client_id") or os.environ.get("M365_CLIENT_ID") or os.environ.get("MICROSOFT_GRAPH_CLIENT_ID")
    client_secret = settings.get("client_secret") or os.environ.get("M365_CLIENT_SECRET") or os.environ.get("MICROSOFT_GRAPH_CLIENT_SECRET")
    missing = [name for name, value in {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
    }.items() if not value]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing Microsoft Graph settings: {', '.join(missing)}")
    return {"tenant_id": tenant_id, "client_id": client_id, "client_secret": client_secret}


def _graph_get_all(url: str, token: str) -> list[dict]:
    items: list[dict] = []
    next_url = url
    while next_url:
        response = requests.get(
            next_url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=40,
        )
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"Microsoft Graph error: {response.text[:500]}")
        payload = response.json()
        items.extend(payload.get("value") or [])
        next_url = payload.get("@odata.nextLink")
    return items


def _fetch_m365_secure_score(org_db: str) -> dict:
    credentials = _resolve_m365_graph_credentials(org_db)
    token_response = requests.post(
        f"https://login.microsoftonline.com/{credentials['tenant_id']}/oauth2/v2.0/token",
        data={
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=40,
    )
    if token_response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Microsoft token error: {token_response.text[:500]}")
    token = token_response.json().get("access_token")
    if not token:
        raise HTTPException(status_code=502, detail="Microsoft token response did not include an access token")

    secure_scores = _graph_get_all(
        "https://graph.microsoft.com/v1.0/security/secureScores?$top=1",
        token,
    )
    profiles = _graph_get_all(
        "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=999",
        token,
    )
    latest_score = secure_scores[0] if secure_scores else {}
    control_scores = {
        item.get("controlName"): item
        for item in latest_score.get("controlScores", [])
        if item.get("controlName")
    }
    merged_items = []
    for profile in profiles:
        control_name = profile.get("controlName") or profile.get("id")
        control_score = control_scores.get(control_name, {})
        merged = {**profile}
        merged["currentScore"] = control_score.get("score")
        merged["maxScore"] = profile.get("maxScore")
        merged["implementationStatus"] = control_score.get("implementationStatus") or profile.get("implementationStatus")
        merged["scoreImpact"] = control_score.get("scoreImpact")
        merged_items.append(merged)
    stored_count = upsert_m365_secure_score_data(org_db, latest_score, merged_items)
    return {"ok": True, "stored": stored_count, "summary": latest_score}


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
            start_new_session=True,
        )
        with scan_processes_lock:
            scan_processes[scan_id] = process

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
        scan_record = get_scan_record(org_db, scan_id) or {}
        if scan_record.get("status") in {"stopping", "stopped"}:
            update_scan_status(org_db, scan_id, "stopped", error_message="Scan stopped by user")
            if manager.has_connections(scan_id) and _event_loop:
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast(scan_id, {
                        "type": "stopped",
                        "message": "Scan stopped by user",
                        "timestamp": datetime.utcnow().isoformat(),
                    }),
                    _event_loop,
                )
            _notify_scan_finished(org_db, scan_id, "stopped")
            return

        if returncode != 0:
            error_msg = "\n".join(all_output[-20:]) if all_output else "Scan failed"
            logger.error(f"Scan {scan_id} failed: {error_msg}")
            update_scan_status(org_db, scan_id, "failed", error_message=error_msg[:4000])
            _notify_scan_finished(org_db, scan_id, "failed")
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

        recalculate_vulnerability_scores(org_db)
        update_scan_status(org_db, scan_id, "completed")
        logger.info(f"Scan {scan_id} completed successfully")
        _notify_scan_finished(org_db, scan_id, "completed")
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
        _notify_scan_finished(org_db, scan_id, "failed")
    except Exception as exc:
        logger.exception(f"Scan {scan_id} failed for {org_db}")
        update_scan_status(org_db, scan_id, "failed", error_message=str(exc)[:4000])
        _notify_scan_finished(org_db, scan_id, "failed")
    finally:
        with scan_processes_lock:
            scan_processes.pop(scan_id, None)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "logged_in": bool(request.session.get("org_db")),
            "organization": request.session.get("organization", ""),
            "role": request.session.get("role", ""),
        },
    )


@app.get("/documentation", response_class=HTMLResponse)
def documentation(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="documentation.html",
        context={},
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


@app.get("/logo_sidn.png")
def sidn_logo():
    logo_path = PROJECT_ROOT / "logo_sidn.png"
    if logo_path.exists():
        return FileResponse(logo_path)
    raise HTTPException(status_code=404, detail="Logo not found")


@app.get("/logo_nlnet.png")
def nlnet_logo():
    logo_path = PROJECT_ROOT / "logo_nlnet.png"
    if logo_path.exists():
        return FileResponse(logo_path)
    raise HTTPException(status_code=404, detail="Logo not found")


@app.get("/api/me")
def me(request: Request):
    org_db = request.session.get("org_db")
    if not org_db:
        token = _extract_bearer_token(request)
        api_context = authenticate_api_key(token) if token else None
        if api_context:
            return {
                "authenticated": True,
                "organization": api_context.get("org_name"),
                "org_db": api_context.get("org_db_name"),
                "role": api_context.get("role"),
                "user": None,
                "auth_method": "api_key",
            }
    user_id = _current_user_id(request)
    memberships = list_user_memberships(user_id) if user_id else []
    visible_orgs = memberships
    current_role = request.session.get("role") or (get_organization_role(org_db) if org_db else None)
    if org_db and current_role == "platform_admin":
        visible_orgs = [
            {
                "org_name": org["org_name"],
                "org_db_name": org["org_db_name"],
                "role": "platform_admin",
                "mfa_required": org.get("mfa_required"),
                "sso_required": org.get("sso_required"),
            }
            for org in list_organizations()
        ]
    platform_policy = get_platform_auth_settings() if org_db else {"mfa_required": False}
    org_settings = get_organization_auth_settings(org_db) if org_db else {}
    return {
        "authenticated": bool(org_db),
        "organization": request.session.get("organization"),
        "org_db": org_db,
        "role": current_role,
        "user": get_user_by_id(user_id) if user_id else None,
        "organizations": visible_orgs,
        "mfa_required": bool(platform_policy.get("mfa_required") or org_settings.get("mfa_required")),
        "sso_required": bool(org_settings.get("sso_required")),
        "auth_method": request.session.get("auth_method", "session") if org_db else None,
    }


@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request):
    if body.email:
        try:
            auth = authenticate_user(body.email, body.password)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

        user = auth["user"]
        memberships = auth["memberships"]
        if not memberships:
            raise HTTPException(status_code=403, detail="No organization memberships are assigned to this user")
        if len(memberships) > 1:
            request.session.clear()
            request.session["pending_user_id"] = user["id"]
            return _org_choices_response(user, memberships)
        return _start_user_login(request, user, memberships[0])

    # Legacy organization login stays available for existing local installs.
    if not body.organization:
        raise HTTPException(status_code=400, detail="Email is required")
    try:
        org_db, created_now = ensure_organization(body.organization, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    settings = get_organization_auth_settings(org_db, include_secrets=True)
    if settings.get("sso_required"):
        raise HTTPException(status_code=403, detail="SSO is required for this organization")
    if settings.get("mfa_enabled"):
        request.session.clear()
        request.session["pending_mfa"] = {
            "organization": body.organization,
            "org_db": org_db,
            "created": created_now,
        }
        return {"ok": True, "mfa_required": True, "organization": body.organization}

    mark_organization_login(org_db)
    request.session["organization"] = body.organization
    request.session["org_db"] = org_db
    request.session["role"] = get_organization_role(org_db)
    request.session["auth_method"] = "password"
    return {
        "ok": True,
        "organization": body.organization,
        "org_db": org_db,
        "role": request.session["role"],
        "created": created_now,
    }


@app.post("/api/auth/select-organization")
def select_organization(body: SelectOrganizationRequest, request: Request):
    user_id = request.session.get("pending_user_id") or request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="No authenticated user is pending organization selection")
    user = get_user_by_id(int(user_id))
    membership = get_user_membership(int(user_id), body.org_db)
    if not user or not membership:
        if request.session.get("role") != "platform_admin":
            raise HTTPException(status_code=403, detail="User is not a member of this organization")
        org = next((item for item in list_organizations() if item.get("org_db_name") == body.org_db), None)
        if not user or not org:
            raise HTTPException(status_code=403, detail="User is not a member of this organization")
        membership = {
            "org_name": org["org_name"],
            "org_db_name": org["org_db_name"],
            "role": "platform_admin",
            "mfa_required": org.get("mfa_required"),
        }
    return _start_user_login(request, user, membership)


@app.post("/api/auth/mfa/verify")
def verify_mfa(body: MfaVerifyRequest, request: Request):
    pending = request.session.get("pending_mfa")
    if not pending:
        raise HTTPException(status_code=400, detail="No MFA login is pending")

    if pending.get("user_id"):
        user = get_user_by_id(int(pending["user_id"]), include_secrets=True)
        if not user or not _verify_totp(user.get("mfa_secret"), body.code):
            raise HTTPException(status_code=401, detail="Invalid MFA code")
        membership = get_user_membership(int(pending["user_id"]), pending["org_db"])
        if not membership:
            raise HTTPException(status_code=403, detail="User is not a member of this organization")
        return _finish_user_login(request, user, membership, auth_method="password_mfa")

    settings = get_organization_auth_settings(pending["org_db"], include_secrets=True)
    if not _verify_totp(settings.get("mfa_secret"), body.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    request.session.clear()
    request.session["organization"] = pending["organization"]
    request.session["org_db"] = pending["org_db"]
    request.session["role"] = get_organization_role(pending["org_db"])
    request.session["auth_method"] = "password_mfa"
    mark_organization_login(pending["org_db"])
    return {
        "ok": True,
        "organization": pending["organization"],
        "org_db": pending["org_db"],
        "role": request.session["role"],
        "created": pending.get("created", False),
    }


@app.post("/api/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/api/auth/mfa/settings")
def mfa_settings(request: Request):
    org_db = _get_org_db(request)
    user_id = _current_user_id(request)
    if user_id:
        user = get_user_by_id(user_id) or {}
        org_settings = get_organization_auth_settings(org_db)
        platform_settings = get_platform_auth_settings()
        return {
            "enabled": bool(user.get("mfa_enabled")),
            "user_enabled": bool(user.get("mfa_enabled")),
            "org_required": bool(org_settings.get("mfa_required")),
            "org_sso_required": bool(org_settings.get("sso_required")),
            "platform_required": bool(platform_settings.get("mfa_required")),
            "required": bool(org_settings.get("mfa_required") or platform_settings.get("mfa_required")),
        }
    settings = get_organization_auth_settings(org_db)
    return {
        "enabled": bool(settings.get("mfa_enabled")),
        "org_required": bool(settings.get("mfa_required")),
        "org_sso_required": bool(settings.get("sso_required")),
    }


@app.post("/api/auth/mfa/setup")
def setup_mfa(request: Request):
    org_db = _get_org_db(request)
    user_id = _current_user_id(request)
    if user_id:
        user = get_user_by_id(user_id) or {}
        secret = _generate_totp_secret()
        otpauth_url = _otpauth_uri(user.get("email") or "Darkstar", secret)
        update_user_mfa_secret(user_id, secret, enabled=False)
        return {"secret": secret, "otpauth_url": otpauth_url, "qr_data_uri": _qr_data_uri(otpauth_url)}
    organization = request.session.get("organization") or getattr(request.state, "api_organization", org_db)
    secret = _generate_totp_secret()
    otpauth_url = _otpauth_uri(organization, secret)
    update_mfa_secret(org_db, secret, enabled=False)
    return {"secret": secret, "otpauth_url": otpauth_url, "qr_data_uri": _qr_data_uri(otpauth_url)}


@app.post("/api/auth/mfa/enable")
def enable_mfa(body: MfaVerifyRequest, request: Request):
    pending_setup = request.session.get("pending_mfa_setup")
    if pending_setup:
        user = get_user_by_id(int(pending_setup["user_id"]), include_secrets=True)
        if not user or not _verify_totp(user.get("mfa_secret"), body.code):
            raise HTTPException(status_code=401, detail="Invalid MFA code")
        update_user_mfa_secret(user["id"], user.get("mfa_secret"), enabled=True)
        membership = get_user_membership(user["id"], pending_setup["org_db"])
        if not membership:
            raise HTTPException(status_code=403, detail="User is not a member of this organization")
        return _finish_user_login(request, user, membership, auth_method="password_mfa")

    org_db = _get_org_db(request)
    user_id = _current_user_id(request)
    if user_id:
        user = get_user_by_id(user_id, include_secrets=True)
        if not user or not _verify_totp(user.get("mfa_secret"), body.code):
            raise HTTPException(status_code=401, detail="Invalid MFA code")
        return update_user_mfa_secret(user_id, user.get("mfa_secret"), enabled=True)
    settings = get_organization_auth_settings(org_db, include_secrets=True)
    if not _verify_totp(settings.get("mfa_secret"), body.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    return update_mfa_secret(org_db, settings.get("mfa_secret"), enabled=True)


@app.post("/api/auth/mfa/disable")
def disable_mfa(request: Request):
    org_db = _get_org_db(request)
    user_id = _current_user_id(request)
    if user_id:
        org_settings = get_organization_auth_settings(org_db)
        platform_settings = get_platform_auth_settings()
        if org_settings.get("mfa_required") or platform_settings.get("mfa_required"):
            raise HTTPException(status_code=400, detail="MFA cannot be disabled while it is required by policy")
        return update_user_mfa_secret(user_id, None, enabled=False)
    return update_mfa_secret(org_db, None, enabled=False)


@app.patch("/api/auth/organization-policy")
def save_organization_auth_policy(request: Request, body: AuthPolicyRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    if body.mfa_required:
        _require_current_user_mfa_enabled(request)
    if body.sso_required:
        _require_sso_configured_for_enforcement(org_db)
    return update_organization_auth_requirements(org_db, body.mfa_required, body.sso_required)


@app.get("/api/auth/sso/settings")
def sso_settings(request: Request):
    org_db = _get_org_db(request)
    settings = get_organization_auth_settings(org_db)
    return {
        "enabled": bool(settings.get("sso_enabled")),
        "required": bool(settings.get("sso_required")),
        "issuer": settings.get("sso_issuer"),
        "client_id": settings.get("sso_client_id"),
        "client_secret_configured": bool(settings.get("sso_client_secret_configured")),
        "allowed_domain": settings.get("sso_allowed_domain"),
    }


@app.patch("/api/auth/sso/settings")
def save_sso_settings(request: Request, body: SsoSettingsRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    current = get_organization_auth_settings(org_db)
    if not body.enabled and current.get("sso_required"):
        raise HTTPException(status_code=400, detail="Disable SSO enforcement before disabling SSO")
    if body.enabled and not (body.issuer and body.client_id):
        raise HTTPException(status_code=400, detail="Issuer and client ID are required when SSO is enabled")
    return update_sso_settings(
        org_db,
        enabled=body.enabled,
        issuer=body.issuer,
        client_id=body.client_id,
        client_secret=body.client_secret,
        allowed_domain=body.allowed_domain,
    )


def _oidc_discovery(issuer: str) -> dict:
    response = requests.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration", timeout=15)
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {response.text[:300]}")
    return response.json()


def _decode_jwt_payload(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        padded = payload + "=" * ((4 - len(payload) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return {}


@app.get("/api/auth/sso/start")
def start_sso(request: Request, organization: str):
    settings = get_sso_settings_by_org_name(organization, include_secret=True)
    if not settings or not settings.get("sso_enabled"):
        raise HTTPException(status_code=404, detail="SSO is not configured for this organization")
    if not settings.get("sso_issuer") or not settings.get("sso_client_id"):
        raise HTTPException(status_code=400, detail="SSO issuer and client ID are required")

    discovery = _oidc_discovery(settings["sso_issuer"])
    state = secrets.token_urlsafe(24)
    request.session["sso_state"] = state
    request.session["sso_org"] = organization
    redirect_uri = os.environ.get("SSO_REDIRECT_URI") or str(request.url_for("sso_callback"))
    query = urlencode({
        "response_type": "code",
        "client_id": settings["sso_client_id"],
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
    })
    return RedirectResponse(f"{discovery['authorization_endpoint']}?{query}")


@app.get("/api/auth/sso/callback", name="sso_callback")
def sso_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    if error:
        raise HTTPException(status_code=401, detail=f"SSO failed: {error}")
    if not code or state != request.session.get("sso_state"):
        raise HTTPException(status_code=401, detail="Invalid SSO callback state")

    organization = request.session.get("sso_org")
    settings = get_sso_settings_by_org_name(organization, include_secret=True) if organization else None
    if not settings or not settings.get("sso_enabled"):
        raise HTTPException(status_code=404, detail="SSO session organization not found")

    discovery = _oidc_discovery(settings["sso_issuer"])
    redirect_uri = os.environ.get("SSO_REDIRECT_URI") or str(request.url_for("sso_callback"))
    token_response = requests.post(
        discovery["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": settings["sso_client_id"],
            "client_secret": settings.get("sso_client_secret") or "",
        },
        timeout=20,
    )
    if token_response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"OIDC token exchange failed: {token_response.text[:300]}")
    token_payload = token_response.json()
    claims = _decode_jwt_payload(token_payload.get("id_token", ""))
    if token_payload.get("access_token") and discovery.get("userinfo_endpoint"):
        userinfo_response = requests.get(
            discovery["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {token_payload['access_token']}"},
            timeout=15,
        )
        if userinfo_response.status_code < 400:
            claims.update(userinfo_response.json())

    email = claims.get("email") or claims.get("preferred_username") or claims.get("upn") or ""
    allowed_domain = (settings.get("sso_allowed_domain") or "").lstrip("@").lower()
    if allowed_domain and not email.lower().endswith(f"@{allowed_domain}"):
        raise HTTPException(status_code=403, detail="SSO user is outside the allowed domain")

    request.session.clear()
    request.session["organization"] = settings["org_name"]
    request.session["org_db"] = settings["org_db_name"]
    request.session["role"] = settings.get("role") or get_organization_role(settings["org_db_name"])
    request.session["auth_method"] = "sso"
    request.session["sso_subject"] = claims.get("sub")
    request.session["sso_email"] = email
    mark_organization_login(settings["org_db_name"])
    return RedirectResponse("/")


@app.get("/api/api-keys")
def api_keys(request: Request):
    org_db = _get_org_db(request)
    return {"items": list_api_keys(org_db)}


@app.post("/api/api-keys")
def create_rest_api_key(request: Request, body: ApiKeyRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    role = body.role if body.role in ROLE_RANK else "security_analyst"
    if _role_rank(role) > _role_rank(_get_role(request)):
        raise HTTPException(status_code=403, detail="Cannot create an API key with a higher role than your own")
    return create_api_key(org_db, body.name, role=role)


@app.delete("/api/api-keys/{key_id}")
def delete_rest_api_key(request: Request, key_id: int):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    if not revoke_api_key(org_db, key_id):
        raise HTTPException(status_code=404, detail="API key not found")
    return {"ok": True}


@app.get("/api/endpoints/overview")
def endpoint_overview(request: Request):
    org_db = _get_org_db(request)
    return get_endpoint_overview(org_db)


@app.get("/api/endpoints/enrollment-tokens")
def endpoint_enrollment_tokens(request: Request):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    return {"items": list_endpoint_enrollment_tokens(org_db)}


@app.post("/api/endpoints/enrollment-tokens")
def create_endpoint_enrollment(request: Request, body: EndpointEnrollmentRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    token = create_endpoint_enrollment_token(org_db, body.name, body.expires_days)
    token["install_command"] = _endpoint_install_command(org_db, token["token"], request)
    return token


@app.delete("/api/endpoints/enrollment-tokens/{token_id}")
def revoke_endpoint_enrollment(request: Request, token_id: int):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    if not revoke_endpoint_enrollment_token(org_db, token_id):
        raise HTTPException(status_code=404, detail="Endpoint enrollment token not found")
    return {"ok": True}


@app.get("/api/endpoints/agents")
def endpoint_agents(
    request: Request,
    search: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    org_db = _get_org_db(request)
    _require_min_role(request, "viewer")
    return list_endpoint_agents(org_db, search=search, status=status, limit=limit, offset=offset)


@app.get("/api/endpoints/agents/{agent_id}")
def endpoint_agent_detail(request: Request, agent_id: str):
    org_db = _get_org_db(request)
    row = get_endpoint_agent(org_db, agent_id)
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint agent not found")
    return row


@app.post("/api/endpoints/agents/{agent_id}/revoke")
def revoke_endpoint_agent_api(request: Request, agent_id: str):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    if not revoke_endpoint_agent(org_db, agent_id):
        raise HTTPException(status_code=404, detail="Endpoint agent not found or already revoked")
    return {"ok": True}


@app.delete("/api/endpoints/agents/{agent_id}")
def delete_endpoint_agent_api(request: Request, agent_id: str):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    if not delete_endpoint_agent(org_db, agent_id):
        raise HTTPException(status_code=404, detail="Endpoint agent not found")
    return {"ok": True}


@app.get("/api/endpoints/software")
def endpoint_software(
    request: Request,
    agent_id: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    org_db = _get_org_db(request)
    return list_endpoint_software(org_db, agent_id=agent_id, search=search, limit=limit, offset=offset)


@app.get("/api/endpoints/vulnerabilities")
def endpoint_vulnerabilities(
    request: Request,
    agent_id: str | None = None,
    search: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    org_db = _get_org_db(request)
    return list_endpoint_vulnerabilities(
        org_db,
        agent_id=agent_id,
        search=search,
        severity=severity,
        limit=limit,
        offset=offset,
    )


@app.post("/api/endpoints/vulnerabilities/recalculate")
def recalculate_endpoint_vulnerabilities_api(request: Request):
    org_db = _get_org_db(request)
    _require_min_role(request, "security_analyst")
    agents_processed = 0
    software_total = 0
    vulnerability_total = 0
    cache_hits = 0
    cache_misses = 0
    vendor_findings = 0
    agent_offset = 0
    while True:
        agents_result = list_endpoint_agents(org_db, limit=500, offset=agent_offset)
        agents = agents_result.get("items") or []
        if not agents:
            break
        for agent in agents:
            agent_id = agent.get("agent_id")
            if not agent_id:
                continue
            software = []
            offset = 0
            while True:
                page = list_endpoint_software(org_db, agent_id=agent_id, limit=500, offset=offset)
                items = page.get("items") or []
                software.extend(items)
                offset += page.get("limit") or 500
                if offset >= int(page.get("total") or 0) or not items:
                    break
            agent_detail = get_endpoint_agent(org_db, agent_id) or agent
            findings, matcher_stats = _match_endpoint_vulnerabilities(
                org_db,
                software,
                os_info=_endpoint_os_info_from_agent(agent_detail),
            )
            vulnerability_total += replace_endpoint_vulnerabilities(org_db, agent_id, findings)
            software_total += len(software)
            cache_hits += int(matcher_stats.get("cache_hits") or 0)
            cache_misses += int(matcher_stats.get("cache_misses") or 0)
            vendor_findings += int(matcher_stats.get("vendor_findings") or 0)
            agents_processed += 1
        agent_offset += agents_result.get("limit") or 500
        if agent_offset >= int(agents_result.get("total") or 0):
            break
    return {
        "ok": True,
        "agents": agents_processed,
        "software": software_total,
        "vulnerabilities": vulnerability_total,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "vendor_findings": vendor_findings,
        "matcher": "osv_purl_exact_version_cached+vendor",
    }


@app.get("/api/endpoints/vulnerabilities/{finding_id}")
def endpoint_vulnerability_detail(request: Request, finding_id: int):
    org_db = _get_org_db(request)
    row = get_endpoint_vulnerability(org_db, finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint vulnerability not found")
    return row


@app.post("/api/endpoint-agents/register")
def register_endpoint_agent_api(body: EndpointRegisterRequest):
    try:
        result = register_endpoint_agent(
            body.organization,
            body.enrollment_token,
            body.hostname,
            body.os,
            body.agent_version,
            body.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    return {"ok": True, **result}


@app.post("/api/endpoint-agents/inventory")
def endpoint_agent_inventory(request: Request, body: EndpointInventoryRequest):
    agent = _get_endpoint_agent_context(request)
    result = upsert_endpoint_inventory(
        agent["org_db"],
        agent["agent_id"],
        body.os,
        body.software,
        ip_addresses=body.ip_addresses,
        mac_addresses=body.mac_addresses,
        metadata=body.metadata,
    )
    findings, matcher_stats = _match_endpoint_vulnerabilities(
        agent["org_db"],
        result.get("software") or [],
        os_info=body.os,
    )
    finding_count = replace_endpoint_vulnerabilities(agent["org_db"], agent["agent_id"], findings)
    return {
        "ok": True,
        "agent_id": agent["agent_id"],
        "software_count": result.get("software_count") or 0,
        "vulnerability_count": finding_count,
        "matcher": matcher_stats["matcher"],
        "matcher_stats": matcher_stats,
    }


@app.get("/api/scanner-nodes")
def scanner_nodes(request: Request):
    _require_min_role(request, "platform_admin")
    return {"items": list_scanner_nodes()}


@app.get("/api/scanner-nodes/available")
def available_scanner_nodes(request: Request):
    _require_min_role(request, "security_analyst")
    items = []
    for node in list_available_scanner_nodes():
        items.append(
            {
                "node_id": node.get("node_id"),
                "name": node.get("name"),
                "status": node.get("status"),
                "last_seen_at": node.get("last_seen_at"),
                "running_jobs": node.get("running_jobs") or 0,
                "max_parallel_jobs": node.get("max_parallel_jobs") or 1,
            }
        )
    return {"items": items}


@app.post("/api/scanner-nodes")
def create_scanner_node_api(request: Request, body: ScannerNodeRequest):
    _require_min_role(request, "platform_admin")
    node = create_scanner_node(
        body.name,
        capabilities=["*"],
        max_parallel_jobs=body.max_parallel_jobs,
    )
    node["attach_command"] = _scanner_attach_command(node, request)
    return node


@app.delete("/api/scanner-nodes/{node_id}")
def delete_scanner_node_api(request: Request, node_id: str):
    _require_min_role(request, "platform_admin")
    if not revoke_scanner_node(node_id):
        raise HTTPException(status_code=404, detail="Scanner node not found")
    return {"ok": True}


@app.delete("/api/scanner-nodes/{node_id}/record")
def delete_revoked_scanner_node_api(request: Request, node_id: str):
    _require_min_role(request, "platform_admin")
    if not delete_revoked_scanner_node(node_id):
        raise HTTPException(status_code=400, detail="Only revoked scanner nodes without active jobs can be deleted")
    return {"ok": True}


@app.post("/api/scanner-workers/heartbeat")
def scanner_worker_heartbeat(request: Request, body: ScannerHeartbeatRequest):
    node = _get_scanner_node(request)
    heartbeat_scanner_node(
        node["node_id"],
        capabilities=body.capabilities,
        status=body.status or "online",
    )
    return {"ok": True, "node_id": node["node_id"], "max_parallel_jobs": node.get("max_parallel_jobs") or 1}


@app.post("/api/scanner-workers/jobs/claim")
def scanner_worker_claim(request: Request, body: ScannerClaimRequest):
    node = _get_scanner_node(request)
    capabilities = body.capabilities or node.get("capabilities") or ["*"]
    job = claim_next_scanner_job(
        node["node_id"],
        capabilities=capabilities,
        lease_seconds=body.lease_seconds,
    )
    return {"job": job}


@app.post("/api/scanner-workers/jobs/{job_id}/logs")
def scanner_worker_logs(request: Request, job_id: int, body: ScannerLogRequest):
    node = _get_scanner_node(request)
    job = extend_scanner_job_lease(job_id, node["node_id"], lease_seconds=body.lease_seconds)
    if not job:
        raise HTTPException(status_code=404, detail="Scanner job not found or not owned by this node")
    messages = [str(message) for message in (body.messages or []) if str(message).strip()]
    if messages:
        insert_scan_logs_batch(job["org_db_name"], job["scan_id"], messages, body.level or "info")
        if manager.has_connections(job["scan_id"]) and _event_loop:
            for message in messages:
                try:
                    asyncio.run_coroutine_threadsafe(
                        manager.broadcast(job["scan_id"], {
                            "type": "log",
                            "level": body.level or "info",
                            "message": message,
                            "timestamp": datetime.utcnow().isoformat(),
                        }),
                        _event_loop,
                    )
                except Exception as exc:
                    logger.warning("WebSocket broadcast error for worker log: %s", exc)
    return {"ok": True, "stop_requested": job.get("status") == "stopping"}


@app.post("/api/scanner-workers/jobs/{job_id}/complete")
def scanner_worker_complete(request: Request, job_id: int, body: ScannerCompleteRequest):
    node = _get_scanner_node(request)
    job = complete_scanner_job(job_id, node["node_id"], body.status, body.error_message)
    if not job:
        raise HTTPException(status_code=404, detail="Scanner job not found or not owned by this node")
    if body.status == "completed":
        recalculate_vulnerability_scores(job["org_db_name"])
    _notify_scan_finished(job["org_db_name"], job["scan_id"], body.status)
    if manager.has_connections(job["scan_id"]) and _event_loop:
        asyncio.run_coroutine_threadsafe(
            manager.broadcast(job["scan_id"], {
                "type": body.status,
                "message": body.error_message or f"Scan {body.status}",
                "timestamp": datetime.utcnow().isoformat(),
            }),
            _event_loop,
        )
    return {"ok": True}


@app.get("/api/rest/status")
def rest_api_status(request: Request):
    org_db = _get_org_db(request)
    return {
        "ok": True,
        "org_db": org_db,
        "auth": "session_or_bearer_api_key",
        "docs": "/docs",
        "openapi": "/openapi.json",
    }


@app.get("/api/vulnerabilities")
def vulnerabilities(request: Request, limit: int = 200):
    org_db = _get_org_db(request)
    return {"items": get_latest_vulnerabilities(org_db, limit=limit)}


@app.get("/api/assets")
def assets(request: Request, limit: int = 100):
    org_db = _get_org_db(request)
    return get_attack_surface_overview(org_db, limit=limit)


@app.get("/api/attack-surface")
def attack_surface(request: Request, search: str | None = None, limit: int = 100, offset: int = 0):
    org_db = _get_org_db(request)
    return get_attack_surface_overview(org_db, search=search, limit=limit, offset=offset)


@app.get("/api/recon/subdomains")
def recon_subdomains(
    request: Request,
    search: str | None = None,
    parent_domain: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    org_db = _get_org_db(request)
    return get_bbot_potential_targets(
        org_db,
        search=search,
        parent_domain=parent_domain,
        limit=limit,
        offset=offset,
    )


@app.get("/api/scans")
def scans(request: Request, limit: int = 50):
    org_db = _get_org_db(request)
    return {"items": get_scan_history(org_db, limit=limit)}


@app.get("/api/scans/{scan_id}")
def scan_detail(request: Request, scan_id: int):
    """Return scan metadata and recent execution logs for drill-down views."""
    org_db = _get_org_db(request)
    scan = get_scan_record(org_db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan": scan,
        "queue_job": get_scanner_job_for_scan(org_db, scan_id),
        "logs": get_scan_logs(org_db, scan_id, limit=250),
    }


@app.get("/api/stats")
def stats(request: Request):
    org_db = _get_org_db(request)
    return get_vulnerability_stats(org_db)


@app.post("/api/scans/start")
def start_scan(request: Request, body: ScanStartRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "security_analyst")
    scan_id = _queue_scan(org_db, body)
    return {"ok": True, "scan_id": scan_id, "status": "queued"}


@app.post("/api/scans/{scan_id}/stop")
def stop_scan(request: Request, scan_id: int):
    """Request termination of a running scan process."""
    org_db = _get_org_db(request)
    _require_min_role(request, "security_analyst")
    scan = get_scan_record(org_db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") not in {"queued", "running", "stopping"}:
        return {"ok": True, "scan_id": scan_id, "status": scan.get("status")}

    update_scan_status(org_db, scan_id, "stopping", error_message="Stop requested by user")
    insert_scan_log(org_db, scan_id, "Stop requested by user", "warning")
    request_scanner_job_stop(org_db, scan_id)
    queue_job = get_scanner_job_for_scan(org_db, scan_id)
    with scan_processes_lock:
        process = scan_processes.get(scan_id)
    if process and process.poll() is None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception as exc:
            logger.warning("Failed to stop scan process group for scan %s: %s", scan_id, exc)
            process.terminate()
    elif not queue_job or not queue_job.get("locked_by_node_id"):
        cancel_queued_scanner_job(org_db, scan_id)
    return {"ok": True, "scan_id": scan_id, "status": "stopping"}


@app.get("/api/vulnerabilities/filtered")
def get_filtered_vulnerabilities(
    request: Request,
    severity: str | None = None,
    host: str | None = None,
    tool: str | None = None,
    limit: int = 50,
    offset: int = 0,
    dedupe: bool = False,
):
    """Get vulnerabilities with filtering and pagination."""
    org_db = _get_org_db(request)
    items, total = get_vulnerabilities_filtered(org_db, severity, host, tool, limit, offset, dedupe=dedupe)
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


@app.get("/api/vulnerabilities/grouped")
def grouped_vulnerabilities(request: Request, group_by: str = "asset"):
    """Get server-side grouped vulnerabilities by asset or vulnerability."""
    org_db = _get_org_db(request)
    return {"items": get_grouped_vulnerabilities(org_db, group_by=group_by)}


@app.get("/api/vulnerabilities/{vulnerability_id}")
def vulnerability_detail(request: Request, vulnerability_id: int):
    """Get a detailed vulnerability record including PoC/reference data."""
    org_db = _get_org_db(request)
    row = get_vulnerability_detail(org_db, vulnerability_id)
    if not row:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return row


@app.post("/api/scoring/recalculate")
def recalculate_scores(request: Request):
    """Recalculate stored priority scores for the current organization."""
    org_db = _get_org_db(request)
    _require_min_role(request, "security_analyst")
    count = recalculate_vulnerability_scores(org_db)
    return {"ok": True, "updated": count}


@app.get("/api/scoring/overview")
def scoring_overview(
    request: Request,
    asset_search: str | None = None,
    asset_limit: int = 25,
    asset_offset: int = 0,
    vuln_severity: str | None = None,
    vuln_host: str | None = None,
    vuln_limit: int = 25,
    vuln_offset: int = 0,
):
    """Get priority, asset and exploitability scoring summaries."""
    org_db = _get_org_db(request)
    return get_scoring_overview(
        org_db,
        asset_search=asset_search,
        asset_limit=asset_limit,
        asset_offset=asset_offset,
        vuln_severity=vuln_severity,
        vuln_host=vuln_host,
        vuln_limit=vuln_limit,
        vuln_offset=vuln_offset,
    )


@app.get("/api/schedules")
def schedules(request: Request):
    org_db = _get_org_db(request)
    return {"items": get_scan_schedules(org_db)}


@app.post("/api/schedules")
def create_schedule(request: Request, body: ScheduleRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "security_analyst")
    _validate_scan_payload(body)
    try:
        schedule_id = create_scan_schedule(
            org_db,
            scan_name=body.scan_name or f"Scheduled {body.mode or body.scanner}",
            targets=body.targets.strip(),
            scan_mode=str(body.mode) if body.mode is not None else None,
            scanner=body.scanner,
            interval_minutes=body.interval_minutes,
            bruteforce=body.bruteforce,
            bruteforce_timeout=body.bruteforce_timeout,
            start_at=body.start_at,
            end_at=body.end_at,
            preferred_node_id=body.preferred_node_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "schedule_id": schedule_id}


@app.patch("/api/schedules/{schedule_id}")
def update_schedule_enabled(request: Request, schedule_id: int, body: ScheduleEnabledRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "security_analyst")
    if not set_scan_schedule_enabled(org_db, schedule_id, body.enabled):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"ok": True, "schedule_id": schedule_id, "enabled": body.enabled}


@app.delete("/api/schedules/{schedule_id}")
def remove_schedule(request: Request, schedule_id: int):
    org_db = _get_org_db(request)
    _require_min_role(request, "security_analyst")
    if not delete_scan_schedule(org_db, schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"ok": True}


@app.post("/api/schedules/{schedule_id}/run")
def run_schedule_now(request: Request, schedule_id: int):
    org_db = _get_org_db(request)
    _require_min_role(request, "security_analyst")
    schedule = get_scan_schedule(org_db, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    payload = ScanStartRequest(
        targets=schedule["targets"],
        mode=int(schedule["scan_mode"]) if schedule.get("scan_mode") and str(schedule["scan_mode"]).isdigit() else None,
        scanner=schedule.get("scanner"),
        scan_name=schedule.get("scan_name"),
        bruteforce=bool(schedule.get("bruteforce")),
        bruteforce_timeout=int(schedule.get("bruteforce_timeout") or 300),
        preferred_node_id=schedule.get("preferred_node_id"),
    )
    scan_id = _queue_scan(org_db, payload, schedule_id=schedule_id)
    mark_schedule_run(org_db, schedule_id)
    return {"ok": True, "scan_id": scan_id}


@app.get("/api/notifications/settings")
def notifications_settings(request: Request):
    org_db = _get_org_db(request)
    return get_notification_settings(org_db)


@app.patch("/api/notifications/settings")
def update_notifications_settings(request: Request, body: NotificationSettingsRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    return update_notification_settings(
        org_db,
        enabled=body.enabled,
        recipients=body.recipients,
        min_severity=body.min_severity,
        notify_on_success=body.notify_on_success,
        notify_on_failure=body.notify_on_failure,
    )


@app.post("/api/notifications/test")
def test_notification(request: Request):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    settings = get_notification_settings(org_db)
    _send_email_notification(
        org_db,
        "Darkstar test notification",
        f"This is a Darkstar test notification for {org_db}.",
        settings,
    )
    return {"ok": True}


@app.get("/api/users")
def org_users(request: Request):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    return {"items": list_users_for_org(org_db)}


@app.post("/api/users")
def org_create_or_update_user(request: Request, body: OrgUserRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    role = body.role if body.role in {"viewer", "security_analyst", "tenant_admin"} else "viewer"
    _validate_user_password(body.password)
    try:
        user = create_or_update_user(
            email=body.email,
            password=body.password,
            display_name=body.display_name,
            org_db_name=org_db,
            role=role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "user": user}


@app.delete("/api/users/{user_id}")
def org_remove_user(request: Request, user_id: int):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    if _current_user_id(request) == user_id:
        raise HTTPException(status_code=400, detail="You cannot remove your own active organization membership")
    if not remove_user_membership(user_id, org_db):
        raise HTTPException(status_code=404, detail="User membership not found")
    return {"ok": True}


@app.get("/api/integrations/m365/settings")
def m365_settings(request: Request):
    org_db = _get_org_db(request)
    return get_m365_graph_settings(org_db)


@app.patch("/api/integrations/m365/settings")
def update_m365_settings(request: Request, body: M365GraphSettingsRequest):
    org_db = _get_org_db(request)
    _require_min_role(request, "tenant_admin")
    return update_m365_graph_settings(
        org_db,
        tenant_id=body.tenant_id,
        client_id=body.client_id,
        client_secret=body.client_secret,
        enabled=body.enabled,
    )


@app.get("/api/integrations/m365/secure-score")
def m365_secure_score(request: Request):
    org_db = _get_org_db(request)
    return get_m365_secure_score(org_db)


@app.post("/api/integrations/m365/secure-score/sync")
def sync_m365_secure_score(request: Request):
    org_db = _get_org_db(request)
    _require_min_role(request, "security_analyst")
    return _fetch_m365_secure_score(org_db)


@app.get("/api/exports/vulnerabilities.csv")
def export_vulnerabilities_csv(
    request: Request,
    severity: str | None = None,
    host: str | None = None,
    tool: str | None = None,
):
    org_db = _get_org_db(request)
    rows = get_vulnerability_export_rows(org_db, severity=severity, host=host, tool=tool)
    output = io.StringIO()
    fieldnames = [
        "id", "severity", "priority_score", "cve", "title", "host", "tool",
        "cvss", "epss", "kev", "has_poc", "has_public_exploit", "solution",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key) for key in fieldnames})
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=darkstar-vulnerabilities.csv"},
    )


def _xlsx_col(index: int) -> str:
    letters = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _xlsx_cell(row: int, col: int, value, style: int = 0) -> str:
    ref = f"{_xlsx_col(col)}{row}"
    style_attr = f' s="{style}"' if style else ""
    text = html_escape("" if value is None else str(value))
    return f'<c r="{ref}" t="inlineStr"{style_attr}><is><t>{text}</t></is></c>'


def _xlsx_workbook(headers: list[str], rows: list[list], widths: list[int], sheet_name: str, severity_col: int | None = None) -> bytes:
    severity_styles = {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
        "baseline": 6,
        "info": 6,
    }
    sheet_rows = [
        f'<row r="1">{"".join(_xlsx_cell(1, idx, header, 1) for idx, header in enumerate(headers, start=1))}</row>'
    ]
    for row_index, values in enumerate(rows, start=2):
        cells = []
        severity_style = 0
        if severity_col is not None and len(values) >= severity_col:
            severity_style = severity_styles.get(str(values[severity_col - 1] or "").lower(), 0)
        for col_index, value in enumerate(values, start=1):
            cells.append(_xlsx_cell(row_index, col_index, value, severity_style if col_index == severity_col else 0))
        sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    widths_xml = "".join(
        f'<col min="{idx}" max="{idx}" width="{width}" customWidth="1"/>'
        for idx, width in enumerate(widths, start=1)
    )
    max_col = _xlsx_col(len(headers))
    sheet_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <cols>{widths_xml}</cols>
  <sheetData>{"".join(sheet_rows)}</sheetData>
  <autoFilter ref="A1:{max_col}{max(1, len(rows) + 1)}"/>
</worksheet>'''
    styles_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2"><font><sz val="11"/><color rgb="FF111827"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>
  <fills count="7"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF10231F"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFF05154"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFF7678"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFF49E31"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF5FD0A5"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF83D8FF"/><bgColor indexed="64"/></patternFill></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="7"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="1" borderId="0" xfId="0" applyFill="1" applyFont="1"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFill="1" applyFont="1"/><xf numFmtId="0" fontId="1" fillId="3" borderId="0" xfId="0" applyFill="1" applyFont="1"/><xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="6" borderId="0" xfId="0" applyFill="1"/></cellXfs>
</styleSheet>'''
    safe_sheet = html_escape(sheet_name[:31] or "Report")
    workbook_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="{safe_sheet}" sheetId="1" r:id="rId1"/></sheets></workbook>'''
    workbook_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'''
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'''
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/styles.xml", styles_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return output.getvalue()


def _attack_surface_export_rows(org_db: str, search: str | None = None) -> list[dict]:
    rows: list[dict] = []
    offset = 0
    while True:
        result = get_attack_surface_overview(org_db, search=search, limit=500, offset=offset)
        items = result.get("items") or []
        rows.extend(items)
        offset += len(items)
        if not items or offset >= int(result.get("total") or 0):
            break
    return rows


def _asm_row_values(asset: dict) -> dict:
    ports = ", ".join(f"{port.get('port')}/{port.get('service') or 'unknown'}" for port in asset.get("ports") or [])
    return {
        "asset": asset.get("host") or "",
        "ips": ", ".join(asset.get("ips") or []),
        "urls": ", ".join(asset.get("urls") or []),
        "ports": ports or "No open ports recorded",
        "issues": asset.get("vulnerability_count") or 0,
        "max_severity": asset.get("max_severity") or "unknown",
        "max_priority": asset.get("max_priority") or 0,
        "exploitable": asset.get("exploitable_count") or 0,
        "sources": ", ".join(asset.get("sources") or []),
        "tags": ", ".join(asset.get("tags") or []),
        "last_seen": asset.get("last_seen") or "",
    }


@app.get("/api/exports/vulnerabilities.xlsx")
def export_vulnerabilities_xlsx(
    request: Request,
    severity: str | None = None,
    host: str | None = None,
    tool: str | None = None,
):
    """Export vulnerabilities as a styled XLSX workbook without extra runtime deps."""
    org_db = _get_org_db(request)
    rows = get_vulnerability_export_rows(org_db, severity=severity, host=host, tool=tool)
    headers = [
        "ID", "Severity", "Priority", "Title", "Host", "Tool", "CVE",
        "Exploit", "Summary", "Solution",
    ]
    severity_styles = {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
        "baseline": 6,
        "info": 6,
    }
    sheet_rows = []
    sheet_rows.append(
        f'<row r="1">{"".join(_xlsx_cell(1, idx, header, 1) for idx, header in enumerate(headers, start=1))}</row>'
    )
    for row_index, row in enumerate(rows, start=2):
        sev = str(row.get("severity") or "unknown").lower()
        sev_style = severity_styles.get(sev, 0)
        values = [
            row.get("id"),
            row.get("severity") or "unknown",
            row.get("priority_score") if row.get("priority_score") is not None else "",
            row.get("title") or row.get("cve") or "",
            row.get("host") or "",
            row.get("tool") or "",
            row.get("cve") or "",
            "Yes" if row.get("has_public_exploit") or row.get("has_poc") else "No",
            row.get("summary") or "",
            row.get("solution") or "",
        ]
        cells = []
        for col_index, value in enumerate(values, start=1):
            cells.append(_xlsx_cell(row_index, col_index, value, sev_style if col_index == 2 else 0))
        sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    widths = "".join(
        f'<col min="{idx}" max="{idx}" width="{width}" customWidth="1"/>'
        for idx, width in enumerate([8, 14, 10, 44, 28, 22, 18, 10, 60, 60], start=1)
    )
    sheet_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <cols>{widths}</cols>
  <sheetData>{"".join(sheet_rows)}</sheetData>
  <autoFilter ref="A1:J{max(1, len(rows) + 1)}"/>
</worksheet>'''
    styles_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2"><font><sz val="11"/><color rgb="FF111827"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>
  <fills count="7"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF10231F"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFF05154"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFF7678"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFF49E31"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF5FD0A5"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF83D8FF"/><bgColor indexed="64"/></patternFill></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="7"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="1" borderId="0" xfId="0" applyFill="1" applyFont="1"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFill="1" applyFont="1"/><xf numFmtId="0" fontId="1" fillId="3" borderId="0" xfId="0" applyFill="1" applyFont="1"/><xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="6" borderId="0" xfId="0" applyFill="1"/></cellXfs>
</styleSheet>'''
    workbook_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Vulnerabilities" sheetId="1" r:id="rId1"/></sheets></workbook>'''
    workbook_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'''
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'''
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/styles.xml", styles_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return Response(
        content=output.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=darkstar-vulnerabilities.xlsx"},
    )


@app.get("/api/exports/attack-surface.csv")
def export_attack_surface_csv(request: Request, search: str | None = None):
    org_db = _get_org_db(request)
    rows = [_asm_row_values(asset) for asset in _attack_surface_export_rows(org_db, search=search)]
    output = io.StringIO()
    fieldnames = [
        "asset", "ips", "urls", "ports", "issues", "max_severity",
        "max_priority", "exploitable", "sources", "tags", "last_seen",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=darkstar-attack-surface.csv"},
    )


@app.get("/api/exports/attack-surface.xlsx")
def export_attack_surface_xlsx(request: Request, search: str | None = None):
    org_db = _get_org_db(request)
    rows = [_asm_row_values(asset) for asset in _attack_surface_export_rows(org_db, search=search)]
    headers = [
        "Asset", "IPs", "URLs", "Open Ports / Services", "Issues",
        "Max Severity", "Max Priority", "Exploitable", "Sources", "Tags", "Last Seen",
    ]
    workbook_rows = [
        [
            row["asset"], row["ips"], row["urls"], row["ports"], row["issues"],
            row["max_severity"], row["max_priority"], row["exploitable"],
            row["sources"], row["tags"], row["last_seen"],
        ]
        for row in rows
    ]
    content = _xlsx_workbook(
        headers,
        workbook_rows,
        [28, 24, 48, 30, 10, 14, 12, 12, 34, 42, 22],
        "Attack Surface",
        severity_col=6,
    )
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=darkstar-attack-surface.xlsx"},
    )


@app.get("/api/exports/attack-surface.html", response_class=HTMLResponse)
def export_attack_surface_html(request: Request, search: str | None = None, download: bool = False):
    org_db = _get_org_db(request)
    rows = [_asm_row_values(asset) for asset in _attack_surface_export_rows(org_db, search=search)]
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    download_params = {"download": "true"}
    if search:
        download_params["search"] = search
    download_href = f"/api/exports/attack-surface.html?{urlencode(download_params)}"

    severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
    severity_counts = {sev: 0 for sev in severity_order}
    for row in rows:
        sev = str(row["max_severity"] or "unknown").lower()
        severity_counts[sev if sev in severity_counts else "unknown"] += 1
    exposed_ports = sum(0 if row["ports"] == "No open ports recorded" else len(row["ports"].split(",")) for row in rows)
    exploitable_assets = sum(1 for row in rows if int(row["exploitable"] or 0) > 0)

    def h(value) -> str:
        return html_escape("" if value is None else str(value))

    bars_html = "\n".join(
        f'<div class="sev-row"><span class="sev-dot {h(sev)}"></span><span>{h(sev.title())}</span><strong>{count}</strong></div>'
        for sev, count in severity_counts.items()
        if count
    ) or '<p class="muted">No exposure data available.</p>'
    table_html = "\n".join(
        f"""
        <tr>
            <td><strong>{h(row['asset'])}</strong><small>{h(row['urls'])}</small></td>
            <td>{h(row['ips'] or '-')}</td>
            <td>{h(row['ports'])}</td>
            <td>{h(row['issues'])}</td>
            <td><span class="sev-pill {h(str(row['max_severity']).lower())}">{h(row['max_severity'])}</span></td>
            <td>{h(row['sources'] or '-')}</td>
            <td>{h(row['tags'] or '-')}</td>
        </tr>
        """
        for row in rows
    ) or '<tr><td colspan="7">No attack surface assets matched this export.</td></tr>'
    html = f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Darkstar Attack Surface Report</title>
    <style>
        :root {{ color-scheme: dark; --bg:#071512; --panel:#0d1e1b; --text:#eefcf7; --muted:#a8c7bd; --line:rgba(95,208,165,.22); --green:#5fd0a5; --red:#f05154; --orange:#f49e31; --blue:#83d8ff; }}
        * {{ box-sizing: border-box; }}
        body {{ margin:0; background:linear-gradient(145deg,#071512,#10231f); color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
        main {{ width:min(1180px,calc(100% - 48px)); margin:0 auto; padding:42px 0 56px; }}
        header,.panel,.metric {{ border:1px solid var(--line); border-radius:18px; background:rgba(13,30,27,.86); box-shadow:0 18px 50px rgba(0,0,0,.24); }}
        header {{ padding:30px; border-radius:24px; background:linear-gradient(135deg,rgba(95,208,165,.16),transparent 42%),rgba(8,22,19,.86); }}
        h1 {{ margin:8px 0 10px; font-size:clamp(32px,5vw,58px); line-height:1; }}
        h2 {{ margin:0 0 16px; font-size:18px; }}
        .eyebrow {{ color:var(--green); font:700 12px ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.14em; text-transform:uppercase; }}
        .subhead,.muted,td small {{ color:var(--muted); }}
        .report-actions {{ display:flex; flex-wrap:wrap; gap:10px; margin-top:20px; }}
        .report-actions a,.report-actions button {{ border:1px solid var(--line); border-radius:999px; padding:9px 14px; background:rgba(95,208,165,.10); color:var(--text); font-weight:800; text-decoration:none; cursor:pointer; }}
        .metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin:22px 0; }}
        .metric {{ padding:18px; }}
        .metric span,.metric em {{ display:block; color:var(--muted); font-size:12px; font-style:normal; }}
        .metric strong {{ display:block; margin:8px 0; font-size:34px; }}
        .panel {{ padding:20px; margin-bottom:22px; overflow:hidden; }}
        .severity-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; }}
        .sev-row {{ display:flex; align-items:center; gap:10px; padding:11px 12px; border:1px solid rgba(255,255,255,.06); border-radius:12px; background:rgba(255,255,255,.03); }}
        .sev-row strong {{ margin-left:auto; }}
        .sev-dot {{ width:10px; height:10px; border-radius:999px; background:var(--muted); }}
        .critical,.sev-pill.critical {{ background:var(--red); }}
        .high,.sev-pill.high {{ background:#ff7678; }}
        .medium,.sev-pill.medium {{ background:var(--orange); }}
        .low,.sev-pill.low {{ background:var(--green); color:#061914; }}
        .info,.unknown,.sev-pill.info,.sev-pill.unknown {{ background:var(--blue); color:#061914; }}
        .report-table-wrap {{ width:100%; overflow-x:auto; }}
        table {{ width:100%; min-width:1040px; table-layout:fixed; border-collapse:collapse; font-size:13px; }}
        th,td {{ padding:12px 10px; border-bottom:1px solid rgba(95,208,165,.13); text-align:left; vertical-align:top; overflow-wrap:anywhere; word-break:break-word; }}
        th:nth-child(1),td:nth-child(1) {{ width:220px; }}
        th:nth-child(2),td:nth-child(2) {{ width:160px; }}
        th:nth-child(3),td:nth-child(3) {{ width:190px; }}
        th:nth-child(4),td:nth-child(4) {{ width:76px; }}
        th:nth-child(5),td:nth-child(5) {{ width:112px; }}
        th {{ color:var(--muted); font:700 11px ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.08em; text-transform:uppercase; cursor:pointer; }}
        td small {{ display:block; margin-top:5px; line-height:1.45; }}
        .sev-pill {{ display:inline-flex; align-items:center; border-radius:999px; padding:4px 9px; color:white; font-weight:800; font-size:11px; text-transform:uppercase; }}
        @media (max-width:760px) {{ main {{ width:min(100% - 24px,1180px); }} .metrics {{ grid-template-columns:1fr 1fr; }} }}
        @media print {{ body {{ background:#fff; color:#111; }} header,.metric,.panel {{ box-shadow:none; background:#fff; border-color:#ddd; }} .report-actions {{ display:none; }} .subhead,.muted,th,td small {{ color:#555; }} }}
    </style>
</head>
<body>
    <main>
        <header>
            <div class="eyebrow">Darkstar attack surface report</div>
            <h1>ASM Exposure</h1>
            <p class="subhead">Generated {h(generated_at)} for {h(request.session.get('organization') or org_db)}. {h('Search: ' + search if search else 'No export filters applied')}.</p>
            <div class="report-actions">
                <a href="{h(download_href)}">Download HTML</a>
                <button type="button" onclick="window.print()">Print / Save PDF</button>
            </div>
        </header>
        <section class="metrics">
            <article class="metric"><span>Assets</span><strong>{len(rows)}</strong><em>Visible external assets</em></article>
            <article class="metric"><span>Open Ports</span><strong>{exposed_ports}</strong><em>Recorded exposed services</em></article>
            <article class="metric"><span>Exploitable</span><strong>{exploitable_assets}</strong><em>Assets with exploit signals</em></article>
            <article class="metric"><span>Findings</span><strong>{sum(int(row['issues'] or 0) for row in rows)}</strong><em>Total linked vulnerabilities</em></article>
        </section>
        <section class="panel"><h2>Exposure Distribution</h2><div class="severity-grid">{bars_html}</div></section>
        <section class="panel">
            <h2>Assets</h2>
            <div class="report-table-wrap">
                <table>
                    <thead><tr><th>Asset</th><th>IPs</th><th>Open Ports / Services</th><th>Issues</th><th>Max Severity</th><th>Sources</th><th>Tags</th></tr></thead>
                    <tbody>{table_html}</tbody>
                </table>
            </div>
        </section>
    </main>
    <script>
    document.querySelectorAll('th').forEach((th,index)=>{{th.addEventListener('click',()=>{{const table=th.closest('table');const tbody=table.tBodies[0];const rows=Array.from(tbody.rows);const asc=th.dataset.sort!=='asc';table.querySelectorAll('th').forEach(h=>h.dataset.sort='');th.dataset.sort=asc?'asc':'desc';rows.sort((a,b)=>{{const av=a.cells[index]?.innerText.trim()||'';const bv=b.cells[index]?.innerText.trim()||'';const an=Number(av.replace(/[^0-9.-]/g,''));const bn=Number(bv.replace(/[^0-9.-]/g,''));const result=!Number.isNaN(an)&&!Number.isNaN(bn)&&/\\d/.test(av+bv)?an-bn:av.localeCompare(bv);return asc?result:-result;}});rows.forEach(row=>tbody.appendChild(row));}});}});
    </script>
</body>
</html>"""
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f"{'attachment' if download else 'inline'}; filename=darkstar-attack-surface-report.html"},
    )


@app.get("/api/exports/vulnerabilities.html", response_class=HTMLResponse)
def export_vulnerabilities_html(
    request: Request,
    severity: str | None = None,
    host: str | None = None,
    tool: str | None = None,
    download: bool = False,
):
    """Render a designed standalone HTML vulnerability report."""
    org_db = _get_org_db(request)
    def h(value) -> str:
        return html_escape("" if value is None else str(value))

    rows = get_vulnerability_export_rows(org_db, severity=severity, host=host, tool=tool, limit=5000)
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    severity_order = ["critical", "high", "medium", "low", "baseline", "info", "unknown"]
    severity_counts = {key: 0 for key in severity_order}
    exploitable_count = 0
    max_score = 0.0
    hosts = set()
    for row in rows:
        sev = str(row.get("severity") or "unknown").lower()
        severity_counts[sev if sev in severity_counts else "unknown"] += 1
        if row.get("has_public_exploit") or row.get("has_poc"):
            exploitable_count += 1
        try:
            max_score = max(max_score, float(row.get("priority_score") or 0))
        except (TypeError, ValueError):
            pass
        if row.get("host"):
            hosts.add(str(row["host"]))

    filters = [part for part in [
        f"Severity: {severity}" if severity else "",
        f"Host: {host}" if host else "",
        f"Tool: {tool}" if tool else "",
    ] if part]
    download_params = {
        key: value
        for key, value in {
            "severity": severity,
            "host": host,
            "tool": tool,
            "download": "true",
        }.items()
        if value
    }
    download_href = f"/api/exports/vulnerabilities.html?{urlencode(download_params)}"

    metric_cards = [
        ("Findings", len(rows), "Total exported findings"),
        ("Assets", len(hosts), "Unique affected hosts"),
        ("Max Score", f"{max_score:.0f}", "Highest priority score"),
        ("Exploitable", exploitable_count, "PoC or public exploit present"),
    ]

    metrics_html = "\n".join(
        f"""
        <article class="metric">
            <span>{h(label)}</span>
            <strong>{h(value)}</strong>
            <em>{h(caption)}</em>
        </article>
        """
        for label, value, caption in metric_cards
    )

    severity_html = "\n".join(
        f"""
        <div class="sev-row">
            <span class="sev-dot {h(sev)}"></span>
            <span>{h(sev.title())}</span>
            <strong>{count}</strong>
        </div>
        """
        for sev, count in severity_counts.items()
        if count
    ) or '<p class="muted">No severity data available.</p>'

    rows_html = "\n".join(
        f"""
        <tr>
            <td><span class="sev-pill {h(str(row.get('severity') or 'unknown').lower())}">{h(row.get('severity') or 'unknown')}</span></td>
            <td>{h(row.get('priority_score') if row.get('priority_score') is not None else '-')}</td>
            <td>
                <strong>{h(row.get('title') or row.get('cve') or 'Untitled finding')}</strong>
                <small>{h(row.get('summary') or '')}</small>
            </td>
            <td>{h(row.get('host') or '-')}</td>
            <td>{h(row.get('tool') or '-')}</td>
            <td>{h(row.get('cve') or '-')}</td>
            <td>{'Yes' if row.get('has_public_exploit') or row.get('has_poc') else 'No'}</td>
            <td>{h(row.get('solution') or '-')}</td>
        </tr>
        """
        for row in rows
    ) or '<tr><td colspan="8">No vulnerabilities matched the export filters.</td></tr>'

    html = f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Darkstar Vulnerability Report</title>
    <style>
        :root {{
            color-scheme: dark;
            --bg: #071512;
            --panel: #0d1e1b;
            --panel-2: #102823;
            --text: #eefcf7;
            --muted: #a8c7bd;
            --line: rgba(95,208,165,.22);
            --green: #5fd0a5;
            --red: #f05154;
            --orange: #f49e31;
            --blue: #83d8ff;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            background: radial-gradient(circle at 14% 8%, rgba(95,208,165,.18), transparent 30%), linear-gradient(145deg, #071512, #10231f);
            color: var(--text);
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }}
        main {{ width: min(1180px, calc(100% - 48px)); margin: 0 auto; padding: 42px 0 56px; }}
        header {{
            border: 1px solid var(--line);
            border-radius: 24px;
            padding: 30px;
            background: linear-gradient(135deg, rgba(95,208,165,.16), transparent 42%), rgba(8,22,19,.86);
            box-shadow: 0 24px 70px rgba(0,0,0,.35);
        }}
        .eyebrow {{ color: var(--green); font: 700 12px ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .14em; text-transform: uppercase; }}
        h1 {{ margin: 8px 0 10px; font-size: clamp(32px, 5vw, 58px); line-height: 1; }}
        .subhead {{ max-width: 760px; color: var(--muted); }}
        .filters {{ margin-top: 18px; color: var(--muted); font-size: 13px; }}
        .report-actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 20px; }}
        .report-actions a, .report-actions button {{ border: 1px solid var(--line); border-radius: 999px; padding: 9px 14px; background: rgba(95,208,165,.10); color: var(--text); font-weight: 800; text-decoration: none; cursor: pointer; }}
        .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 22px 0; }}
        .metric, .panel {{
            border: 1px solid var(--line);
            border-radius: 18px;
            background: rgba(13,30,27,.86);
            box-shadow: 0 18px 50px rgba(0,0,0,.24);
        }}
        .metric {{ padding: 18px; }}
        .metric span, .metric em {{ display: block; color: var(--muted); font-size: 12px; font-style: normal; }}
        .metric strong {{ display: block; margin: 8px 0; font-size: 34px; }}
        .panel {{ padding: 20px; margin-bottom: 22px; overflow: hidden; }}
        .report-table-wrap {{ width: 100%; overflow-x: auto; }}
        h2 {{ margin: 0 0 16px; font-size: 18px; }}
        .severity-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }}
        .sev-row {{ display: flex; align-items: center; gap: 10px; padding: 11px 12px; border: 1px solid rgba(255,255,255,.06); border-radius: 12px; background: rgba(255,255,255,.03); }}
        .sev-row strong {{ margin-left: auto; }}
        .sev-dot {{ width: 10px; height: 10px; border-radius: 999px; background: var(--muted); }}
        .critical, .sev-pill.critical {{ background: var(--red); }}
        .high, .sev-pill.high {{ background: #ff7678; }}
        .medium, .sev-pill.medium {{ background: var(--orange); }}
        .low, .sev-pill.low {{ background: var(--green); color: #061914; }}
        .baseline, .info, .sev-pill.baseline, .sev-pill.info {{ background: var(--blue); color: #061914; }}
        table {{ width: 100%; min-width: 1080px; border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
        th, td {{ padding: 12px 10px; border-bottom: 1px solid rgba(95,208,165,.13); text-align: left; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }}
        th:nth-child(1), td:nth-child(1) {{ width: 104px; }}
        th:nth-child(2), td:nth-child(2) {{ width: 72px; }}
        th:nth-child(4), td:nth-child(4) {{ width: 170px; }}
        th:nth-child(5), td:nth-child(5) {{ width: 130px; }}
        th:nth-child(6), td:nth-child(6), th:nth-child(7), td:nth-child(7) {{ width: 88px; }}
        th {{ color: var(--muted); font: 700 11px ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .08em; text-transform: uppercase; }}
        td small {{ display: block; margin-top: 5px; color: var(--muted); line-height: 1.45; }}
        .sev-pill {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 4px 9px; color: white; font-weight: 800; font-size: 11px; text-transform: uppercase; }}
        .muted {{ color: var(--muted); }}
        @media print {{
            body {{ background: #fff; color: #111; }}
            header, .metric, .panel {{ box-shadow: none; background: #fff; border-color: #ddd; }}
            .subhead, .filters, th, td small, .muted {{ color: #555; }}
            .report-actions {{ display: none; }}
        }}
    </style>
</head>
<body>
    <main>
        <header>
            <div class="eyebrow">Darkstar vulnerability report</div>
            <h1>Exposure Summary</h1>
            <p class="subhead">Generated {h(generated_at)} for {h(request.session.get('organization') or org_db)}. This report includes prioritized vulnerabilities, affected assets, exploitability signals and remediation guidance.</p>
            <p class="filters">{h(' | '.join(filters) if filters else 'No export filters applied')}</p>
            <div class="report-actions">
                <a href="{h(download_href)}">Download HTML</a>
                <button type="button" onclick="window.print()">Print / Save PDF</button>
            </div>
        </header>
        <section class="metrics">{metrics_html}</section>
        <section class="panel">
            <h2>Severity Distribution</h2>
            <div class="severity-grid">{severity_html}</div>
        </section>
        <section class="panel">
            <h2>Findings</h2>
            <div class="report-table-wrap">
                <table>
                    <thead>
                        <tr><th>Severity</th><th>Score</th><th>Finding</th><th>Host</th><th>Tool</th><th>CVE</th><th>Exploit</th><th>Recommended Fix</th></tr>
                    </thead>
                    <tbody>{rows_html}</tbody>
                </table>
            </div>
        </section>
    </main>
    <script>
    document.querySelectorAll('th').forEach((th, index) => {{
        th.style.cursor = 'pointer';
        th.addEventListener('click', () => {{
            const table = th.closest('table');
            const tbody = table.tBodies[0];
            const rows = Array.from(tbody.rows);
            const asc = th.dataset.sort !== 'asc';
            table.querySelectorAll('th').forEach(h => h.dataset.sort = '');
            th.dataset.sort = asc ? 'asc' : 'desc';
            rows.sort((a, b) => {{
                const av = a.cells[index]?.innerText.trim() || '';
                const bv = b.cells[index]?.innerText.trim() || '';
                const an = Number(av.replace(/[^0-9.-]/g, ''));
                const bn = Number(bv.replace(/[^0-9.-]/g, ''));
                const result = !Number.isNaN(an) && !Number.isNaN(bn) && /\\d/.test(av + bv)
                    ? an - bn
                    : av.localeCompare(bv);
                return asc ? result : -result;
            }});
            rows.forEach(row => tbody.appendChild(row));
        }});
    }});
    </script>
</body>
</html>"""
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f"{'attachment' if download else 'inline'}; filename=darkstar-vulnerability-report.html"},
    )


def _pdf_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_simple_pdf(title: str, lines: list[str]) -> bytes:
    """Build a small text-only PDF without extra runtime dependencies."""
    content_lines = ["BT", "/F1 16 Tf", "50 790 Td", f"({_pdf_escape(title)}) Tj", "/F1 9 Tf", "0 -24 Td"]
    for line in lines[:90]:
        content_lines.append(f"({_pdf_escape(line[:110])}) Tj")
        content_lines.append("0 -12 Td")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")
    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n",
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
        f"5 0 obj << /Length {len(stream)} >> stream\n".encode("ascii") + stream + b"\nendstream endobj\n",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(pdf)


@app.get("/api/exports/vulnerabilities.pdf")
def export_vulnerabilities_pdf(request: Request):
    org_db = _get_org_db(request)
    rows = get_vulnerability_export_rows(org_db, limit=200)
    lines = [
        f"{row.get('severity') or '-'} | score {row.get('priority_score') or 0} | {row.get('host') or '-'} | {row.get('cve') or '-'} | {row.get('title') or '-'}"
        for row in rows
    ]
    pdf = _build_simple_pdf("Darkstar Vulnerability Report", lines or ["No vulnerabilities found."])
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=darkstar-vulnerabilities.pdf"},
    )


@app.get("/api/admin/organizations")
def admin_organizations(request: Request):
    _require_platform_admin(request)
    return {"items": list_organizations()}


@app.get("/api/admin/auth/policy")
def admin_auth_policy(request: Request):
    _require_platform_admin(request)
    return get_platform_auth_settings()


@app.patch("/api/admin/auth/policy")
def update_admin_auth_policy(request: Request, body: AuthPolicyRequest):
    _require_platform_admin(request)
    if body.mfa_required:
        _require_current_user_mfa_enabled(request)
    return update_platform_auth_settings(body.mfa_required)


@app.get("/api/admin/users")
def admin_users(request: Request):
    _require_platform_admin(request)
    return {"items": list_users()}


@app.post("/api/admin/users")
def admin_create_or_update_user(request: Request, body: AdminUserRequest):
    _require_platform_admin(request)
    _validate_user_password(body.password)
    try:
        user = create_or_update_user(
            email=body.email,
            password=body.password,
            display_name=body.display_name,
            org_db_name=body.org_db,
            role=body.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "user": user}


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(request: Request, user_id: int):
    _require_platform_admin(request)
    if _current_user_id(request) == user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    if not delete_user(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}/memberships/{org_db}")
def admin_remove_user_membership(request: Request, user_id: int, org_db: str):
    _require_platform_admin(request)
    if _current_user_id(request) == user_id and request.session.get("org_db") == org_db:
        raise HTTPException(status_code=400, detail="You cannot remove your own active organization membership")
    if not remove_user_membership(user_id, org_db):
        raise HTTPException(status_code=404, detail="User membership not found")
    return {"ok": True}


@app.get("/api/admin/overview")
def admin_overview(request: Request):
    _require_platform_admin(request)
    return get_oversight_summary()


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
