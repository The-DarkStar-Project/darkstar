"""Small HTTP facade around the Greenbone Management Protocol (GMP)."""

from contextlib import ExitStack, suppress
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError, GvmResponseError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

logger = logging.getLogger("openvas_api")


class TargetCreate(BaseModel):
    name: str
    hosts: List[str]
    port_range: Optional[str] = "1-65535"
    port_list_id: Optional[str] = None


class TargetInfo(BaseModel):
    id: str
    name: str
    hosts: List[str]


class TaskCreate(BaseModel):
    name: str
    target_id: str
    config_id: Optional[str] = None
    scanner_id: Optional[str] = None


class TaskInfo(BaseModel):
    id: str
    name: str
    status: str


app = FastAPI(title="OpenVAS GMP HTTP API")

SOCK_PATH = os.getenv("GMP_SOCKET", "/run/gvmd/gvmd.sock")
# Compose historically exposed OPENVAS_* while this service only read GVM_*.
# Support both names so existing .env files continue to work.
GVM_USER = os.getenv("GVM_USER") or os.getenv("OPENVAS_USER") or "admin"
GVM_PASS = os.getenv("GVM_PASSWORD") or os.getenv("OPENVAS_PASS") or "admin"


def _connection_error_detail(exc: Exception) -> str:
    if isinstance(exc, FileNotFoundError):
        return f"gvmd socket is not available at {SOCK_PATH}"
    if isinstance(exc, PermissionError):
        return f"gvmd socket is not accessible at {SOCK_PATH}"
    return f"gvmd connection or authentication failed: {type(exc).__name__}: {exc}"


def get_gmp():
    """Yield an authenticated GMP session or an actionable HTTP 503."""
    if not os.path.exists(SOCK_PATH):
        raise HTTPException(
            status_code=503,
            detail=f"gvmd socket is not available at {SOCK_PATH}",
        )

    stack = ExitStack()
    try:
        connection = UnixSocketConnection(path=SOCK_PATH)
        # This transform makes python-gvm raise on GMP 4xx/5xx responses.
        # Without it, failed authentication can look like a valid XML result.
        gmp = stack.enter_context(
            Gmp(connection, transform=EtreeCheckCommandTransform())
        )
        gmp.authenticate(GVM_USER, GVM_PASS)
    except Exception as exc:
        with suppress(Exception):
            stack.close()
        detail = _connection_error_detail(exc)
        logger.exception("Unable to establish an authenticated GMP session")
        raise HTTPException(status_code=503, detail=detail) from exc

    try:
        yield gmp
    finally:
        with suppress(Exception):
            stack.close()


@app.exception_handler(GvmError)
async def handle_gvm_error(_request: Request, exc: GvmError):
    """Turn runtime GMP failures into useful gateway errors, not opaque 500s."""
    status_code = 502
    if isinstance(exc, GvmResponseError):
        with suppress(TypeError, ValueError):
            gmp_status = int(exc.status)
            if 400 <= gmp_status < 500:
                status_code = gmp_status
    logger.exception("GMP request failed")
    return JSONResponse(status_code=status_code, content={"detail": str(exc)})


def _parse_xml(response: Any):
    """Return an XML root for string, bytes, ElementTree, or lxml responses."""
    if hasattr(response, "getroot"):
        return response.getroot()
    if hasattr(response, "tag") and hasattr(response, "find"):
        return response
    if isinstance(response, bytes):
        response = response.decode("utf-8", errors="replace")
    if not isinstance(response, str):
        raise TypeError(f"Unsupported GMP response type: {type(response).__name__}")
    return ET.fromstring(response)


def _http_status(root: Any, fallback: int = 502) -> int:
    try:
        status = int(root.get("status", ""))
    except (TypeError, ValueError):
        return fallback
    return status if 400 <= status <= 599 else fallback


def _hosts_from_target(target: Any) -> list[str]:
    nested_hosts = [
        host.text.strip()
        for host in target.findall("hosts/ip")
        if host.text and host.text.strip()
    ]
    if nested_hosts:
        return nested_hosts

    # gvmd normally returns a comma/newline-separated <hosts> value.
    hosts_text = target.findtext("hosts") or ""
    return [host for host in re.split(r"[\s,]+", hosts_text.strip()) if host]


def _xml_text(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, bytes):
        return response.decode("utf-8", errors="replace")
    root = _parse_xml(response)
    try:
        return ET.tostring(root, encoding="unicode")
    except TypeError:
        # lxml elements support bytes(element), while stdlib elements do not.
        return bytes(root).decode("utf-8", errors="replace")


@app.get("/health")
def health(gmp: Any = Depends(get_gmp)):
    """Check GMP credentials and ensure a real OpenVAS scanner is registered."""
    root = _parse_xml(gmp.get_version())
    scanners_root = _parse_xml(gmp.get_scanners())
    scanners = [
        scanner
        for scanner in scanners_root.findall(".//scanner")
        if "cve" not in (scanner.findtext("name") or "").lower()
    ]
    if not scanners:
        raise HTTPException(status_code=503, detail="No usable OpenVAS scanner registered")
    return {
        "status": "ok",
        "gvmd_socket": SOCK_PATH,
        "gmp_version": root.findtext(".//version"),
        "scanner_count": len(scanners),
    }


@app.post("/targets", response_model=TargetInfo)
def create_target(body: TargetCreate, gmp: Any = Depends(get_gmp)):
    response = gmp.create_target(
        name=body.name,
        hosts=body.hosts,
        port_range=body.port_range,
        port_list_id=body.port_list_id,
    )
    root = _parse_xml(response)
    if root.get("status") == "201" and root.get("id"):
        return TargetInfo(id=root.get("id"), name=body.name, hosts=body.hosts)
    raise HTTPException(
        status_code=_http_status(root),
        detail=root.get("status_text", "Unable to create OpenVAS target"),
    )


@app.get("/targets", response_model=List[TargetInfo])
def list_targets(gmp: Any = Depends(get_gmp)):
    root = _parse_xml(gmp.get_targets())
    return [
        TargetInfo(
            id=target.get("id") or "",
            name=target.findtext("name") or "",
            hosts=_hosts_from_target(target),
        )
        for target in root.findall(".//target")
    ]


@app.post("/tasks", response_model=TaskInfo)
def create_task(body: TaskCreate, gmp: Any = Depends(get_gmp)):
    config_id = body.config_id
    if config_id is None:
        config_root = _parse_xml(gmp.get_scan_configs())
        config = config_root.find(".//config[name='Full and fast']")
        if config is None:
            config = config_root.find(".//config")
        if config is None or not config.get("id"):
            raise HTTPException(status_code=503, detail="No scan configuration found")
        config_id = config.get("id")

    scanner_id = body.scanner_id
    if scanner_id is None:
        scanner_root = _parse_xml(gmp.get_scanners())
        scanners = scanner_root.findall(".//scanner")
        usable = [
            scanner
            for scanner in scanners
            if "cve" not in (scanner.findtext("name") or "").lower()
        ]
        scanner = next(
            (
                item
                for item in usable
                if "openvas" in (item.findtext("name") or "").lower()
            ),
            usable[0] if usable else None,
        )
        if scanner is None or not scanner.get("id"):
            raise HTTPException(status_code=503, detail="No OpenVAS scanner found")
        scanner_id = scanner.get("id")

    root = _parse_xml(
        gmp.create_task(
            name=body.name,
            config_id=config_id,
            target_id=body.target_id,
            scanner_id=scanner_id,
        )
    )
    if root.get("status") == "201" and root.get("id"):
        return TaskInfo(id=root.get("id"), name=body.name, status="Created")
    raise HTTPException(
        status_code=_http_status(root),
        detail=root.get("status_text", "Unable to create OpenVAS task"),
    )


@app.post("/tasks/{task_id}/start")
def start_task(task_id: str, gmp: Any = Depends(get_gmp)):
    root = _parse_xml(gmp.start_task(task_id))
    report_id = root.findtext("report_id") or root.get("report_id")
    if not report_id:
        report = root.find(".//report")
        report_id = report.get("id") if report is not None else None
    if not report_id:
        raise HTTPException(
            status_code=_http_status(root),
            detail=root.get("status_text", "gvmd did not return a report id"),
        )
    return {"task_id": task_id, "report_id": report_id, "status": "Started"}


@app.post("/tasks/{task_id}/stop")
def stop_task(task_id: str, gmp: Any = Depends(get_gmp)):
    root = _parse_xml(gmp.stop_task(task_id))
    if root.get("status") in {"200", "202"}:
        return {"task_id": task_id, "status": "Stopped"}
    raise HTTPException(
        status_code=_http_status(root),
        detail=root.get("status_text", "Unable to stop OpenVAS task"),
    )


@app.get("/tasks", response_model=List[TaskInfo])
def list_tasks(gmp: Any = Depends(get_gmp)):
    root = _parse_xml(gmp.get_tasks())
    return [
        TaskInfo(
            id=task.get("id") or "",
            name=task.findtext("name") or "",
            status=task.findtext("status") or "Unknown",
        )
        for task in root.findall(".//task")
    ]


@app.get("/tasks/{task_id}/status", response_model=TaskInfo)
def get_task_status(task_id: str, gmp: Any = Depends(get_gmp)):
    root = _parse_xml(gmp.get_task(task_id=task_id))
    task = root.find(".//task")
    if task is None:
        raise HTTPException(status_code=404, detail=f"Task {task_id} was not found")
    return TaskInfo(
        id=task_id,
        name=task.findtext("name") or "",
        status=task.findtext("status") or "Unknown",
    )


@app.get("/reports/{report_id}")
def get_report(report_id: str, gmp: Any = Depends(get_gmp)):
    formats_root = _parse_xml(gmp.get_report_formats())
    report_format = formats_root.find(".//report_format[name='XML']")
    if report_format is None:
        report_format = formats_root.find(".//report_format")
    if report_format is None or not report_format.get("id"):
        raise HTTPException(status_code=503, detail="No report format found")

    report = gmp.get_report(
        report_id=report_id,
        report_format_id=report_format.get("id"),
    )
    return Response(content=_xml_text(report), media_type="application/xml")
