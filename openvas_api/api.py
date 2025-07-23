# api.py
import os
import xml.etree.ElementTree as ET
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

# ---- Pydantic models ----


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
    # Optional: specify scan config & scanner;
    # if omitted, defaults will be used
    config_id: Optional[str] = None
    scanner_id: Optional[str] = None


class TaskInfo(BaseModel):
    id: str
    name: str
    status: str


# ---- FastAPI app ----

app = FastAPI(title="OpenVAS GMP HTTP API")

SOCK_PATH = os.getenv("GMP_SOCKET", "/run/gvmd/gvmd.sock")
GVM_USER = os.getenv("GVM_USER", "admin")
GVM_PASS = os.getenv("GVM_PASSWORD", "admin")


def get_gmp():
    """Dependency: yields an authenticated GMP session."""
    conn = UnixSocketConnection(path=SOCK_PATH)
    with Gmp(conn) as gmp:
        gmp.authenticate(GVM_USER, GVM_PASS)
        yield gmp


# ---- Helpers to parse GMP XML ----


def _parse_xml(resp) -> ET.Element:
    if isinstance(resp, bytes):
        resp = resp.decode()
    return ET.fromstring(resp)


# ---- Endpoints ----


@app.post("/targets", response_model=TargetInfo)
def create_target(body: TargetCreate, gmp: Gmp = Depends(get_gmp)):
    """Create a new scan target."""
    resp = gmp.create_target(
        name=body.name,
        hosts=body.hosts,
        port_range=body.port_range,
        port_list_id=body.port_list_id,
    )
    print(f"create_target response: {resp}")
    root = _parse_xml(resp)
    status = root.get("status", "unknown status")
    id = root.get("id", "")
    status_text = root.get("status_text", "unknown error")

    if status == "201":
        return TargetInfo(
            id=id,
            name=body.name,
            hosts=body.hosts,
        )
    else:
        raise HTTPException(int(status), f"{status_text}")


@app.get("/targets", response_model=List[TargetInfo])
def list_targets(gmp: Gmp = Depends(get_gmp)):
    """List all scan targets."""
    resp = gmp.get_targets()
    root = _parse_xml(resp)
    out = []
    for tgt in root.findall(".//target"):
        hosts = [h.text for h in tgt.findall("hosts/ip")]
        out.append(TargetInfo(id=tgt.get("id"), name=tgt.findtext("name"), hosts=hosts))
    return out


@app.post("/tasks", response_model=TaskInfo)
def create_task(body: TaskCreate, gmp: Gmp = Depends(get_gmp)):
    """Create a scan task for a given target."""

    # pick defaults if not provided:
    if body.config_id is None:
        cfg_resp = gmp.get_scan_configs()
        cfg_root = _parse_xml(cfg_resp)

        # find config named "Full and fast"
        cfg = cfg_root.find(".//config[name='Full and fast']") or cfg_root.find(
            ".//config"
        )
        if cfg is not None:
            body.config_id = cfg.get("id")
        else:
            raise HTTPException(500, "No scan configuration found")

    if body.scanner_id is None:
        scn_resp = gmp.get_scanners()
        scn_root = _parse_xml(scn_resp)

        scanners = scn_root.findall(".//scanner")

        if len(scanners) > 1:
            scn = scanners[1]
        elif len(scanners) == 1:
            scn = scanners[0]
        else:
            raise HTTPException(500, "No scanner found")
        body.scanner_id = scn.get("id")

    resp = gmp.create_task(
        name=body.name,
        config_id=body.config_id,
        target_id=body.target_id,
        scanner_id=body.scanner_id,
    )

    root = _parse_xml(resp)

    status = root.get("status", "unknown error")
    id_ = root.get("id", "")
    status_text = root.get("status_text", "unknown error")

    if status == "201":
        return TaskInfo(id=id_, name=body.name, status="Created")

    raise HTTPException(int(status), status_text)


@app.post("/tasks/{task_id}/start")
def start_task(task_id: str, gmp: Gmp = Depends(get_gmp)):
    """Start a previously created scan task."""
    resp = gmp.start_task(task_id)
    print(f"Raw XML response: {resp}")
    root = _parse_xml(resp)

    # Debug: Print the entire XML structure
    print(f"XML root tag: {root.tag}")
    print(f"XML root attributes: {root.attrib}")
    for child in root:
        print(f"Child element: {child.tag}, text: {child.text}, attrib: {child.attrib}")

    # Try multiple ways to get the report ID
    report_id = None

    # Method 1: Direct text content
    report_id = root.findtext("report_id")
    print(f"Method 1 - findtext('report_id'): {report_id}")

    # Method 2: As attribute
    if not report_id:
        report_id = root.get("report_id")
        print(f"Method 2 - root.get('report_id'): {report_id}")

    # Method 3: Look for report element
    if not report_id:
        report_elem = root.find(".//report")
        if report_elem is not None:
            report_id = report_elem.get("id")
            print(f"Method 3 - report element id: {report_id}")

    # Method 4: Check if it's nested differently
    if not report_id:
        for elem in root.iter():
            if elem.tag == "report_id" or "report" in elem.tag.lower():
                print(
                    f"Found element: {elem.tag}, text: {elem.text}, attrib: {elem.attrib}"
                )
                if elem.text:
                    report_id = elem.text
                elif elem.get("id"):
                    report_id = elem.get("id")

    print(f"Final report_id: {report_id}")

    # Return a dictionary with both task_id and report_id for monitoring
    return {"task_id": task_id, "report_id": report_id, "status": "Started"}


@app.get("/tasks", response_model=List[TaskInfo])
def list_tasks(gmp: Gmp = Depends(get_gmp)):
    """List all scan tasks and their status."""
    resp = gmp.get_tasks()
    root = _parse_xml(resp)
    out = []
    for t in root.findall(".//task"):
        out.append(
            TaskInfo(
                id=t.get("id"), name=t.findtext("name"), status=t.findtext("status")
            )
        )
    return out


@app.get("/tasks/{task_id}/status", response_model=TaskInfo)
def get_task_status(task_id: str, gmp: Gmp = Depends(get_gmp)):
    """Get status of a specific task."""
    resp = gmp.get_task(task_id=task_id)
    root = _parse_xml(resp)
    t = root.find(".//task")
    return TaskInfo(id=task_id, name=t.findtext("name"), status=t.findtext("status"))


@app.get("/reports/{report_id}")
def get_report(report_id: str, gmp: Gmp = Depends(get_gmp)):
    """Fetch a finished report (defaulting to XML format)."""
    # pick the XML report format
    rf = _parse_xml(gmp.get_report_formats()).find(".//report_format[name='XML']")
    rf_id = (
        rf.get("id")
        if rf is not None
        else _parse_xml(gmp.get_report_formats()).find(".//report_format").get("id")
    )
    print(f"Using report format ID: {rf_id} for report {report_id}")
    report = gmp.get_report(report_id=report_id, report_format_id=rf_id)
    if isinstance(report, bytes):
        report = report.decode()
    return Response(content=report, media_type="application/xml")
