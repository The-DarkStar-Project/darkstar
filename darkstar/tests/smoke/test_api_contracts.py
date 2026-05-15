import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from darkstar import webapp


pytestmark = pytest.mark.smoke


@pytest.fixture()
def api_client(monkeypatch):
    monkeypatch.setattr(webapp, "list_organizations", list)
    monkeypatch.setattr(webapp, "scheduler_started", True)
    monkeypatch.setattr(
        webapp,
        "authenticate_api_key",
        lambda token: {
            "org_db_name": "tenant_db",
            "org_name": "Acme Security",
            "role": "tenant_admin",
        }
        if token == "test-token"
        else None,
    )
    with TestClient(webapp.app) as test_client:
        yield test_client


AUTH_HEADERS = {"Authorization": "Bearer test-token"}


def test_vulnerability_routes_filter_group_and_detail(api_client, monkeypatch):
    filtered_call = {}

    def fake_filtered(org_db, severity, host, tool, limit, offset, dedupe=False):
        filtered_call.update(
            {
                "org_db": org_db,
                "severity": severity,
                "host": host,
                "tool": tool,
                "limit": limit,
                "offset": offset,
                "dedupe": dedupe,
            }
        )
        return (
            [
                {
                    "id": 42,
                    "title": "SQL Injection",
                    "severity": "high",
                    "host": "app.example.com",
                    "tool": "nuclei",
                }
            ],
            1,
        )

    monkeypatch.setattr(webapp, "get_vulnerabilities_filtered", fake_filtered)
    monkeypatch.setattr(webapp, "get_vulnerability_detail", lambda org_db, vuln_id: {"id": vuln_id, "title": "SQL Injection"})
    monkeypatch.setattr(webapp, "get_unique_hosts", lambda org_db: ["app.example.com"])
    monkeypatch.setattr(webapp, "get_unique_tools", lambda org_db: ["nuclei", "zap"])
    monkeypatch.setattr(
        webapp,
        "get_grouped_vulnerabilities",
        lambda org_db, group_by: [{"group_key": "app.example.com", "count": 1, "max_priority": 91}],
    )

    filtered = api_client.get(
        "/api/vulnerabilities/filtered?severity=high&host=app.example.com&tool=nuclei&limit=10&offset=5&dedupe=true",
        headers=AUTH_HEADERS,
    )
    detail = api_client.get("/api/vulnerabilities/42", headers=AUTH_HEADERS)
    hosts = api_client.get("/api/filters/hosts", headers=AUTH_HEADERS)
    tools = api_client.get("/api/filters/tools", headers=AUTH_HEADERS)
    grouped = api_client.get("/api/vulnerabilities/grouped?group_by=asset", headers=AUTH_HEADERS)

    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert filtered_call == {
        "org_db": "tenant_db",
        "severity": "high",
        "host": "app.example.com",
        "tool": "nuclei",
        "limit": 10,
        "offset": 5,
        "dedupe": True,
    }
    assert detail.json()["title"] == "SQL Injection"
    assert hosts.json()["items"] == ["app.example.com"]
    assert tools.json()["items"] == ["nuclei", "zap"]
    assert grouped.json()["items"][0]["group_key"] == "app.example.com"


def test_attack_surface_and_subdomain_routes(api_client, monkeypatch):
    attack_surface_call = {}
    subdomain_call = {}

    def fake_attack_surface(org_db, search=None, limit=100, offset=0):
        attack_surface_call.update({"org_db": org_db, "search": search, "limit": limit, "offset": offset})
        return {
            "summary": {"asset_count": 1, "exposed_ports": 2},
            "items": [{"host": "app.example.com", "ports": [{"port": 443, "service": "https"}]}],
            "total": 1,
        }

    def fake_subdomains(org_db, search=None, parent_domain=None, limit=100, offset=0):
        subdomain_call.update(
            {
                "org_db": org_db,
                "search": search,
                "parent_domain": parent_domain,
                "limit": limit,
                "offset": offset,
            }
        )
        return {
            "items": [{"target": "app.example.com", "preferred_target": "https://app.example.com"}],
            "domains": ["example.com"],
            "total": 1,
        }

    monkeypatch.setattr(webapp, "get_attack_surface_overview", fake_attack_surface)
    monkeypatch.setattr(webapp, "get_bbot_potential_targets", fake_subdomains)

    attack_surface = api_client.get("/api/attack-surface?search=app&limit=25&offset=10", headers=AUTH_HEADERS)
    subdomains = api_client.get(
        "/api/recon/subdomains?search=portal&parent_domain=example.com&limit=50&offset=5",
        headers=AUTH_HEADERS,
    )

    assert attack_surface.status_code == 200
    assert attack_surface.json()["summary"]["asset_count"] == 1
    assert attack_surface_call == {"org_db": "tenant_db", "search": "app", "limit": 25, "offset": 10}
    assert subdomains.status_code == 200
    assert subdomains.json()["domains"] == ["example.com"]
    assert subdomain_call == {
        "org_db": "tenant_db",
        "search": "portal",
        "parent_domain": "example.com",
        "limit": 50,
        "offset": 5,
    }


def test_start_scan_enqueues_worker_job_without_running_scanner(api_client, monkeypatch):
    created = {}
    enqueued = {}
    logs = []

    monkeypatch.setattr(webapp, "get_scan_history", lambda org_db, limit=100: [])
    monkeypatch.setattr(webapp, "get_scanner_node_record", lambda node_id: {"node_id": node_id, "revoked_at": None})

    def fake_create_scan_record(org_db, scan_name, scan_mode, targets):
        created.update({"org_db": org_db, "scan_name": scan_name, "scan_mode": scan_mode, "targets": targets})
        return 701

    def fake_enqueue_scanner_job(org_db, scan_id, scan_name, scan_mode, scanner, targets, payload, schedule_id=None, preferred_node_id=None):
        enqueued.update(
            {
                "org_db": org_db,
                "scan_id": scan_id,
                "scan_name": scan_name,
                "scan_mode": scan_mode,
                "scanner": scanner,
                "targets": targets,
                "payload": payload,
                "schedule_id": schedule_id,
                "preferred_node_id": preferred_node_id,
            }
        )

    monkeypatch.setattr(webapp, "create_scan_record", fake_create_scan_record)
    monkeypatch.setattr(webapp, "enqueue_scanner_job", fake_enqueue_scanner_job)
    monkeypatch.setattr(webapp, "insert_scan_log", lambda org_db, scan_id, message, level="info": logs.append((org_db, scan_id, message, level)))

    response = api_client.post(
        "/api/scans/start",
        headers=AUTH_HEADERS,
        json={
            "targets": "app.example.com, portal.example.com",
            "mode": 2,
            "preferred_node_id": "node-1",
            "scan_name": "Normal app scan",
            "bruteforce": False,
        },
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "scan_id": 701, "status": "queued"}
    assert created == {
        "org_db": "tenant_db",
        "scan_name": "Normal app scan",
        "scan_mode": "2",
        "targets": "app.example.com, portal.example.com",
    }
    assert enqueued["scanner"] is None
    assert enqueued["payload"]["mode"] == 2
    assert enqueued["preferred_node_id"] == "node-1"
    assert logs == [("tenant_db", 701, "Queued for selected scanner appliance node-1", "info")]


def test_schedule_routes_create_update_delete_and_run(api_client, monkeypatch):
    created_schedule = {}
    run_queue = {}

    monkeypatch.setattr(
        webapp,
        "get_scan_schedules",
        lambda org_db: [{"id": 11, "scan_name": "Weekly perimeter", "scan_mode": "2", "targets": "example.com", "enabled": True}],
    )
    monkeypatch.setattr(
        webapp,
        "create_scan_schedule",
        lambda org_db, **kwargs: created_schedule.update({"org_db": org_db, **kwargs}) or 12,
    )
    monkeypatch.setattr(webapp, "set_scan_schedule_enabled", lambda org_db, schedule_id, enabled: schedule_id == 11)
    monkeypatch.setattr(webapp, "delete_scan_schedule", lambda org_db, schedule_id: schedule_id == 11)
    monkeypatch.setattr(
        webapp,
        "get_scan_schedule",
        lambda org_db, schedule_id: {
            "id": schedule_id,
            "targets": "example.com",
            "scan_mode": "2",
            "scanner": None,
            "scan_name": "Weekly perimeter",
            "bruteforce": False,
            "bruteforce_timeout": 300,
            "preferred_node_id": None,
        },
    )
    monkeypatch.setattr(webapp, "mark_schedule_run", lambda org_db, schedule_id: None)
    monkeypatch.setattr(
        webapp,
        "_queue_scan",
        lambda org_db, body, schedule_id=None, allow_overlap=False: run_queue.update(
            {
                "org_db": org_db,
                "targets": body.targets,
                "mode": body.mode,
                "scanner": body.scanner,
                "schedule_id": schedule_id,
                "allow_overlap": allow_overlap,
            }
        )
        or 902,
    )

    schedules = api_client.get("/api/schedules", headers=AUTH_HEADERS)
    created = api_client.post(
        "/api/schedules",
        headers=AUTH_HEADERS,
        json={
            "targets": "example.com",
            "mode": 2,
            "scan_name": "Weekly perimeter",
            "interval_minutes": 10080,
        },
    )
    toggled = api_client.patch("/api/schedules/11", headers=AUTH_HEADERS, json={"enabled": False})
    run_now = api_client.post("/api/schedules/11/run", headers=AUTH_HEADERS)
    deleted = api_client.delete("/api/schedules/11", headers=AUTH_HEADERS)

    assert schedules.status_code == 200
    assert schedules.json()["items"][0]["scan_name"] == "Weekly perimeter"
    assert created.status_code == 200
    assert created.json()["schedule_id"] == 12
    assert created_schedule["org_db"] == "tenant_db"
    assert created_schedule["targets"] == "example.com"
    assert created_schedule["scan_mode"] == "2"
    assert created_schedule["interval_minutes"] == 10080
    assert toggled.json() == {"ok": True, "schedule_id": 11, "enabled": False}
    assert run_now.json() == {"ok": True, "scan_id": 902}
    assert run_queue == {
        "org_db": "tenant_db",
        "targets": "example.com",
        "mode": 2,
        "scanner": None,
        "schedule_id": 11,
        "allow_overlap": False,
    }
    assert deleted.json() == {"ok": True}


def test_notification_settings_routes(api_client, monkeypatch):
    updates = {}
    sent = {}

    monkeypatch.setattr(
        webapp,
        "get_notification_settings",
        lambda org_db: {
            "enabled": False,
            "recipients": "ops@example.org",
            "min_severity": "high",
            "notify_on_success": True,
            "notify_on_failure": True,
        },
    )
    monkeypatch.setattr(
        webapp,
        "update_notification_settings",
        lambda org_db, **kwargs: updates.update({"org_db": org_db, **kwargs}) or {"ok": True, **kwargs},
    )
    monkeypatch.setattr(
        webapp,
        "_send_email_notification",
        lambda org_db, subject, body, settings: sent.update(
            {"org_db": org_db, "subject": subject, "recipients": settings["recipients"]}
        ),
    )

    current = api_client.get("/api/notifications/settings", headers=AUTH_HEADERS)
    updated = api_client.patch(
        "/api/notifications/settings",
        headers=AUTH_HEADERS,
        json={
            "enabled": True,
            "recipients": "security@example.org",
            "min_severity": "critical",
            "notify_on_success": True,
            "notify_on_failure": False,
        },
    )
    test_send = api_client.post("/api/notifications/test", headers=AUTH_HEADERS)

    assert current.status_code == 200
    assert current.json()["recipients"] == "ops@example.org"
    assert updated.status_code == 200
    assert updates == {
        "org_db": "tenant_db",
        "enabled": True,
        "recipients": "security@example.org",
        "min_severity": "critical",
        "notify_on_success": True,
        "notify_on_failure": False,
    }
    assert test_send.status_code == 200
    assert sent == {
        "org_db": "tenant_db",
        "subject": "Darkstar test notification",
        "recipients": "ops@example.org",
    }
