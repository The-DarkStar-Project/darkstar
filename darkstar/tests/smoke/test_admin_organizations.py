import pytest
from fastapi.testclient import TestClient

from darkstar import webapp


pytestmark = pytest.mark.smoke


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(webapp, "list_organizations", list)
    monkeypatch.setattr(webapp, "scheduler_started", True)
    monkeypatch.setattr(webapp, "record_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        webapp, "authenticate_api_key",
        lambda token: {"org_id": 1, "org_db_name": "org_home", "org_name": "Home", "role": token}
        if token in webapp.ROLE_RANK else None,
    )
    with TestClient(webapp.app) as client:
        yield client


def headers(role="platform_admin"):
    return {"Authorization": f"Bearer {role}"}


@pytest.mark.parametrize("role", [None, "tenant_admin", "security_analyst", "viewer"])
def test_only_platform_admin_can_create_organizations(client, mocker, role):
    create = mocker.patch.object(webapp, "create_organization")
    response = client.post("/api/admin/organizations", json={"name": "Acme"}, headers=headers(role) if role else {})
    assert response.status_code == (403 if role else 401)
    create.assert_not_called()


def test_platform_admin_creation_is_available_in_list(client, monkeypatch):
    organization = {"org_name": "Acme", "org_db_name": "org_acme", "role": "tenant_admin"}
    items = []

    def create(name):
        assert name == "Acme"
        items.append(organization)
        return organization

    monkeypatch.setattr(webapp, "create_organization", create)
    monkeypatch.setattr(webapp, "list_organizations", lambda: items)
    response = client.post("/api/admin/organizations", headers=headers(), json={"name": "Acme"})

    assert response.status_code == 201
    assert response.json() == {"ok": True, "organization": organization}
    assert client.get("/api/admin/organizations", headers=headers()).json() == {"items": [organization]}


@pytest.mark.parametrize("name", ["", None, "a" * 101])
def test_invalid_request_names_are_rejected(client, mocker, name):
    create = mocker.patch.object(webapp, "create_organization")
    response = client.post("/api/admin/organizations", headers=headers(), json={"name": name})
    assert response.status_code == 422
    create.assert_not_called()


@pytest.mark.parametrize(
    "error,status,detail",
    [
        (ValueError("Organization name is required"), 400, "Organization name is required"),
        (webapp.OrganizationAlreadyExistsError("Organization already exists"), 409, "Organization already exists"),
        (webapp.OrganizationConflictError("Organization is busy"), 409, "Organization is busy"),
        (RuntimeError("private database connection details"), 503, "Organization provisioning failed"),
    ],
)
def test_provisioning_errors_never_report_success(client, mocker, error, status, detail):
    mocker.patch.object(webapp, "create_organization", side_effect=error)
    audit = mocker.patch.object(webapp, "record_audit_event")
    response = client.post("/api/admin/organizations", headers=headers(), json={"name": "   "})
    assert response.status_code == status
    assert detail in response.json()["detail"]
    assert "private database connection details" not in response.text
    audit.assert_not_called()


@pytest.mark.parametrize("role", [None, "tenant_admin", "security_analyst", "viewer"])
def test_only_platform_admin_can_delete_organizations(client, mocker, role):
    delete = mocker.patch.object(webapp, "delete_organization")
    response = client.delete("/api/admin/organizations/7", headers=headers(role) if role else {})
    assert response.status_code == (403 if role else 401)
    delete.assert_not_called()


def test_platform_admin_deletion_is_audited_in_retained_organization(client, mocker):
    delete = mocker.patch.object(webapp, "delete_organization", return_value={"org_name": "Acme", "org_db_name": "org_acme"})
    audit = mocker.patch.object(webapp, "record_audit_event")
    response = client.delete("/api/admin/organizations/7", headers=headers())
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    delete.assert_called_once_with(7, active_org_db="org_home")
    audit.assert_called_once_with(
        "org_home", "organization.deleted", actor="api_key", entity_type="organization",
        entity_id="org_acme", metadata={"org_name": "Acme"},
    )


@pytest.mark.parametrize(
    "error,status",
    [(None, 404), (webapp.OrganizationConflictError("Stop scans first"), 409),
     (ValueError("Invalid identifier"), 400), (RuntimeError("private connection details"), 503)],
)
def test_deletion_errors_do_not_report_success_or_leak_details(client, mocker, error, status):
    mocker.patch.object(webapp, "delete_organization", side_effect=error, return_value=None)
    audit = mocker.patch.object(webapp, "record_audit_event")
    response = client.delete("/api/admin/organizations/7", headers=headers())
    assert response.status_code == status
    assert "private connection details" not in response.text
    audit.assert_not_called()
