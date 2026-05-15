import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from darkstar import webapp


pytestmark = pytest.mark.smoke


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(webapp, "list_organizations", lambda: [])
    monkeypatch.setattr(webapp, "scheduler_started", True)
    with TestClient(webapp.app) as test_client:
        yield test_client


def test_documentation_page_smoke(client):
    response = client.get("/documentation")

    assert response.status_code == 200
    assert "Darkstar Documentation" in response.text
    assert "Responsible and Authorized Use" in response.text
    assert "Tools and Licenses" in response.text
    assert "Sec/DevOps Pipeline" in response.text


def test_documentation_static_assets_smoke(client):
    css = client.get("/static/css/documentation.css")
    sidn = client.get("/static/logo_sidn.png")
    nlnet = client.get("/static/logo_nlnet.png")
    darkstar_logo = client.get("/logo_darkstar.png")

    assert css.status_code == 200
    assert "--bg: #ffffff" in css.text
    assert sidn.status_code == 200
    assert sidn.headers["content-type"] == "image/png"
    assert nlnet.status_code == 200
    assert nlnet.headers["content-type"] == "image/png"
    assert darkstar_logo.status_code == 200
    assert darkstar_logo.headers["content-type"] == "image/png"


def test_auth_and_status_routes_smoke(client, monkeypatch):
    monkeypatch.setattr(webapp, "authenticate_api_key", lambda token: None)

    me = client.get("/api/me")
    protected = client.get("/api/rest/status")
    openapi = client.get("/openapi.json")

    assert me.status_code == 200
    assert me.json()["authenticated"] is False
    assert protected.status_code == 401
    assert "Login or Bearer API key required" in protected.text
    assert openapi.status_code == 200
    assert "/documentation" in openapi.text
    assert "/api/scanner-workers/jobs/claim" in openapi.text
