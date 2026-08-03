"""Contract tests for the custom GMP-to-HTTP OpenVAS service."""

from pathlib import Path

import httpx
import pytest
import yaml
from fastapi import HTTPException
from fastapi.testclient import TestClient

from openvas_api import api
from openvas.openvas_connector import OpenVASAPIClient, OpenVASAPIError


REPO_ROOT = Path(__file__).resolve().parents[2]


class FakeGMP:
    def get_version(self):
        return '<get_version_response status="200"><version>22.8</version></get_version_response>'

    def get_targets(self):
        return """
        <get_targets_response status="200">
          <target id="target-1">
            <name>Example</name>
            <hosts>192.0.2.1, 192.0.2.2</hosts>
          </target>
        </get_targets_response>
        """

    def get_scanners(self):
        return """
        <get_scanners_response status="200">
          <scanner id="scanner-1"><name>OpenVAS Default</name></scanner>
        </get_scanners_response>
        """


@pytest.fixture
def api_client():
    def fake_gmp_dependency():
        yield FakeGMP()

    api.app.dependency_overrides[api.get_gmp] = fake_gmp_dependency
    with TestClient(api.app) as client:
        yield client
    api.app.dependency_overrides.clear()


def test_health_checks_authenticated_gmp(api_client):
    response = api_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "gvmd_socket": api.SOCK_PATH,
        "gmp_version": "22.8",
        "scanner_count": 1,
    }


def test_health_rejects_cve_only_scanner_registration():
    class CveOnlyGMP(FakeGMP):
        def get_scanners(self):
            return """
            <get_scanners_response status="200">
              <scanner id="scanner-cve"><name>CVE scanner</name></scanner>
            </get_scanners_response>
            """

    def fake_gmp_dependency():
        yield CveOnlyGMP()

    api.app.dependency_overrides[api.get_gmp] = fake_gmp_dependency
    try:
        with TestClient(api.app) as client:
            response = client.get("/health")
    finally:
        api.app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json()["detail"] == "No usable OpenVAS scanner registered"


def test_list_targets_parses_gvmd_hosts_text(api_client):
    response = api_client.get("/targets")

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": "target-1",
            "name": "Example",
            "hosts": ["192.0.2.1", "192.0.2.2"],
        }
    ]


def test_missing_gvmd_socket_returns_service_unavailable(mocker):
    mocker.patch.object(api.os.path, "exists", return_value=False)

    dependency = api.get_gmp()
    with pytest.raises(HTTPException) as error:
        next(dependency)

    assert error.value.status_code == 503
    assert api.SOCK_PATH in error.value.detail


def test_authentication_failure_returns_service_unavailable(mocker):
    class AuthenticationFailure:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def authenticate(self, _username, _password):
            raise api.GvmError("Authentication failed")

    mocker.patch.object(api.os.path, "exists", return_value=True)
    mocker.patch.object(api, "Gmp", AuthenticationFailure)

    dependency = api.get_gmp()
    with pytest.raises(HTTPException) as error:
        next(dependency)

    assert error.value.status_code == 503
    assert "Authentication failed" in error.value.detail


def test_client_preserves_api_error_detail():
    response = httpx.Response(
        503,
        json={"detail": "gvmd socket is not available"},
        request=httpx.Request("GET", "http://openvas-api:8008/health"),
    )

    with pytest.raises(OpenVASAPIError, match="gvmd socket is not available"):
        OpenVASAPIClient._raise_for_status(response)


def test_compose_waits_for_postgres_and_real_gvmd_socket():
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yaml").read_text())
    services = compose["services"]

    assert services["pg-gvm"]["depends_on"]["pg-gvm-migrator"] == {
        "condition": "service_completed_successfully"
    }
    assert "pg_isready" in services["pg-gvm"]["healthcheck"]["test"][1]
    assert services["gvmd"]["depends_on"]["pg-gvm"] == {
        "condition": "service_healthy"
    }
    # gvmd keeps its socket listening after losing PostgreSQL, so the health
    # probe has to make a request that actually needs the database.
    gvmd_healthcheck = services["gvmd"]["healthcheck"]["test"]
    assert gvmd_healthcheck[0] == "CMD-SHELL"
    assert "gvmd --get-scanners" in gvmd_healthcheck[1]


def test_long_running_gvm_services_restart_after_clean_exit():
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yaml").read_text())
    services = compose["services"]

    for service in ("redis-server", "pg-gvm", "gvmd", "openvasd", "ospd-openvas"):
        assert services[service]["restart"] == "unless-stopped"
