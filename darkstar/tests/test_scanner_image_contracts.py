from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_bbot_image_has_timezone_data_inside_and_outside_pipx():
    dockerfile = (REPOSITORY_ROOT / "docker" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "    tzdata \\\n" in dockerfile
    assert "pipx inject bbot tzdata" in dockerfile


def test_nuclei_templates_are_copied_into_runtime_image():
    dockerfile = (REPOSITORY_ROOT / "docker" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert (
        "COPY --from=go-builder /root/nuclei-templates /root/nuclei-templates/"
        in dockerfile
    )


def test_scanner_builds_use_pinned_versions():
    dockerfile = (REPOSITORY_ROOT / "docker" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "@latest" not in dockerfile
    for version_argument in (
        "ARG NUCLEI_VERSION=",
        "ARG KATANA_VERSION=",
        "ARG GAU_VERSION=",
        "ARG HTTPX_VERSION=",
        "ARG DALFOX_VERSION=",
        "ARG RUSTSCAN_VERSION=",
        "ARG BBOT_VERSION=",
        "ARG WAPITI_VERSION=",
        "ARG ZAP_VERSION=",
    ):
        assert version_argument in dockerfile


def test_application_services_share_one_scanner_image():
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "docker-compose.yaml").read_text(encoding="utf-8")
    )

    services = compose["services"]
    assert {
        services[name]["image"]
        for name in ("darkstar", "darkstar-web", "darkstar-scanner")
    } == {"darkstar-darkstar"}
