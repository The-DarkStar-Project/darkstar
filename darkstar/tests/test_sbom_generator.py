import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = REPO_ROOT / "scripts" / "generate_sbom.py"
SPEC = importlib.util.spec_from_file_location("generate_sbom", GENERATOR_PATH)
generate_sbom = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = generate_sbom
SPEC.loader.exec_module(generate_sbom)


def _component_by_ref(sbom):
    return {component["bom-ref"]: component for component in sbom["components"]}


def _property_values(component, name):
    return {
        prop["value"]
        for prop in component.get("properties", [])
        if prop["name"] == name
    }


def test_requirement_parser_handles_pins_extras_and_includes():
    assert generate_sbom.parse_requirement_line("PyJWT[crypto]==2.11.0  # auth") == (
        "pyjwt",
        "2.11.0",
        {"crypto"},
        "==2.11.0",
    )
    assert generate_sbom.parse_requirement_line("aiohttp>=3.11.18") == (
        "aiohttp",
        None,
        set(),
        ">=3.11.18",
    )
    assert generate_sbom.parse_requirement_line("-r requirements.txt") is None


def test_sbom_generation_is_deterministic_and_current():
    generated = generate_sbom.render_sbom(REPO_ROOT)
    assert generated == generate_sbom.render_sbom(REPO_ROOT)

    committed = (REPO_ROOT / "docs/sbom/darkstar.cdx.json").read_text(encoding="utf-8")
    assert json.loads(committed) == json.loads(generated)
    generated_json = json.loads(generated)
    assert "timestamp" not in generated_json["metadata"]
    assert "serialNumber" not in generated_json


def test_sbom_covers_declared_runtime_surfaces():
    sbom = generate_sbom.build_sbom(REPO_ROOT)
    components = _component_by_ref(sbom)

    expected_refs = {
        "pkg:pypi/pyjwt@2.11.0",
        "pkg:pypi/requests@2.34.1",
        "pkg:pypi/requests@2.32.4",
        "pkg:pypi/aiohttp",
        "pkg:golang/golang.org/x/sys@v0.32.0",
        "pkg:docker/ubuntu@22.04",
        "pkg:docker/mariadb@10.5",
        "pkg:deb/debian/openjdk-17-jre-headless",
        "pkg:golang/github.com/projectdiscovery/katana/cmd/katana@latest",
    }
    assert expected_refs <= set(components)
    assert any(
        component["name"] == "zaproxy" and component.get("version") == "2.16.0"
        for component in components.values()
    )

    pyjwt = components["pkg:pypi/pyjwt@2.11.0"]
    assert _property_values(pyjwt, "darkstar:extra") == {"crypto"}
    assert "requirements.txt" in _property_values(pyjwt, "darkstar:sourceManifest")

    go_sys = components["pkg:golang/golang.org/x/sys@v0.32.0"]
    assert "agents/darkstar-windows-agent/go.mod" in _property_values(
        go_sys,
        "darkstar:sourceManifest",
    )
    assert _property_values(go_sys, "darkstar:goDirect") == {"true"}

    dependencies = sbom["dependencies"][0]
    assert dependencies["ref"] == generate_sbom.APPLICATION_REF
    assert expected_refs <= set(dependencies["dependsOn"])
