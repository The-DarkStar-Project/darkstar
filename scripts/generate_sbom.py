#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM from repository manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import sys
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote


APPLICATION_REF = "pkg:github/The-DarkStar-Project/darkstar"
DEFAULT_OUTPUT = Path("docs/sbom/darkstar.cdx.json")
IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}


@dataclass
class ComponentRecord:
    component_type: str
    name: str
    ecosystem: str
    bom_ref: str
    purl: str | None = None
    version: str | None = None
    scope: str = "required"
    sources: set[str] = field(default_factory=set)
    specifiers: set[str] = field(default_factory=set)
    extras: set[str] = field(default_factory=set)
    properties: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    external_references: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def add_source(self, source: Path | str) -> None:
        self.sources.add(str(source))

    def to_cyclonedx(self) -> dict[str, object]:
        component: dict[str, object] = {
            "type": self.component_type,
            "bom-ref": self.bom_ref,
            "name": self.name,
            "scope": self.scope,
        }
        if self.version:
            component["version"] = self.version
        if self.purl:
            component["purl"] = self.purl

        properties: list[dict[str, str]] = [
            {"name": "darkstar:ecosystem", "value": self.ecosystem},
        ]
        for source in sorted(self.sources):
            properties.append({"name": "darkstar:sourceManifest", "value": source})
        for specifier in sorted(self.specifiers):
            properties.append({"name": "darkstar:versionSpecifier", "value": specifier})
        for extra in sorted(self.extras):
            properties.append({"name": "darkstar:extra", "value": extra})
        for name in sorted(self.properties):
            for value in sorted(self.properties[name]):
                properties.append({"name": name, "value": value})
        if properties:
            component["properties"] = properties

        external_references = []
        for reference_type in sorted(self.external_references):
            for url in sorted(self.external_references[reference_type]):
                external_references.append({"type": reference_type, "url": url})
        if external_references:
            component["externalReferences"] = external_references

        return component


class ComponentCatalog:
    def __init__(self) -> None:
        self._records: dict[str, ComponentRecord] = {}

    def add(self, record: ComponentRecord) -> ComponentRecord:
        existing = self._records.get(record.bom_ref)
        if existing is None:
            self._records[record.bom_ref] = record
            return record

        existing.sources.update(record.sources)
        existing.specifiers.update(record.specifiers)
        existing.extras.update(record.extras)
        for name, values in record.properties.items():
            existing.properties[name].update(values)
        for reference_type, urls in record.external_references.items():
            existing.external_references[reference_type].update(urls)
        return existing

    def to_components(self) -> list[dict[str, object]]:
        records = sorted(
            self._records.values(),
            key=lambda record: (
                record.ecosystem,
                record.name.lower(),
                record.version or "",
                record.bom_ref,
            ),
        )
        return [record.to_cyclonedx() for record in records]

    def refs(self) -> list[str]:
        return sorted(self._records)


def should_skip(path: Path) -> bool:
    return any(part in IGNORED_PARTS for part in path.parts)


def discover_files(root: Path, predicate) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if should_skip(rel) or not path.is_file():
            continue
        if predicate(rel):
            files.append(rel)
    return sorted(files)


def stable_ref(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def purl(package_type: str, name: str, version: str | None = None) -> str:
    safe_name = quote(name, safe="/._-+")
    if version:
        return f"pkg:{package_type}/{safe_name}@{quote(version, safe='._-+')}"
    return f"pkg:{package_type}/{safe_name}"


def normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def split_inline_comment(value: str) -> str:
    return re.sub(r"\s+#.*$", "", value).strip()


def parse_requirement_line(line: str) -> tuple[str, str | None, set[str], str] | None:
    stripped = split_inline_comment(line.strip())
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
        return None
    if stripped.startswith(("--index-url", "--extra-index-url", "--trusted-host")):
        return None

    if stripped.startswith(("-e ", "--editable ")):
        egg_match = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", stripped)
        if egg_match:
            return normalize_python_name(egg_match.group(1)), None, set(), stripped
        return None

    requirement, _, marker = stripped.partition(";")
    match = re.match(
        r"^\s*([A-Za-z0-9_.-]+)(?:\[([A-Za-z0-9_, .-]+)\])?\s*(.*)$",
        requirement.strip(),
    )
    if not match:
        return None

    name = normalize_python_name(match.group(1))
    extras = {
        normalize_python_name(extra.strip())
        for extra in (match.group(2) or "").split(",")
        if extra.strip()
    }
    specifier = match.group(3).strip()
    if marker.strip():
        specifier = f"{specifier}; {marker.strip()}".strip()
    exact_match = re.fullmatch(r"={2,3}\s*([^,\s]+)", match.group(3).strip())
    version = exact_match.group(1) if exact_match else None
    return name, version, extras, specifier


def add_python_requirement(
    catalog: ComponentCatalog,
    source: Path,
    requirement: tuple[str, str | None, set[str], str],
) -> None:
    name, version, extras, specifier = requirement
    package_purl = purl("pypi", name, version)
    bom_ref = package_purl
    record = ComponentRecord(
        component_type="library",
        name=name,
        ecosystem="pypi",
        version=version,
        bom_ref=bom_ref,
        purl=package_purl,
    )
    record.add_source(source)
    record.extras.update(extras)
    if specifier:
        record.specifiers.add(specifier)
    catalog.add(record)


def collect_requirements(root: Path, catalog: ComponentCatalog) -> None:
    requirement_files = discover_files(
        root,
        lambda path: path.name.startswith("requirements") and path.suffix == ".txt",
    )
    for rel_path in requirement_files:
        for line in (root / rel_path).read_text(encoding="utf-8").splitlines():
            requirement = parse_requirement_line(line)
            if requirement is not None:
                add_python_requirement(catalog, rel_path, requirement)


def collect_pyproject_dependencies(root: Path, catalog: ComponentCatalog) -> None:
    pyproject_files = discover_files(root, lambda path: path.name == "pyproject.toml")
    for rel_path in pyproject_files:
        data = tomllib.loads((root / rel_path).read_text(encoding="utf-8"))
        dependencies = list(data.get("project", {}).get("dependencies", []))
        for group_dependencies in data.get("dependency-groups", {}).values():
            dependencies.extend(group_dependencies)

        for dependency in dependencies:
            requirement = parse_requirement_line(str(dependency))
            if requirement is not None:
                add_python_requirement(catalog, rel_path, requirement)


def parse_go_mod(root: Path, rel_path: Path) -> dict[tuple[str, str], bool]:
    direct: dict[tuple[str, str], bool] = {}
    in_block = False
    for raw_line in (root / rel_path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line.removeprefix("require ").strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2:
            direct[(parts[0], parts[1])] = "// indirect" not in line
    return direct


def parse_go_sum(root: Path, rel_path: Path) -> dict[tuple[str, str], set[str]]:
    checksums: dict[tuple[str, str], set[str]] = defaultdict(set)
    for raw_line in (root / rel_path).read_text(encoding="utf-8").splitlines():
        parts = raw_line.split()
        if len(parts) != 3:
            continue
        module, version, checksum = parts
        version = version.removesuffix("/go.mod")
        checksums[(module, version)].add(checksum)
    return checksums


def collect_go_modules(root: Path, catalog: ComponentCatalog) -> None:
    go_mod_files = discover_files(root, lambda path: path.name == "go.mod")
    for go_mod_path in go_mod_files:
        module_sources = parse_go_mod(root, go_mod_path)
        go_sum_path = go_mod_path.with_name("go.sum")
        checksums = parse_go_sum(root, go_sum_path) if (root / go_sum_path).exists() else {}
        all_modules = sorted(set(module_sources) | set(checksums))
        for module, version in all_modules:
            module_purl = purl("golang", module, version)
            record = ComponentRecord(
                component_type="library",
                name=module,
                ecosystem="golang",
                version=version,
                bom_ref=module_purl,
                purl=module_purl,
            )
            record.add_source(go_mod_path)
            if (module, version) in checksums:
                record.add_source(go_sum_path)
            record.properties["darkstar:goDirect"].add(str(module_sources.get((module, version), False)).lower())
            for checksum in checksums.get((module, version), set()):
                record.properties["darkstar:goChecksum"].add(checksum)
            catalog.add(record)


def split_image_reference(image: str) -> tuple[str, str | None]:
    reference = image.split("@", 1)[0]
    last_segment = reference.rsplit("/", 1)[-1]
    if ":" in last_segment:
        name, version = reference.rsplit(":", 1)
        return name, version
    return reference, None


def add_container_image(catalog: ComponentCatalog, source: Path, image: str) -> None:
    name, version = split_image_reference(image)
    image_purl = purl("docker", name, version)
    record = ComponentRecord(
        component_type="container",
        name=name,
        ecosystem="docker",
        version=version,
        bom_ref=image_purl,
        purl=image_purl,
    )
    record.add_source(source)
    record.properties["darkstar:imageReference"].add(image)
    catalog.add(record)


def collect_compose_images(root: Path, catalog: ComponentCatalog) -> None:
    compose_files = discover_files(
        root,
        lambda path: path.name in {"docker-compose.yaml", "docker-compose.yml"}
        or path.name.startswith("compose.") and path.suffix in {".yaml", ".yml"},
    )
    for rel_path in compose_files:
        for line in (root / rel_path).read_text(encoding="utf-8").splitlines():
            match = re.match(r"^\s*image:\s*['\"]?([^'\"\s#]+)", line)
            if match:
                add_container_image(catalog, rel_path, match.group(1))


def collect_dockerfile_images(root: Path, catalog: ComponentCatalog) -> None:
    dockerfiles = discover_files(root, lambda path: path.name == "Dockerfile")
    for rel_path in dockerfiles:
        for line in (root / rel_path).read_text(encoding="utf-8").splitlines():
            match = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)", line, flags=re.IGNORECASE)
            if match:
                add_container_image(catalog, rel_path, match.group(1))


def collect_apt_packages(root: Path, catalog: ComponentCatalog) -> None:
    dockerfiles = discover_files(root, lambda path: path.name == "Dockerfile")
    for rel_path in dockerfiles:
        collecting = False
        for raw_line in (root / rel_path).read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not collecting and "apt-get install" not in line:
                continue
            if "apt-get install" in line:
                collecting = True
                line = line.split("apt-get install", 1)[1]

            line = line.split("&&", 1)[0].rstrip("\\").strip()
            try:
                tokens = shlex.split(line)
            except ValueError:
                tokens = line.split()
            for token in tokens:
                if token.startswith("-") or token in {"apt-get", "install"}:
                    continue
                if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:-]*", token):
                    package_purl = purl("deb/debian", token)
                    record = ComponentRecord(
                        component_type="operating-system",
                        name=token,
                        ecosystem="debian",
                        bom_ref=package_purl,
                        purl=package_purl,
                    )
                    record.add_source(rel_path)
                    catalog.add(record)

            if not raw_line.rstrip().endswith("\\"):
                collecting = False


def add_tool_component(
    catalog: ComponentCatalog,
    source: Path,
    name: str,
    ecosystem: str,
    package_type: str | None = None,
    version: str | None = None,
    installer: str | None = None,
    vcs_url: str | None = None,
) -> None:
    package_purl = purl(package_type, name, version) if package_type else None
    bom_ref = package_purl or stable_ref(f"tool:{ecosystem}", name, version or "", vcs_url or "")
    record = ComponentRecord(
        component_type="application",
        name=name,
        ecosystem=ecosystem,
        version=version,
        bom_ref=bom_ref,
        purl=package_purl,
    )
    record.add_source(source)
    if installer:
        record.properties["darkstar:installer"].add(installer)
    if vcs_url:
        record.external_references["vcs"].add(vcs_url)
    catalog.add(record)


def collect_dockerfile_tools(root: Path, catalog: ComponentCatalog) -> None:
    dockerfiles = discover_files(root, lambda path: path.name == "Dockerfile")
    for rel_path in dockerfiles:
        content = (root / rel_path).read_text(encoding="utf-8")
        for module, version in re.findall(r"\bgo\s+install\s+(\S+?)@([^\s&]+)", content):
            add_tool_component(
                catalog,
                rel_path,
                module,
                ecosystem="golang-tool",
                package_type="golang",
                version=version,
                installer="go install",
            )
        for package in re.findall(r"\bpipx\s+install\s+([A-Za-z0-9_.-]+)", content):
            add_tool_component(
                catalog,
                rel_path,
                normalize_python_name(package),
                ecosystem="pypi-tool",
                package_type="pypi",
                installer="pipx install",
            )
        for package in re.findall(r"\bcargo\s+install\s+([A-Za-z0-9_.-]+)", content):
            add_tool_component(
                catalog,
                rel_path,
                package,
                ecosystem="cargo-tool",
                package_type="cargo",
                installer="cargo install",
            )
        for url in re.findall(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", content):
            name = url.removesuffix(".git").rsplit("/", 1)[-1]
            add_tool_component(
                catalog,
                rel_path,
                name,
                ecosystem="git-tool",
                installer="git clone",
                vcs_url=url if url.endswith(".git") else f"{url}.git",
            )

        zap_version = re.search(r"^\s*ARG\s+ZAP_VERSION=([^\s]+)", content, flags=re.MULTILINE)
        if zap_version:
            add_tool_component(
                catalog,
                rel_path,
                "zaproxy",
                ecosystem="github-release",
                version=zap_version.group(1),
                installer="GitHub release archive",
                vcs_url="https://github.com/zaproxy/zaproxy.git",
            )


def build_sbom(root: Path) -> dict[str, object]:
    catalog = ComponentCatalog()
    collect_requirements(root, catalog)
    collect_pyproject_dependencies(root, catalog)
    collect_go_modules(root, catalog)
    collect_dockerfile_images(root, catalog)
    collect_compose_images(root, catalog)
    collect_apt_packages(root, catalog)
    collect_dockerfile_tools(root, catalog)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "darkstar-manifest-sbom-generator",
                        "version": "1.0.0",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": APPLICATION_REF,
                "name": "darkstar",
                "purl": APPLICATION_REF,
            },
            "properties": [
                {"name": "darkstar:generator", "value": "scripts/generate_sbom.py"},
                {"name": "darkstar:format", "value": "CycloneDX 1.5 JSON"},
                {
                    "name": "darkstar:coverage",
                    "value": "requirements.txt, pyproject.toml, Go modules, Docker images, Dockerfile-installed tools",
                },
                {
                    "name": "darkstar:deterministic",
                    "value": "true; timestamps and git commit identifiers are intentionally omitted",
                },
            ],
        },
        "components": catalog.to_components(),
        "dependencies": [
            {
                "ref": APPLICATION_REF,
                "dependsOn": catalog.refs(),
            }
        ],
    }


def render_sbom(root: Path) -> str:
    return json.dumps(build_sbom(root), indent=2, sort_keys=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if the committed SBOM is not current")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    output = args.output
    if not output.is_absolute():
        output = root / output

    rendered = render_sbom(root)
    if args.check:
        if not output.exists():
            print(f"{output} does not exist; run scripts/generate_sbom.py", file=sys.stderr)
            return 1
        current = output.read_text(encoding="utf-8")
        if current != rendered:
            print(f"{output} is out of date; run scripts/generate_sbom.py", file=sys.stderr)
            return 1
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"Wrote {output.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
