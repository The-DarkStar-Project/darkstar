"""Darkstar endpoint inventory agent.

This is intentionally narrow: collect software inventory and send it to the
Darkstar orchestrator. It does not implement SIEM/FIM behavior.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests


AGENT_VERSION = "0.1.0"


def _parse_source_rpm(value: str | None) -> tuple[str | None, str | None]:
    source = str(value or "").strip()
    if source.endswith(".src.rpm"):
        source = source[:-8]
    if not source or "-" not in source:
        return source or None, None
    name, version, release = source.rsplit("-", 2)
    if not name or not version:
        return source, None
    full_version = f"{version}-{release}" if release else version
    return name, full_version


def _default_state_file() -> Path:
    path = Path("/var/lib/darkstar-endpoint/agent.json")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    except PermissionError:
        return Path.home() / ".darkstar-endpoint-agent.json"


def _run_json(command: list[str], timeout: int = 30) -> list[dict[str, Any]]:
    data = _run_json_value(command, timeout=timeout)
    return data if isinstance(data, list) else []


def _run_json_value(command: list[str], timeout: int = 30) -> Any:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def _powershell_json(script: str, timeout: int = 45) -> Any:
    powershell = shutil.which("powershell") or shutil.which("pwsh") or shutil.which("powershell.exe")
    if not powershell:
        return None
    return _run_json_value(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )


def _osquery(query: str) -> list[dict[str, Any]]:
    osqueryi = shutil.which("osqueryi")
    if not osqueryi:
        return []
    return _run_json([osqueryi, "--json", query])


def _command_lines(command: list[str], timeout: int = 30) -> list[str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def _purl_type_value(value: str) -> str:
    return quote(str(value or "").strip().lower(), safe=".-_+")


def _purl_version(value: str) -> str:
    return quote(str(value or "").strip(), safe=".-_+~:")


def _windows_build_version(row: dict[str, Any]) -> str | None:
    build = (
        row.get("build")
        or row.get("Build")
        or row.get("current_build_number")
        or row.get("CurrentBuildNumber")
    )
    ubr = row.get("ubr") or row.get("UBR")
    if not build:
        return None
    build_text = str(build).strip()
    if build_text.count(".") >= 2:
        return build_text
    parts = ["10", "0", build_text]
    if ubr not in (None, ""):
        parts.append(str(ubr).strip())
    return ".".join(parts)


def _windows_registry_os_info() -> dict[str, Any]:
    data = _powershell_json(
        "$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; "
        "[pscustomobject]@{"
        "ProductName=$cv.ProductName;"
        "EditionID=$cv.EditionID;"
        "DisplayVersion=$cv.DisplayVersion;"
        "ReleaseId=$cv.ReleaseId;"
        "CurrentBuildNumber=$cv.CurrentBuildNumber;"
        "UBR=$cv.UBR;"
        "InstallationType=$cv.InstallationType;"
        "BuildLabEx=$cv.BuildLabEx"
        "} | ConvertTo-Json -Compress",
        timeout=20,
    )
    if not isinstance(data, dict):
        return {}
    build = _windows_build_version(data)
    return {
        "platform": "windows",
        "name": data.get("ProductName") or platform.system(),
        "version": data.get("DisplayVersion") or data.get("ReleaseId") or platform.version(),
        "display_version": data.get("DisplayVersion"),
        "release_id": data.get("ReleaseId"),
        "build": build or platform.version(),
        "build_number": data.get("CurrentBuildNumber"),
        "ubr": data.get("UBR"),
        "installation_type": data.get("InstallationType"),
        "edition": data.get("EditionID"),
        "build_lab": data.get("BuildLabEx"),
    }


def _os_info() -> dict[str, Any]:
    rows = _osquery("select * from os_version;")
    row = rows[0] if rows else {}
    if platform.system().lower() == "windows":
        registry_row = _windows_registry_os_info()
        if registry_row:
            row = {**row, **{key: value for key, value in registry_row.items() if value not in (None, "")}}
    if not row and platform.system().lower() == "linux":
        try:
            release = platform.freedesktop_os_release()
            row = {
                "platform": release.get("ID"),
                "platform_like": release.get("ID_LIKE"),
                "name": release.get("NAME"),
                "version": release.get("VERSION_ID") or release.get("VERSION"),
                "codename": release.get("VERSION_CODENAME"),
            }
        except Exception:
            row = {}
    system_info = _osquery("select hostname, cpu_brand, hardware_vendor, hardware_model from system_info;")
    system = system_info[0] if system_info else {}
    return {
        "hostname": system.get("hostname") or socket.gethostname(),
        "platform": (row.get("platform") or platform.system()).lower(),
        "platform_like": row.get("platform_like"),
        "name": row.get("name") or platform.system(),
        "version": row.get("version") or platform.version(),
        "display_version": row.get("display_version") or row.get("DisplayVersion"),
        "release_id": row.get("release_id") or row.get("ReleaseId"),
        "codename": row.get("codename"),
        "arch": platform.machine(),
        "build": row.get("build") or _windows_build_version(row),
        "build_number": row.get("build_number") or row.get("CurrentBuildNumber"),
        "ubr": row.get("ubr") or row.get("UBR"),
        "installation_type": row.get("installation_type") or row.get("InstallationType"),
        "edition": row.get("edition") or row.get("EditionID"),
        "build_lab": row.get("build_lab") or row.get("BuildLabEx"),
        "major": row.get("major"),
        "minor": row.get("minor"),
        "hardware_vendor": system.get("hardware_vendor"),
        "hardware_model": system.get("hardware_model"),
    }


def _distro_namespace(os_info: dict[str, Any], fallback: str) -> str:
    platform_name = str(os_info.get("platform") or fallback or "").lower()
    if platform_name in {"ubuntu", "debian", "fedora", "centos", "rhel", "redhat", "almalinux", "rocky", "opensuse", "sles", "amazon"}:
        return platform_name
    return fallback


def _distro_qualifier(os_info: dict[str, Any]) -> str:
    name = str(os_info.get("platform") or os_info.get("name") or "").lower().replace(" ", "-")
    version = str(os_info.get("version") or "").split(" ", 1)[0]
    value = "-".join(part for part in [name, version] if part)
    return quote(value, safe=".-_+") if value else ""


def _deb_packages(os_info: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _osquery("select name, version, source, arch from deb_packages;")
    if not rows and shutil.which("dpkg-query"):
        for line in _command_lines([
            "dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n",
        ]):
            parts = line.split("\t")
            if len(parts) >= 3:
                rows.append({
                    "name": parts[0],
                    "version": parts[1],
                    "arch": parts[2],
                    "source_package": parts[3] if len(parts) > 3 else parts[0],
                    "source_version": parts[4] if len(parts) > 4 else parts[1],
                })
    namespace = _distro_namespace(os_info, "debian")
    distro = _distro_qualifier(os_info)
    software = []
    for row in rows:
        name = row.get("name")
        version = row.get("version")
        if not name or not version:
            continue
        qualifiers = []
        if row.get("arch"):
            qualifiers.append(f"arch={quote(str(row['arch']), safe='.-_+')}")
        if distro:
            qualifiers.append(f"distro={distro}")
        purl = f"pkg:deb/{namespace}/{_purl_type_value(name)}@{_purl_version(version)}"
        if qualifiers:
            purl += "?" + "&".join(qualifiers)
        software.append({
            "name": name,
            "version": version,
            "vendor": namespace,
            "ecosystem": "deb",
            "architecture": row.get("arch"),
            "source": "deb_packages",
            "package_type": "deb",
            "source_package": row.get("source_package") or row.get("source") or name,
            "source_version": row.get("source_version") or version,
            "purl": purl,
            "raw": row,
        })
    return software


def _rpm_packages(os_info: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _osquery("select name, version, release, arch, vendor, source from rpm_packages;")
    if not rows and shutil.which("rpm"):
        for line in _command_lines(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{SOURCERPM}\n"]):
            parts = line.split("\t")
            if len(parts) >= 5:
                rows.append({
                    "name": parts[0],
                    "version": parts[1],
                    "release": parts[2],
                    "arch": parts[3],
                    "vendor": parts[4],
                    "source": parts[5] if len(parts) > 5 else "",
                })
    namespace = _distro_namespace(os_info, "rpm")
    distro = _distro_qualifier(os_info)
    software = []
    for row in rows:
        name = row.get("name")
        version = row.get("version")
        if not name or not version:
            continue
        full_version = version
        if row.get("release"):
            full_version = f"{version}-{row['release']}"
        source_name, source_version = _parse_source_rpm(row.get("source"))
        qualifiers = []
        if row.get("arch"):
            qualifiers.append(f"arch={quote(str(row['arch']), safe='.-_+')}")
        if distro:
            qualifiers.append(f"distro={distro}")
        purl = f"pkg:rpm/{namespace}/{_purl_type_value(name)}@{_purl_version(full_version)}"
        if qualifiers:
            purl += "?" + "&".join(qualifiers)
        software.append({
            "name": name,
            "version": full_version,
            "vendor": row.get("vendor") or namespace,
            "ecosystem": "rpm",
            "architecture": row.get("arch"),
            "source": row.get("source") or "rpm_packages",
            "package_type": "rpm",
            "source_package": source_name or name,
            "source_version": source_version or full_version,
            "purl": purl,
            "raw": row,
        })
    return software


def _windows_program_rows() -> list[dict[str, Any]]:
    rows = _osquery("select name, version, publisher, install_location, identifying_number from programs;")
    if rows:
        return rows
    data = _powershell_json(
        "$paths = @("
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        "); "
        "$items = foreach ($path in $paths) { "
        "Get-ItemProperty $path -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object @{n='name';e={$_.DisplayName}},"
        "@{n='version';e={$_.DisplayVersion}},"
        "@{n='publisher';e={$_.Publisher}},"
        "@{n='install_location';e={$_.InstallLocation}},"
        "@{n='identifying_number';e={$_.PSChildName}}"
        "}; "
        "$items | ConvertTo-Json -Compress",
        timeout=60,
    )
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def _windows_patch_rows() -> list[dict[str, Any]]:
    rows = _osquery("select hotfix_id, caption, installed_on from patches;")
    if rows:
        return rows
    data = _powershell_json(
        "Get-HotFix | Select-Object "
        "@{n='hotfix_id';e={$_.HotFixID}},"
        "@{n='caption';e={$_.Description}},"
        "@{n='installed_on';e={$_.InstalledOn}} | ConvertTo-Json -Compress",
        timeout=60,
    )
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def _windows_programs(os_info: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _windows_program_rows()
    software = []
    os_version = os_info.get("build") or os_info.get("version")
    software.append({
        "name": os_info.get("name") or "Microsoft Windows",
        "version": os_version,
        "vendor": "Microsoft",
        "ecosystem": "windows_os",
        "architecture": os_info.get("arch"),
        "source": "windows_registry",
        "package_type": "windows_os",
        "purl": f"pkg:generic/microsoft/windows@{_purl_version(os_version)}" if os_version else None,
        "raw": os_info,
    })
    for row in rows:
        if not row.get("name"):
            continue
        software.append({
            "name": row.get("name"),
            "version": row.get("version"),
            "vendor": row.get("publisher"),
            "ecosystem": "windows_program",
            "install_location": row.get("install_location"),
            "source": "programs",
            "package_type": "windows_program",
            "raw": row,
        })
    for row in _windows_patch_rows():
        hotfix = row.get("hotfix_id")
        if not hotfix:
            continue
        software.append({
            "name": hotfix,
            "version": row.get("installed_on"),
            "vendor": "Microsoft",
            "ecosystem": "windows_kb",
            "source": "patches",
            "package_type": "windows_kb",
            "raw": row,
        })
    return software


def _macos_apps() -> list[dict[str, Any]]:
    software = []
    for row in _osquery("select name, bundle_identifier, bundle_short_version, bundle_version, path from apps;"):
        if not row.get("name"):
            continue
        software.append({
            "name": row.get("name"),
            "version": row.get("bundle_short_version") or row.get("bundle_version"),
            "vendor": row.get("bundle_identifier"),
            "ecosystem": "macos_app",
            "install_location": row.get("path"),
            "source": "apps",
            "package_type": "macos_app",
            "raw": row,
        })
    if shutil.which("brew"):
        for line in _command_lines(["brew", "list", "--versions", "--formula"]):
            parts = line.split()
            if len(parts) >= 2:
                name, version = parts[0], parts[1]
                software.append({
                    "name": name,
                    "version": version,
                    "vendor": "homebrew",
                    "ecosystem": "brew",
                    "source": "brew",
                    "package_type": "brew",
                    "purl": f"pkg:brew/{_purl_type_value(name)}@{_purl_version(version)}",
                    "raw": {"line": line},
                })
    return software


def _python_packages() -> list[dict[str, Any]]:
    command = [sys.executable, "-m", "pip", "list", "--format=json"]
    rows = _run_json(command, timeout=45)
    software = []
    for row in rows:
        name = row.get("name")
        version = row.get("version")
        if not name or not version:
            continue
        software.append({
            "name": name,
            "version": version,
            "vendor": "pypi",
            "ecosystem": "pypi",
            "source": "pip_current_python",
            "package_type": "pypi",
            "purl": f"pkg:pypi/{_purl_type_value(name)}@{_purl_version(version)}",
            "raw": row,
        })
    return software


def _npm_purl(name: str, version: str) -> str:
    package = str(name or "").strip()
    if package.startswith("@") and "/" in package:
        namespace, package_name = package.split("/", 1)
        return f"pkg:npm/{_purl_type_value(namespace)}/{_purl_type_value(package_name)}@{_purl_version(version)}"
    return f"pkg:npm/{_purl_type_value(package)}@{_purl_version(version)}"


def _npm_global_packages() -> list[dict[str, Any]]:
    if not shutil.which("npm"):
        return []
    data = _run_json_value(["npm", "list", "-g", "--depth=0", "--json"], timeout=45) or {}
    dependencies = data.get("dependencies") if isinstance(data, dict) else {}
    if not isinstance(dependencies, dict):
        return []
    software = []
    for name, row in dependencies.items():
        if not isinstance(row, dict):
            continue
        version = row.get("version")
        if not name or not version:
            continue
        software.append({
            "name": name,
            "version": version,
            "vendor": "npm",
            "ecosystem": "npm",
            "source": "npm_global",
            "package_type": "npm",
            "purl": _npm_purl(name, version),
            "raw": row,
        })
    return software


def _network_ids() -> tuple[list[str], list[str]]:
    rows = _osquery("select address, mac from interface_addresses join interface_details using (interface) where address not like '127.%' and address != '::1';")
    ips, macs = [], []
    for row in rows:
        if row.get("address") and row["address"] not in ips:
            ips.append(row["address"])
        if row.get("mac") and row["mac"] not in macs and row["mac"] != "00:00:00:00:00:00":
            macs.append(row["mac"])
    return ips, macs


def collect_inventory() -> dict[str, Any]:
    os_info = _os_info()
    system = platform.system().lower()
    software = []
    if system == "windows":
        software.extend(_windows_programs(os_info))
    elif system == "darwin":
        software.extend(_macos_apps())
    else:
        software.extend(_deb_packages(os_info))
        software.extend(_rpm_packages(os_info))
    software.extend(_python_packages())
    software.extend(_npm_global_packages())
    ips, macs = _network_ids()
    return {
        "os": os_info,
        "software": software,
        "ip_addresses": ips,
        "mac_addresses": macs,
        "metadata": {
            "hostname": os_info.get("hostname") or socket.gethostname(),
            "collector": "darkstar_endpoint_agent",
            "collector_version": AGENT_VERSION,
            "osquery": bool(shutil.which("osqueryi")),
        },
    }


def _load_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def register(base_url: str, org: str, enrollment_token: str, inventory: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "organization": org,
        "enrollment_token": enrollment_token,
        "hostname": inventory.get("metadata", {}).get("hostname") or socket.gethostname(),
        "os": inventory.get("os") or {},
        "agent_version": AGENT_VERSION,
        "metadata": inventory.get("metadata") or {},
    }
    response = requests.post(f"{base_url.rstrip('/')}/api/endpoint-agents/register", json=payload, timeout=30)
    response.raise_for_status()
    return response.json()


def send_inventory(base_url: str, agent_token: str, inventory: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(
        f"{base_url.rstrip('/')}/api/endpoint-agents/inventory",
        json=inventory,
        headers={"Authorization": f"Bearer {agent_token}"},
        timeout=120,
    )
    response.raise_for_status()
    return response.json()


def run_once(args: argparse.Namespace) -> dict[str, Any]:
    state_file = Path(args.state_file) if args.state_file else _default_state_file()
    state = _load_state(state_file)
    inventory = collect_inventory()
    agent_token = args.agent_token or state.get("agent_token")
    if not agent_token:
        if not args.org or not args.enrollment_token:
            raise SystemExit("--org and --enrollment-token are required for first registration")
        registration = register(args.url, args.org, args.enrollment_token, inventory)
        agent_token = registration["agent_token"]
        state.update({
            "agent_id": registration["agent_id"],
            "agent_token": agent_token,
            "org_db": registration.get("org_db") or args.org,
            "url": args.url,
        })
        _save_state(state_file, state)
    return send_inventory(args.url, agent_token, inventory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Darkstar endpoint inventory agent")
    parser.add_argument("--url", help="Darkstar orchestrator URL")
    parser.add_argument("--org", help="Tenant/org database name for first enrollment")
    parser.add_argument("--enrollment-token", help="One-time enrollment token")
    parser.add_argument("--agent-token", help="Existing endpoint agent token")
    parser.add_argument("--state-file", help="Path for persisted agent token")
    parser.add_argument("--interval", type=int, default=3600, help="Inventory interval in seconds")
    parser.add_argument("--once", action="store_true", help="Collect and send one inventory snapshot")
    parser.add_argument("--print-inventory", action="store_true", help="Print inventory JSON and exit")
    args = parser.parse_args(argv)

    if args.print_inventory:
        try:
            print(json.dumps(collect_inventory(), indent=2))
        except BrokenPipeError:
            return 0
        return 0
    if not args.url:
        raise SystemExit("--url is required unless --print-inventory is used")

    while True:
        try:
            result = run_once(args)
            print(json.dumps(result))
        except Exception as exc:
            print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(max(60, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
