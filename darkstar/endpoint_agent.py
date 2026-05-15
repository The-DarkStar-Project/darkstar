"""Darkstar endpoint inventory agent.

This is intentionally narrow: collect software inventory and send it to the
Darkstar orchestrator. It does not implement SIEM/FIM behavior.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import glob
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests


AGENT_VERSION = "0.2.1"
NETWORK_PROBE_VERSION = 1
SECURITY_CHECK_SCHEMA_VERSION = 1
POSTURE_SOFTWARE_KEY = "darkstar-security-posture"
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
DEFAULT_FINGERPRINT_PORTS = [22, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443, 62078]


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
    if not ips:
        for iface in _local_interfaces():
            name = str(iface.get("name") or "")
            if name.startswith(("br-", "docker", "veth", "virbr")):
                continue
            ip = iface.get("ip")
            mac = iface.get("mac")
            if ip and ip not in ips:
                ips.append(ip)
            if mac and mac not in macs and mac != "00:00:00:00:00:00":
                macs.append(mac)
    return ips, macs


def _safe_ip(value: str | None):
    try:
        return ipaddress.ip_address(str(value or "").split("%", 1)[0])
    except ValueError:
        return None


def _is_probe_ip(value: str | None) -> bool:
    ip = _safe_ip(value)
    if not ip:
        return False
    if ip.version != 4:
        return False
    return bool(ip.is_private or ip.is_link_local or ip in CGNAT_NETWORK) and not bool(
        ip.is_loopback or ip.is_multicast or ip.is_unspecified
    )


def _local_interfaces() -> list[dict[str, Any]]:
    interfaces: list[dict[str, Any]] = []
    routes = _local_routes()
    gateways_by_interface = {
        str(route.get("interface") or ""): route.get("gateway")
        for route in routes
        if route.get("gateway")
    }
    data = _run_json_value(["ip", "-j", "addr", "show"], timeout=8) if shutil.which("ip") else None
    if isinstance(data, list):
        for iface in data:
            if not isinstance(iface, dict):
                continue
            flags = {str(flag).upper() for flag in iface.get("flags") or []}
            if "LOOPBACK" in flags or "UP" not in flags:
                continue
            name = iface.get("ifname")
            mac = iface.get("address")
            for addr in iface.get("addr_info") or []:
                if addr.get("family") != "inet":
                    continue
                ip_text = addr.get("local")
                ip = _safe_ip(ip_text)
                if not ip or ip.is_loopback or ip.is_multicast:
                    continue
                prefix = int(addr.get("prefixlen") or 32)
                try:
                    network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                    cidr = str(network)
                except ValueError:
                    cidr = None
                interfaces.append({
                    "name": name,
                    "ip": str(ip),
                    "cidr": cidr,
                    "prefixlen": prefix,
                    "mac": mac,
                    "gateway": gateways_by_interface.get(str(name)),
                    "family": "ipv4",
                    "scope": addr.get("scope"),
                    "private": _is_probe_ip(str(ip)),
                })
    return interfaces


def _local_routes() -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    data = _run_json_value(["ip", "-j", "route", "show"], timeout=8) if shutil.which("ip") else None
    if isinstance(data, list):
        for route in data:
            if not isinstance(route, dict):
                continue
            routes.append({
                "destination": route.get("dst") or "default",
                "gateway": route.get("gateway"),
                "interface": route.get("dev"),
                "protocol": route.get("protocol"),
                "metric": route.get("metric"),
            })
    return routes


def _network_for_ip(ip_text: str | None, interfaces: list[dict[str, Any]]) -> str | None:
    ip = _safe_ip(ip_text)
    if not ip:
        return None
    for iface in interfaces:
        cidr = iface.get("cidr")
        if not cidr:
            continue
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return cidr
        except ValueError:
            continue
    return None


def _neighbors(interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    data = _run_json_value(["ip", "-j", "neigh", "show"], timeout=8) if shutil.which("ip") else None
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            ip_text = item.get("dst")
            mac = item.get("lladdr")
            raw_state = item.get("state")
            state = " ".join(raw_state) if isinstance(raw_state, list) else raw_state
            if not _is_probe_ip(ip_text):
                continue
            if str(state or "").upper() == "FAILED":
                continue
            key = (str(ip_text), str(mac or ""))
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "ip": str(ip_text),
                "mac": mac,
                "interface": item.get("dev"),
                "state": state,
                "source": "arp_neighbor",
                "network_cidr": _network_for_ip(str(ip_text), interfaces),
            })
    elif shutil.which("arp"):
        arp_line = re.compile(r"\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:.-]+)")
        for line in _command_lines(["arp", "-an"], timeout=8):
            match = arp_line.search(line)
            if not match:
                continue
            ip_text = match.group("ip")
            mac = match.group("mac")
            if not _is_probe_ip(ip_text):
                continue
            rows.append({
                "ip": ip_text,
                "mac": mac,
                "source": "arp_cache",
                "network_cidr": _network_for_ip(ip_text, interfaces),
            })
    return rows


def _public_ip() -> str | None:
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=4)
        if response.ok:
            value = response.json().get("ip")
            return str(value) if value else None
    except Exception:
        return None
    return None


def _tcp_port_open(ip_text: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((ip_text, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _open_ports_for_target(ip_text: str, ports: list[int]) -> list[int]:
    open_ports: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(ports)))) as executor:
        futures = {executor.submit(_tcp_port_open, ip_text, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                continue
    return sorted(open_ports)


def _ping_once(ip_text: str) -> tuple[bool, int | None]:
    if not shutil.which("ping"):
        return False, None
    system = platform.system().lower()
    command = ["ping", "-n", "-c", "1", "-W", "1", ip_text]
    if system == "darwin":
        command = ["ping", "-n", "-c", "1", "-W", "1000", ip_text]
    start = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=2, check=False)
        latency = max(1, int((time.time() - start) * 1000))
        return result.returncode == 0, latency if result.returncode == 0 else None
    except Exception:
        return False, None


def _fingerprint_device(target: dict[str, Any]) -> dict[str, Any]:
    ports = set(int(port) for port in target.get("open_ports") or [])
    hostname = str(target.get("hostname") or "").lower()
    ip_text = str(target.get("ip") or "")
    device_type = "unknown"
    os_family = None
    confidence = 35 if ports else 20

    if target.get("peer_agent_id"):
        device_type = "endpoint"
        os_family = target.get("os_platform")
        confidence = 85 if target.get("reachable") else 60
    elif ports & {135, 139, 445, 3389}:
        device_type = "endpoint"
        os_family = "windows"
        confidence = 80
    elif 22 in ports:
        device_type = "server"
        os_family = "linux/unix"
        confidence = 65
    elif 62078 in ports or any(marker in hostname for marker in ["iphone", "ipad", "android"]):
        device_type = "phone"
        os_family = "mobile"
        confidence = 65
    elif target.get("gateway") or (53 in ports and ports & {80, 443, 8080, 8443}):
        device_type = "router"
        os_family = "network"
        confidence = 70
    elif ports & {80, 443, 8080, 8443}:
        device_type = "web_service"
        confidence = 55

    if ip_text.endswith(".1") and device_type == "unknown":
        device_type = "router"
        os_family = "network"
        confidence = 45

    target["device_type"] = device_type
    target["os_family"] = os_family
    target["confidence"] = confidence
    target["protocols"] = [f"tcp/{port}" for port in sorted(ports)]
    return target


def collect_network_probe(peer_targets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    interfaces = _local_interfaces()
    routes = _local_routes()
    public_ip = _public_ip()
    neighbors = _neighbors(interfaces)
    self_ips = {iface.get("ip") for iface in interfaces if iface.get("ip")}
    max_targets = max(4, min(int(os.environ.get("ENDPOINT_NETWORK_PROBE_MAX_TARGETS", "48")), 256))
    ports = DEFAULT_FINGERPRINT_PORTS

    targets: dict[str, dict[str, Any]] = {}
    for neighbor in neighbors:
        ip_text = neighbor.get("ip")
        if ip_text and ip_text not in self_ips:
            targets[ip_text] = dict(neighbor)
    for iface in interfaces:
        gateway = iface.get("gateway")
        if gateway and _is_probe_ip(gateway) and gateway not in self_ips:
            targets.setdefault(gateway, {
                "ip": gateway,
                "source": "default_gateway",
                "gateway": True,
                "interface": iface.get("name"),
                "network_cidr": iface.get("cidr"),
            })
    peer_checks: list[dict[str, Any]] = []
    for peer in peer_targets or []:
        ip_text = str(peer.get("ip") or "").strip()
        if not _is_probe_ip(ip_text) or ip_text in self_ips:
            continue
        target = targets.setdefault(ip_text, {
            "ip": ip_text,
            "source": "endpoint_peer",
            "network_cidr": _network_for_ip(ip_text, interfaces),
        })
        target["peer_agent_id"] = peer.get("agent_id")
        target["os_platform"] = peer.get("os_platform")
        target["hostname"] = target.get("hostname") or peer.get("hostname")
        if target.get("source") != "endpoint_peer":
            target["source"] = f"{target.get('source') or 'observed'}+endpoint_peer"

    selected_targets = list(targets.values())[:max_targets]

    def probe(item: dict[str, Any]) -> dict[str, Any]:
        ip_text = str(item.get("ip") or "")
        open_ports = _open_ports_for_target(ip_text, ports)
        item["open_ports"] = open_ports
        item["reachability"] = "open_tcp" if open_ports else str(item.get("state") or "seen")
        if item.get("peer_agent_id"):
            ping_ok, latency = _ping_once(ip_text)
            item["reachable"] = bool(open_ports or ping_ok)
            item["latency_ms"] = latency
        return _fingerprint_device(item)

    observations: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, max(1, len(selected_targets)))) as executor:
        for item in executor.map(probe, selected_targets):
            observations.append(item)
            if item.get("peer_agent_id"):
                peer_checks.append({
                    "agent_id": item.get("peer_agent_id"),
                    "hostname": item.get("hostname"),
                    "ip": item.get("ip"),
                    "reachable": bool(item.get("reachable")),
                    "method": "tcp_connect+icmp_ping",
                    "latency_ms": item.get("latency_ms"),
                    "open_ports": item.get("open_ports") or [],
                })

    return {
        "version": NETWORK_PROBE_VERSION,
        "collected_at": datetime_utc_iso(),
        "public_ip": public_ip,
        "interfaces": interfaces,
        "routes": routes,
        "neighbors": observations,
        "peer_checks": peer_checks,
        "limits": {
            "max_targets": max_targets,
            "ports": ports,
            "mode": "neighbor-cache+gateway+endpoint-peers",
        },
    }


def _failed_security_check(check_id: str, evidence: dict[str, Any] | None = None, confidence: int = 90) -> dict[str, Any]:
    return {
        "id": check_id,
        "passed": False,
        "confidence": confidence,
        "evidence": evidence or {},
    }


def _read_text_file(path: str, max_bytes: int = 1024 * 1024) -> str | None:
    try:
        file_path = Path(path)
        if not file_path.is_file() or file_path.stat().st_size > max_bytes:
            return None
        return file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def _safe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _parse_login_defs(path: str = "/etc/login.defs") -> dict[str, str]:
    values: dict[str, str] = {}
    text = _read_text_file(path, max_bytes=256 * 1024)
    if not text:
        return values
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            values[parts[0].upper()] = parts[1].strip()
    return values


def _parse_pwquality(path: str = "/etc/security/pwquality.conf") -> dict[str, str]:
    values: dict[str, str] = {}
    text = _read_text_file(path, max_bytes=256 * 1024)
    if not text:
        return values
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip().lower()] = value.strip()
    return values


def _sshd_config_lines(path: str = "/etc/ssh/sshd_config", seen: set[str] | None = None, depth: int = 0):
    seen = seen or set()
    if depth > 4:
        return
    try:
        real_path = str(Path(path).resolve())
    except Exception:
        real_path = path
    if real_path in seen:
        return
    seen.add(real_path)
    text = _read_text_file(path, max_bytes=1024 * 1024)
    if not text:
        return
    base_dir = str(Path(path).parent)
    in_match_block = False
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        directive = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if directive == "match":
            in_match_block = True
            continue
        if in_match_block:
            continue
        if directive == "include":
            for pattern in value.split():
                expanded = pattern if pattern.startswith("/") else str(Path(base_dir) / pattern)
                for include_path in sorted(glob.glob(expanded)):
                    yield from _sshd_config_lines(include_path, seen=seen, depth=depth + 1)
            continue
        yield path, lineno, directive, value


def _linux_ssh_checks() -> list[dict[str, Any]]:
    settings: dict[str, tuple[str, str, int]] = {}
    for path, lineno, directive, value in _sshd_config_lines() or []:
        settings[directive] = (value.strip().lower(), path, lineno)

    checks: list[dict[str, Any]] = []
    root_login = settings.get("permitrootlogin")
    if root_login and root_login[0] == "yes":
        checks.append(_failed_security_check(
            "DARKSTAR-LINUX-SSH-ROOT-LOGIN",
            {"effective_value": root_login[0], "source": root_login[1], "line": root_login[2]},
        ))
    password_auth = settings.get("passwordauthentication")
    if password_auth and password_auth[0] == "yes":
        checks.append(_failed_security_check(
            "DARKSTAR-LINUX-SSH-PASSWORD-AUTH",
            {"effective_value": password_auth[0], "source": password_auth[1], "line": password_auth[2]},
        ))
    empty_passwords = settings.get("permitemptypasswords")
    if empty_passwords and empty_passwords[0] == "yes":
        checks.append(_failed_security_check(
            "DARKSTAR-LINUX-SSH-EMPTY-PASSWORDS",
            {"effective_value": empty_passwords[0], "source": empty_passwords[1], "line": empty_passwords[2]},
            confidence=95,
        ))
    return checks


def _linux_sudo_checks() -> list[dict[str, Any]]:
    paths = ["/etc/sudoers"]
    paths.extend(sorted(glob.glob("/etc/sudoers.d/*")))
    examples: list[dict[str, Any]] = []
    for path in paths:
        try:
            if not Path(path).is_file():
                continue
        except Exception:
            continue
        text = _read_text_file(path, max_bytes=1024 * 1024)
        if not text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "NOPASSWD" in stripped.upper():
                examples.append({"source": path, "line": lineno})
    if not examples:
        return []
    return [_failed_security_check(
        "DARKSTAR-LINUX-SUDO-NOPASSWD",
        {"entry_count": len(examples), "examples": examples[:10]},
    )]


def _linux_shadow_checks() -> list[dict[str, Any]]:
    text = _read_text_file("/etc/shadow", max_bytes=2 * 1024 * 1024)
    if not text:
        return []
    empty_count = 0
    weak_algorithms: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        password_field = parts[1]
        if password_field == "":
            empty_count += 1
            continue
        if password_field.startswith(("!", "*")):
            continue
        if password_field.startswith("$1$"):
            weak_algorithms["md5"] = weak_algorithms.get("md5", 0) + 1
        elif password_field and not password_field.startswith("$"):
            weak_algorithms["des"] = weak_algorithms.get("des", 0) + 1

    checks: list[dict[str, Any]] = []
    if empty_count:
        checks.append(_failed_security_check(
            "DARKSTAR-LINUX-EMPTY-PASSWORD",
            {"account_count": empty_count, "source": "/etc/shadow", "hashes_collected": False},
            confidence=95,
        ))
    if weak_algorithms:
        checks.append(_failed_security_check(
            "DARKSTAR-LINUX-WEAK-PASSWORD-HASH",
            {"algorithm_counts": weak_algorithms, "source": "/etc/shadow", "hashes_collected": False},
        ))
    return checks


def _linux_passwd_uid0_checks() -> list[dict[str, Any]]:
    text = _read_text_file("/etc/passwd", max_bytes=1024 * 1024)
    if not text:
        return []
    accounts = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 3:
            continue
        if parts[0] != "root" and _safe_int(parts[2]) == 0:
            accounts.append(parts[0])
    if not accounts:
        return []
    return [_failed_security_check(
        "DARKSTAR-LINUX-UID0-EXTRA-ACCOUNT",
        {"account_count": len(accounts), "accounts": accounts[:20], "source": "/etc/passwd"},
    )]


def _linux_sensitive_permission_checks() -> list[dict[str, Any]]:
    unsafe = []
    checks = [
        ("/etc/passwd", stat.S_IWGRP | stat.S_IWOTH, "group_or_world_writable"),
        ("/etc/shadow", stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH, "world_readable_or_group_world_writable"),
        ("/etc/sudoers", stat.S_IWGRP | stat.S_IWOTH, "group_or_world_writable"),
    ]
    for path, mask, reason in checks:
        try:
            mode = os.stat(path).st_mode
        except Exception:
            continue
        if mode & mask:
            unsafe.append({"path": path, "mode": oct(stat.S_IMODE(mode)), "reason": reason})
    if not unsafe:
        return []
    return [_failed_security_check(
        "DARKSTAR-LINUX-SENSITIVE-FILE-PERMISSIONS",
        {"files": unsafe},
        confidence=95,
    )]


def _linux_world_writable_path_checks() -> list[dict[str, Any]]:
    path_values = (os.environ.get("PATH") or "").split(os.pathsep)
    path_values.extend(["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"])
    unsafe = []
    seen = set()
    for path in path_values:
        if not path or path in seen:
            continue
        seen.add(path)
        try:
            mode = os.stat(path).st_mode
        except Exception:
            continue
        if stat.S_ISDIR(mode) and mode & stat.S_IWOTH:
            unsafe.append({"path": path, "mode": oct(stat.S_IMODE(mode))})
    if not unsafe:
        return []
    return [_failed_security_check(
        "DARKSTAR-LINUX-WORLD-WRITABLE-PATH",
        {"directories": unsafe[:20]},
    )]


def _linux_root_equivalent_group_checks() -> list[dict[str, Any]]:
    text = _read_text_file("/etc/group", max_bytes=1024 * 1024)
    if not text:
        return []
    risky_groups = {"docker", "lxd", "libvirt", "podman"}
    groups = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 4 or parts[0] not in risky_groups:
            continue
        members = [member for member in parts[3].split(",") if member]
        if members:
            groups.append({"group": parts[0], "member_count": len(members), "members": members[:20]})
    if not groups:
        return []
    return [_failed_security_check(
        "DARKSTAR-LINUX-ROOT-EQUIVALENT-GROUP",
        {"groups": groups},
    )]


def _linux_password_policy_checks() -> list[dict[str, Any]]:
    login_defs = _parse_login_defs()
    pwquality = _parse_pwquality()
    weak = []
    min_len = _safe_int(login_defs.get("PASS_MIN_LEN"))
    if min_len is not None and min_len < 12:
        weak.append({"setting": "PASS_MIN_LEN", "value": min_len, "baseline": 12})
    max_days = _safe_int(login_defs.get("PASS_MAX_DAYS"))
    if max_days is not None and (max_days <= 0 or max_days > 90):
        weak.append({"setting": "PASS_MAX_DAYS", "value": max_days, "baseline": 90})
    min_days = _safe_int(login_defs.get("PASS_MIN_DAYS"))
    if min_days is not None and min_days < 1:
        weak.append({"setting": "PASS_MIN_DAYS", "value": min_days, "baseline": 1})
    quality_min_len = _safe_int(pwquality.get("minlen"))
    if quality_min_len is not None and quality_min_len < 12:
        weak.append({"setting": "pwquality.minlen", "value": quality_min_len, "baseline": 12})
    if not weak:
        return []
    return [_failed_security_check(
        "DARKSTAR-LINUX-PASSWORD-POLICY-WEAK",
        {"weak_settings": weak, "sources": ["/etc/login.defs", "/etc/security/pwquality.conf"]},
    )]


def _linux_suid_coredump_checks() -> list[dict[str, Any]]:
    value = (_read_text_file("/proc/sys/fs/suid_dumpable", max_bytes=32) or "").strip()
    if value not in {"1", "2"}:
        return []
    return [_failed_security_check(
        "DARKSTAR-LINUX-SUID-COREDUMPS",
        {"path": "/proc/sys/fs/suid_dumpable", "value": value, "expected": "0"},
    )]


def _linux_security_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    checks.extend(_linux_ssh_checks())
    checks.extend(_linux_sudo_checks())
    checks.extend(_linux_shadow_checks())
    checks.extend(_linux_passwd_uid0_checks())
    checks.extend(_linux_sensitive_permission_checks())
    checks.extend(_linux_world_writable_path_checks())
    checks.extend(_linux_root_equivalent_group_checks())
    checks.extend(_linux_password_policy_checks())
    checks.extend(_linux_suid_coredump_checks())
    return checks


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _windows_security_state() -> dict[str, Any]:
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
function Get-RegDword($Path, $Name) {
  try {
    $value = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    if ($null -eq $value) { return $null }
    return [int]$value
  } catch { return $null }
}
function Get-RegString($Path, $Name) {
  try {
    $value = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    if ($null -eq $value) { return $null }
    return [string]$value
  } catch { return $null }
}
function Test-RegValue($Path, $Name) {
  try {
    $key = Get-Item -Path $Path -ErrorAction Stop
    return @($key.GetValueNames()) -contains $Name
  } catch { return $false }
}
$users = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
  Select-Object Name, SID, Disabled, PasswordRequired)
$services = @(Get-CimInstance Win32_Service |
  Where-Object {
    $_.PathName -and
    $_.PathName.Contains(' ') -and
    -not $_.PathName.TrimStart().StartsWith('"') -and
    $_.PathName -match '^[A-Za-z]:\\'
  } |
  Select-Object -First 20 Name, StartName, PathName)
$firewall = @(Get-NetFirewallProfile | Select-Object Name, Enabled)
$netAccounts = ""
try { $netAccounts = (net accounts | Out-String) } catch {}
[pscustomobject]@{
  AutoAdminLogon = Get-RegString 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
  DefaultPasswordPresent = Test-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'
  WDigestUseLogonCredential = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
  AlwaysInstallElevatedHKLM = Get-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
  AlwaysInstallElevatedHKCU = Get-RegDword 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
  EnableLUA = Get-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
  FDenyTSConnections = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
  RdpUserAuthentication = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
  AllowInsecureGuestAuth = Get-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth'
  NoLMHash = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash'
  SMB1 = Get-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
  LocalAccountTokenFilterPolicy = Get-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
  Users = $users
  UnquotedServices = $services
  FirewallProfiles = $firewall
  NetAccounts = $netAccounts
} | ConvertTo-Json -Depth 5 -Compress
"""
    data = _powershell_json(script, timeout=60)
    return data if isinstance(data, dict) else {}


def _parse_windows_net_accounts(text: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for line in str(text or "").splitlines():
        if "Minimum password length" in line:
            match = re.search(r"(\d+)", line)
            if match:
                parsed["minimum_password_length"] = int(match.group(1))
        elif "Maximum password age" in line:
            if "unlimited" in line.lower() or "never" in line.lower():
                parsed["maximum_password_age_days"] = None
                parsed["maximum_password_age_unlimited"] = True
            else:
                match = re.search(r"(\d+)", line)
                if match:
                    parsed["maximum_password_age_days"] = int(match.group(1))
        elif "Lockout threshold" in line:
            if "never" in line.lower():
                parsed["lockout_threshold"] = 0
            else:
                match = re.search(r"(\d+)", line)
                if match:
                    parsed["lockout_threshold"] = int(match.group(1))
    return parsed


def _windows_security_checks() -> list[dict[str, Any]]:
    state = _windows_security_state()
    checks: list[dict[str, Any]] = []
    if str(state.get("AutoAdminLogon") or "").strip() == "1" and state.get("DefaultPasswordPresent"):
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-AUTOLOGON-PASSWORD",
            {"registry_path": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "password_value_collected": False},
            confidence=95,
        ))
    if state.get("WDigestUseLogonCredential") == 1:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-WDIGEST-CREDENTIAL-CACHING",
            {"registry_value": "WDigest\\UseLogonCredential", "value": 1},
        ))
    if state.get("AlwaysInstallElevatedHKLM") == 1 and state.get("AlwaysInstallElevatedHKCU") == 1:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-ALWAYS-INSTALL-ELEVATED",
            {"hklm": 1, "hkcu": 1},
        ))
    if state.get("EnableLUA") == 0:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-UAC-DISABLED",
            {"registry_value": "Policies\\System\\EnableLUA", "value": 0},
        ))
    rdp_enabled = state.get("FDenyTSConnections") == 0
    if rdp_enabled:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-RDP-ENABLED",
            {"registry_value": "Terminal Server\\fDenyTSConnections", "value": 0},
        ))
        if state.get("RdpUserAuthentication") == 0:
            checks.append(_failed_security_check(
                "DARKSTAR-WINDOWS-RDP-NLA-DISABLED",
                {"registry_value": "RDP-Tcp\\UserAuthentication", "value": 0},
            ))
    if state.get("AllowInsecureGuestAuth") == 1:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-INSECURE-GUEST-SMB",
            {"registry_value": "LanmanWorkstation\\AllowInsecureGuestAuth", "value": 1},
        ))
    if state.get("NoLMHash") == 0:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-LM-HASH-STORAGE",
            {"registry_value": "Lsa\\NoLMHash", "value": 0},
        ))
    if state.get("SMB1") == 1:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-SMBV1-ENABLED",
            {"registry_value": "LanmanServer\\Parameters\\SMB1", "value": 1},
        ))
    if state.get("LocalAccountTokenFilterPolicy") == 1:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-LOCALACCOUNT-TOKEN-FILTER",
            {"registry_value": "Policies\\System\\LocalAccountTokenFilterPolicy", "value": 1},
        ))

    users = [user for user in _as_list(state.get("Users")) if isinstance(user, dict)]
    no_password_users = [
        user.get("Name")
        for user in users
        if not user.get("Disabled") and user.get("PasswordRequired") is False
    ]
    if no_password_users:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-PASSWORD-NOT-REQUIRED",
            {"account_count": len(no_password_users), "accounts": no_password_users[:20]},
        ))
    builtin_admins = [
        user.get("Name")
        for user in users
        if not user.get("Disabled") and str(user.get("SID") or "").endswith("-500")
    ]
    if builtin_admins:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-BUILTIN-ADMIN-ENABLED",
            {"account_count": len(builtin_admins), "accounts": builtin_admins[:20]},
        ))

    services = [service for service in _as_list(state.get("UnquotedServices")) if isinstance(service, dict)]
    if services:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-UNQUOTED-SERVICE-PATH",
            {
                "service_count": len(services),
                "examples": [
                    {
                        "name": service.get("Name"),
                        "run_as": service.get("StartName"),
                        "path": str(service.get("PathName") or "")[:500],
                    }
                    for service in services[:10]
                ],
            },
        ))

    disabled_profiles = [
        profile.get("Name")
        for profile in _as_list(state.get("FirewallProfiles"))
        if isinstance(profile, dict) and profile.get("Enabled") is False
    ]
    if disabled_profiles:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-FIREWALL-DISABLED",
            {"profiles": disabled_profiles[:10]},
        ))

    policy = _parse_windows_net_accounts(str(state.get("NetAccounts") or ""))
    weak_policy = []
    min_len = policy.get("minimum_password_length")
    if min_len is not None and int(min_len) < 12:
        weak_policy.append({"setting": "minimum_password_length", "value": min_len, "baseline": 12})
    if policy.get("maximum_password_age_unlimited") or (
        policy.get("maximum_password_age_days") is not None and int(policy["maximum_password_age_days"]) > 90
    ):
        weak_policy.append({"setting": "maximum_password_age_days", "value": policy.get("maximum_password_age_days"), "baseline": 90})
    if policy.get("lockout_threshold") == 0:
        weak_policy.append({"setting": "lockout_threshold", "value": 0, "baseline": "non-zero"})
    if weak_policy:
        checks.append(_failed_security_check(
            "DARKSTAR-WINDOWS-WEAK-PASSWORD-POLICY",
            {"weak_settings": weak_policy},
        ))
    return checks


def collect_security_checks() -> list[dict[str, Any]]:
    system = platform.system().lower()
    try:
        if system == "windows":
            checks = _windows_security_checks()
        elif system == "linux":
            checks = _linux_security_checks()
        else:
            checks = []
    except Exception:
        return []
    collected_at = datetime_utc_iso()
    for check in checks:
        check.setdefault("collected_at", collected_at)
    return checks


def security_posture_software(os_info: dict[str, Any], checks: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "software_key": POSTURE_SOFTWARE_KEY,
        "name": "Endpoint Security Posture",
        "version": str(SECURITY_CHECK_SCHEMA_VERSION),
        "vendor": "Darkstar",
        "ecosystem": "security_posture",
        "source": "darkstar_security_checks",
        "package_type": "security_posture",
        "raw": {
            "schema_version": SECURITY_CHECK_SCHEMA_VERSION,
            "platform": os_info.get("platform") or platform.system().lower(),
            "collected_at": datetime_utc_iso(),
            "security_checks": checks,
            "failed_count": len(checks),
        },
    }


def security_checks_metadata(checks: list[dict[str, Any]]) -> dict[str, Any]:
    categories: dict[str, int] = {}
    for check in checks:
        check_id = str(check.get("id") or "")
        prefix = check_id.split("-", 3)[2].lower() if check_id.count("-") >= 3 else "custom"
        categories[prefix] = categories.get(prefix, 0) + 1
    return {
        "schema_version": SECURITY_CHECK_SCHEMA_VERSION,
        "failed_count": len(checks),
        "categories": categories,
    }


def datetime_utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def collect_inventory(peer_targets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    os_info = _os_info()
    system = platform.system().lower()
    security_checks = collect_security_checks()
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
    software.append(security_posture_software(os_info, security_checks))
    ips, macs = _network_ids()
    network_probe = collect_network_probe(peer_targets)
    return {
        "os": os_info,
        "software": software,
        "ip_addresses": ips,
        "mac_addresses": macs,
        "network_probe": network_probe,
        "metadata": {
            "hostname": os_info.get("hostname") or socket.gethostname(),
            "collector": "darkstar_endpoint_agent",
            "collector_version": AGENT_VERSION,
            "osquery": bool(shutil.which("osqueryi")),
            "network_probe": {
                "version": NETWORK_PROBE_VERSION,
                "mode": "neighbor-cache+gateway+endpoint-peers",
            },
            "security_checks": security_checks_metadata(security_checks),
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
        return


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
    inventory = collect_inventory(state.get("network_probe_targets") or [])
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
    result = send_inventory(args.url, agent_token, inventory)
    if isinstance(result, dict) and "network_probe_targets" in result:
        state["network_probe_targets"] = result.get("network_probe_targets") or []
        _save_state(state_file, state)
    return result


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
