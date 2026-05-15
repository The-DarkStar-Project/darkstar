"""Endpoint custom posture checks.

The agent reports only passive check identifiers and evidence. This module owns
the finding metadata so endpoint inventory cannot spoof severity or remediation
text by changing the submitted payload.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


POSTURE_SOFTWARE_KEY = "darkstar-security-posture"
CUSTOM_CHECK_SOURCE = "DarkstarCheck"


@dataclass(frozen=True)
class CustomCheckDefinition:
    title: str
    severity: str
    category: str
    summary: str
    impact: str
    remediation: str
    cvss: float | None = None
    confidence: int = 90


CHECK_DEFINITIONS: dict[str, CustomCheckDefinition] = {
    "DARKSTAR-LINUX-SSH-ROOT-LOGIN": CustomCheckDefinition(
        title="SSH root login is permitted",
        severity="high",
        category="weak_setting",
        summary="The SSH daemon is configured to allow direct root logins.",
        impact="Attackers can target the highest-privilege account directly if SSH credentials or keys are exposed.",
        remediation="Disable direct root SSH logins by setting PermitRootLogin no and use named administrator accounts with sudo.",
        cvss=7.2,
    ),
    "DARKSTAR-LINUX-SSH-PASSWORD-AUTH": CustomCheckDefinition(
        title="SSH password authentication is enabled",
        severity="medium",
        category="passwords",
        summary="The SSH daemon accepts password-based authentication.",
        impact="Password-based SSH increases exposure to password spraying and credential reuse attacks.",
        remediation="Prefer key-based authentication, disable PasswordAuthentication where possible, and enforce MFA for remote access.",
        cvss=5.3,
    ),
    "DARKSTAR-LINUX-SSH-EMPTY-PASSWORDS": CustomCheckDefinition(
        title="SSH permits empty passwords",
        severity="critical",
        category="passwords",
        summary="The SSH daemon is configured to allow accounts with empty passwords.",
        impact="Any enabled account without a password may be remotely accessible over SSH.",
        remediation="Set PermitEmptyPasswords no and disable or assign strong passwords to any passwordless local accounts.",
        cvss=9.1,
        confidence=95,
    ),
    "DARKSTAR-LINUX-SUDO-NOPASSWD": CustomCheckDefinition(
        title="Sudo NOPASSWD entries are present",
        severity="medium",
        category="privilege_escalation",
        summary="One or more sudo rules allow command execution without re-authentication.",
        impact="A compromised user session can move to elevated privileges without requiring the user's password.",
        remediation="Remove broad NOPASSWD rules or scope them tightly to audited administrative workflows.",
        cvss=6.5,
    ),
    "DARKSTAR-LINUX-EMPTY-PASSWORD": CustomCheckDefinition(
        title="Local account has an empty password",
        severity="critical",
        category="passwords",
        summary="At least one local account has an empty password field in the shadow database.",
        impact="Passwordless local accounts can allow trivial local or remote authentication depending on service configuration.",
        remediation="Lock the account or set a strong password and confirm services do not permit empty-password authentication.",
        cvss=9.1,
        confidence=95,
    ),
    "DARKSTAR-LINUX-WEAK-PASSWORD-HASH": CustomCheckDefinition(
        title="Weak local password hash algorithm detected",
        severity="high",
        category="passwords",
        summary="At least one local password hash uses a legacy algorithm such as DES or MD5.",
        impact="Legacy password hashes are significantly easier to crack if the shadow database is exposed.",
        remediation="Force affected users to change passwords after configuring a modern password hashing method.",
        cvss=7.0,
    ),
    "DARKSTAR-LINUX-UID0-EXTRA-ACCOUNT": CustomCheckDefinition(
        title="Additional UID 0 account exists",
        severity="high",
        category="privilege_escalation",
        summary="A local account other than root has UID 0.",
        impact="Any UID 0 account is equivalent to root and may bypass normal administrator accountability.",
        remediation="Remove unneeded UID 0 accounts or assign them unique non-root UIDs.",
        cvss=7.8,
    ),
    "DARKSTAR-LINUX-SENSITIVE-FILE-PERMISSIONS": CustomCheckDefinition(
        title="Sensitive Linux file permissions are unsafe",
        severity="critical",
        category="privilege_escalation",
        summary="A sensitive system file such as passwd, shadow, or sudoers has unsafe permissions.",
        impact="Unsafe permissions can expose password metadata or allow local users to change authentication and privilege rules.",
        remediation="Restore distribution defaults for ownership and permissions on the affected files.",
        cvss=9.0,
        confidence=95,
    ),
    "DARKSTAR-LINUX-WORLD-WRITABLE-PATH": CustomCheckDefinition(
        title="World-writable directory is present in system PATH",
        severity="high",
        category="privilege_escalation",
        summary="A directory used for command lookup is writable by all users.",
        impact="Local users may be able to plant executables that are later run by privileged processes or administrators.",
        remediation="Remove world-writable directories from PATH or tighten directory ownership and permissions.",
        cvss=7.4,
    ),
    "DARKSTAR-LINUX-ROOT-EQUIVALENT-GROUP": CustomCheckDefinition(
        title="User belongs to a root-equivalent local group",
        severity="medium",
        category="privilege_escalation",
        summary="One or more users are members of groups that commonly grant root-equivalent access, such as docker or lxd.",
        impact="Members of these groups can often obtain root-level control through container or virtualization features.",
        remediation="Limit membership in root-equivalent groups to trusted administrators and review whether membership is still required.",
        cvss=6.8,
    ),
    "DARKSTAR-LINUX-PASSWORD-POLICY-WEAK": CustomCheckDefinition(
        title="Linux password policy is weak",
        severity="medium",
        category="passwords",
        summary="Local password aging or length policy is weaker than the Darkstar baseline.",
        impact="Weak password policy increases the likelihood of long-lived or low-complexity local credentials.",
        remediation="Set stronger password aging and quality controls in login.defs and pwquality configuration.",
        cvss=5.3,
    ),
    "DARKSTAR-LINUX-SUID-COREDUMPS": CustomCheckDefinition(
        title="SUID core dumps are enabled",
        severity="medium",
        category="privilege_escalation",
        summary="The kernel is configured to allow core dumps for privileged SUID programs.",
        impact="Core dumps from privileged programs can expose sensitive memory contents to local users or crash handlers.",
        remediation="Set fs.suid_dumpable to 0 unless a documented crash collection workflow requires otherwise.",
        cvss=5.5,
    ),
    "DARKSTAR-WINDOWS-AUTOLOGON-PASSWORD": CustomCheckDefinition(
        title="Windows AutoAdminLogon password is configured",
        severity="critical",
        category="passwords",
        summary="Windows automatic logon is enabled and a DefaultPassword registry value exists.",
        impact="Auto logon stores reusable credentials in a location commonly targeted during compromise.",
        remediation="Disable AutoAdminLogon and remove stored logon password values from Winlogon registry settings.",
        cvss=9.0,
        confidence=95,
    ),
    "DARKSTAR-WINDOWS-WDIGEST-CREDENTIAL-CACHING": CustomCheckDefinition(
        title="WDigest credential caching is enabled",
        severity="critical",
        category="passwords",
        summary="WDigest is configured to keep reusable logon credentials in memory.",
        impact="A local administrator or malware process may be able to recover cleartext credentials from memory.",
        remediation="Set UseLogonCredential to 0 and reboot affected systems after confirming application compatibility.",
        cvss=9.0,
    ),
    "DARKSTAR-WINDOWS-ALWAYS-INSTALL-ELEVATED": CustomCheckDefinition(
        title="AlwaysInstallElevated is enabled",
        severity="high",
        category="privilege_escalation",
        summary="Both machine and user Windows Installer policies allow elevated MSI installs.",
        impact="A low-privilege user may be able to execute a crafted installer with elevated privileges.",
        remediation="Disable AlwaysInstallElevated in both HKLM and HKCU policy locations.",
        cvss=8.4,
    ),
    "DARKSTAR-WINDOWS-UAC-DISABLED": CustomCheckDefinition(
        title="User Account Control is disabled",
        severity="high",
        category="privilege_escalation",
        summary="Windows User Account Control is disabled through policy.",
        impact="Administrative actions run without UAC prompts, reducing containment after account compromise.",
        remediation="Enable UAC by setting EnableLUA to 1 and rebooting the host.",
        cvss=7.2,
    ),
    "DARKSTAR-WINDOWS-RDP-NLA-DISABLED": CustomCheckDefinition(
        title="RDP Network Level Authentication is disabled",
        severity="high",
        category="weak_setting",
        summary="Remote Desktop is enabled without requiring Network Level Authentication.",
        impact="RDP can be reached before authentication, increasing exposure to credential attacks and pre-authentication flaws.",
        remediation="Require Network Level Authentication for Remote Desktop connections.",
        cvss=7.0,
    ),
    "DARKSTAR-WINDOWS-RDP-ENABLED": CustomCheckDefinition(
        title="Remote Desktop is enabled",
        severity="medium",
        category="weak_setting",
        summary="Remote Desktop connections are allowed on this endpoint.",
        impact="RDP increases the remote attack surface and should be restricted to managed administration paths.",
        remediation="Disable RDP where it is not required or restrict access through firewall rules, VPN, and MFA.",
        cvss=5.3,
    ),
    "DARKSTAR-WINDOWS-INSECURE-GUEST-SMB": CustomCheckDefinition(
        title="Insecure SMB guest authentication is enabled",
        severity="high",
        category="weak_setting",
        summary="The workstation policy allows insecure guest authentication to SMB servers.",
        impact="Users may connect to unauthenticated SMB services, increasing credential interception and tampering risk.",
        remediation="Disable AllowInsecureGuestAuth for LanmanWorkstation.",
        cvss=7.1,
    ),
    "DARKSTAR-WINDOWS-LM-HASH-STORAGE": CustomCheckDefinition(
        title="LM password hash storage is enabled",
        severity="high",
        category="passwords",
        summary="Windows is configured to allow storage of legacy LAN Manager password hashes.",
        impact="LM hashes are weak and can materially reduce password cracking resistance if the SAM is exposed.",
        remediation="Set NoLMHash to 1 and require users to change passwords so old LM hashes are removed.",
        cvss=7.0,
    ),
    "DARKSTAR-WINDOWS-BUILTIN-ADMIN-ENABLED": CustomCheckDefinition(
        title="Built-in Administrator account is enabled",
        severity="medium",
        category="passwords",
        summary="The local built-in Administrator account is enabled.",
        impact="The well-known local administrator SID is a common target for credential guessing and lateral movement.",
        remediation="Disable or tightly control the built-in Administrator account and use named administrator accounts.",
        cvss=6.0,
    ),
    "DARKSTAR-WINDOWS-PASSWORD-NOT-REQUIRED": CustomCheckDefinition(
        title="Local account does not require a password",
        severity="high",
        category="passwords",
        summary="At least one enabled local Windows account is configured with PasswordRequired set to false.",
        impact="Accounts that do not require passwords can undermine local and remote authentication controls.",
        remediation="Require passwords for enabled local accounts or disable accounts that are not needed.",
        cvss=8.0,
    ),
    "DARKSTAR-WINDOWS-WEAK-PASSWORD-POLICY": CustomCheckDefinition(
        title="Windows password policy is weak",
        severity="medium",
        category="passwords",
        summary="Local Windows password policy is weaker than the Darkstar baseline.",
        impact="Weak local password policy increases the risk of credential guessing and long-lived passwords.",
        remediation="Set a minimum password length of at least 12, enforce password expiry appropriate to policy, and configure lockout.",
        cvss=5.3,
    ),
    "DARKSTAR-WINDOWS-UNQUOTED-SERVICE-PATH": CustomCheckDefinition(
        title="Unquoted Windows service path detected",
        severity="high",
        category="privilege_escalation",
        summary="One or more Windows services have unquoted executable paths containing spaces.",
        impact="If path permissions are also weak, a local user may be able to hijack service execution for privilege escalation.",
        remediation="Quote affected service executable paths and review filesystem ACLs on parent directories.",
        cvss=7.3,
    ),
    "DARKSTAR-WINDOWS-FIREWALL-DISABLED": CustomCheckDefinition(
        title="Windows Firewall profile is disabled",
        severity="medium",
        category="weak_setting",
        summary="One or more Windows Firewall profiles are disabled.",
        impact="Disabled host firewall profiles increase exposure to lateral movement and unnecessary inbound access.",
        remediation="Enable Windows Firewall for all profiles and allow only required inbound services.",
        cvss=5.5,
    ),
    "DARKSTAR-WINDOWS-SMBV1-ENABLED": CustomCheckDefinition(
        title="SMBv1 server support is enabled",
        severity="high",
        category="weak_setting",
        summary="SMBv1 is enabled on the Windows Server service.",
        impact="SMBv1 is obsolete and has a long history of severe remote exploitation and downgrade risk.",
        remediation="Disable SMBv1 and migrate dependencies to SMBv2 or newer.",
        cvss=8.1,
    ),
    "DARKSTAR-WINDOWS-LOCALACCOUNT-TOKEN-FILTER": CustomCheckDefinition(
        title="Remote UAC filtering is disabled for local accounts",
        severity="medium",
        category="privilege_escalation",
        summary="LocalAccountTokenFilterPolicy allows full administrator tokens for remote local-account connections.",
        impact="Compromised local administrator credentials become more useful for remote lateral movement.",
        remediation="Remove LocalAccountTokenFilterPolicy or set it to 0 unless a documented administration workflow requires it.",
        cvss=6.5,
    ),
}


def _parse_json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return str(value)[:500]
    if isinstance(value, dict):
        return {str(key)[:80]: _bounded(item, depth + 1) for key, item in list(value.items())[:40]}
    if isinstance(value, list):
        return [_bounded(item, depth + 1) for item in value[:50]]
    if isinstance(value, str):
        return value[:1000]
    return value


def _posture_payload(item: dict[str, Any]) -> dict[str, Any] | None:
    raw_json = _parse_json(item.get("raw_json"))
    raw = item.get("raw")
    if isinstance(raw, str):
        raw = _parse_json(raw)

    candidates = [item]
    if isinstance(raw, dict):
        candidates.append(raw)
    if isinstance(raw_json, dict):
        candidates.append(raw_json)
        nested_raw = raw_json.get("raw")
        if isinstance(nested_raw, dict):
            candidates.append(nested_raw)

    for candidate in candidates:
        if isinstance(candidate, dict) and isinstance(candidate.get("security_checks"), list):
            return candidate
    return None


def _posture_items(software: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for item in software or []:
        if not isinstance(item, dict):
            continue
        package_type = str(item.get("package_type") or item.get("ecosystem") or "").lower()
        source = str(item.get("source") or "").lower()
        if (
            item.get("software_key") == POSTURE_SOFTWARE_KEY
            or package_type == "security_posture"
            or source == "darkstar_security_checks"
            or _posture_payload(item)
        ):
            items.append(item)
    return items


def _finding_summary(definition: CustomCheckDefinition) -> str:
    return (
        f"{definition.title}\n\n"
        f"{definition.summary}\n\n"
        f"Impact: {definition.impact}\n\n"
        f"Recommended fix: {definition.remediation}"
    )


def match_custom_vulnerabilities(
    software: list[dict[str, Any]],
    os_info: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return Darkstar custom endpoint findings from agent posture checks."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in _posture_items(software):
        payload = _posture_payload(item)
        if not payload:
            continue
        software_key = item.get("software_key") or POSTURE_SOFTWARE_KEY
        for check in payload.get("security_checks") or []:
            if not isinstance(check, dict):
                continue
            check_id = str(check.get("id") or "").strip().upper()
            definition = CHECK_DEFINITIONS.get(check_id)
            if not definition or check.get("passed") is True:
                continue
            key = (str(software_key), check_id)
            if key in seen:
                continue
            seen.add(key)
            evidence = {
                "matcher": "darkstar_endpoint_custom_check",
                "check_id": check_id,
                "title": definition.title,
                "category": definition.category,
                "platform": (os_info or {}).get("platform") or payload.get("platform"),
                "observed_at": payload.get("collected_at") or check.get("collected_at"),
                "agent_evidence": _bounded(check.get("evidence") or {}),
            }
            findings.append({
                "software_key": software_key,
                "cve": check_id,
                "source": CUSTOM_CHECK_SOURCE,
                "severity": definition.severity,
                "cvss": definition.cvss,
                "summary": _finding_summary(definition),
                "fixed_version": None,
                "affected_version": item.get("version") or (os_info or {}).get("version"),
                "purl": item.get("purl"),
                "confidence": int(check.get("confidence") or definition.confidence),
                "evidence": evidence,
            })
    return findings
