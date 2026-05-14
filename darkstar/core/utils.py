"""
General utility functions for the Darkstar security framework.

This module provides various utility functions used throughout the framework,
such as file handling, target processing, and other common operations.
"""

import os
import pandas as pd
from typing import List, Dict
import ipaddress
import re
import logging
from colorama import Fore, Style
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


COMMON_MULTI_LABEL_PUBLIC_SUFFIXES = {
    "ac",
    "co",
    "com",
    "edu",
    "gov",
    "mil",
    "net",
    "org",
}


def normalize_network_target(target: str) -> str:
    """Return a host/IP/CIDR value suitable for network scanners."""
    clean_target = str(target or "").strip()
    if not clean_target:
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_target):
        parsed = urlparse(clean_target)
        return parsed.hostname or clean_target
    return clean_target.rstrip("/")


def normalize_domain_target(target: str) -> str:
    """Return a clean hostname from a URL/domain target, without ports or paths."""
    clean_target = str(target or "").strip().strip("[]").rstrip("/")
    if not clean_target:
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_target):
        parsed = urlparse(clean_target)
        clean_target = parsed.hostname or ""
    else:
        clean_target = clean_target.split("/", 1)[0]
        if "@" in clean_target:
            clean_target = clean_target.rsplit("@", 1)[-1]
        if ":" in clean_target and clean_target.count(":") == 1:
            clean_target = clean_target.split(":", 1)[0]
    return clean_target.lower().strip(".")


def registrable_domain(target: str) -> str:
    """
    Best-effort eTLD+1 extraction for email security scoping.

    This intentionally avoids live public suffix downloads in scanner containers.
    It handles normal domains and common ccTLD second-level suffixes such as
    example.com.br and example.co.uk.
    """
    host = normalize_domain_target(target)
    if not host or "." not in host or "localhost" in host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass

    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return ""
    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2] in COMMON_MULTI_LABEL_PUBLIC_SUFFIXES
    ):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def email_security_domains_from_targets(targets: List[str]) -> List[str]:
    """Collapse scan targets to unique root domains suitable for SPF/DMARC checks."""
    domains = []
    for target in targets:
        domain = registrable_domain(target)
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def host_targets_from_targets(targets: List[str]) -> List[str]:
    """Return normalized non-IP host targets while preserving subdomain scope."""
    hosts = []
    for target in targets:
        host = normalize_domain_target(target)
        if not host or "." not in host or "localhost" in host:
            continue
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        if host not in hosts:
            hosts.append(host)
    return hosts


def get_scan_targets(target_df: pd.DataFrame) -> List[str]:
    """
    Extract all scan targets from a target DataFrame.

    Args:
        target_df: Target DataFrame with categorized targets

    Returns:
        List[str]: List of all targets for scanning
    """
    all_targets = []
    target_types = ["IPv4", "Domains", "CIDRs", "IPv6", "URLs"]

    for column in target_types:
        if column in target_df.columns:
            all_targets.extend(
                normalized
                for normalized in (normalize_network_target(target) for target in target_df[column].tolist())
                if normalized
            )

    return all_targets


def ensure_directory_exists(path: str) -> None:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        path: Path to the directory
    """
    os.makedirs(path, exist_ok=True)


def prepare_output_directory(org_domain: str, scan_type: str = None) -> str:
    """
    Prepare and create an output directory for scan results.

    Args:
        org_domain: Organization domain/name for directory structure
        scan_type: Type of scan (e.g., 'rustscan', 'nuclei', etc.)

    Returns:
        str: Path to the created output directory
    """
    base_dir = f"scan_results/{org_domain}"

    ensure_directory_exists(base_dir)

    if scan_type:
        output_dir = f"{base_dir}/{scan_type}"
        ensure_directory_exists(output_dir)
        return output_dir

    return base_dir


def categorize_targets(targets: List[str]) -> Dict[str, List[str]]:
    """
    Categorize each target using proper validation.
    Returns:
        Dict mapping category names to lists of targets
    """
    categories: Dict[str, List[str]] = {
        "CIDRs": [],
        "IPv4": [],
        "IPv6": [],
        "Domains": [],
        "URLs": [],
    }

    url_pattern = re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
    domain_pattern = re.compile(
        r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
    )

    for target in targets:
        try:
            if url_pattern.match(target):
                categories["URLs"].append(target)

            elif "/" in target and is_valid_cidr(target):
                categories["CIDRs"].append(target)

            elif ":" in target and is_valid_ipv6(target):
                categories["IPv6"].append(target)

            elif is_valid_ipv4(target):
                categories["IPv4"].append(target)

            elif domain_pattern.match(target):
                categories["Domains"].append(target)

            # If nothing else matches, assume it's a domain
            else:
                categories["Domains"].append(target)

        except Exception as e:
            logger.debug(f"Error categorizing target '{target}': {str(e)}")
            categories["Domains"].append(target)

    return categories


def is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Check if string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def log_target_summary(categories: Dict[str, List[str]]) -> None:
    """Log a summary of categorized targets."""

    for category, targets in categories.items():
        if targets:
            # Only show first 5 targets if there are many
            display_targets = (
                ", ".join(targets) if len(targets) <= 5 else targets[:5] + ["..."]
            )
            logger.info(
                f"{Fore.MAGENTA}{category}: {Fore.CYAN}{len(targets)} target(s): {display_targets}{Style.RESET_ALL}"
            )


def create_target_dataframe(categories: Dict[str, List[str]]) -> pd.DataFrame:
    """Create a DataFrame from categorized targets that supports different length lists."""
    data = {category: targets for category, targets in categories.items() if targets}

    if not data:
        return pd.DataFrame()

    dfs = []
    for category, items in data.items():
        df = pd.DataFrame({category: items})
        dfs.append(df)

    if len(dfs) == 1:
        return dfs[0]

    result = pd.DataFrame()
    for df in dfs:
        result = pd.concat([result, df], axis=1)

    return result
