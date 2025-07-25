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

logger = logging.getLogger(__name__)


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
            all_targets.extend(target_df[column].tolist())

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
