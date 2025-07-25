"""
Utility functions specific to RustScanPy operations.
"""

import asyncio
import json
import logging
import os
import shutil
from datetime import datetime
from typing import Dict, List
from colorama import Fore, Style


logger = logging.getLogger(__name__)

# ===== Dependency Verification =====


async def verify_installation(program):
    """
    Check if a program is available in the system path.

    Args:
        program: Name of the program to check

    Returns:
        bool: True if program is installed, False otherwise
    """
    try:
        if shutil.which(program) is not None:
            return True

        process = await asyncio.create_subprocess_exec(
            "which",
            program,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        return process.returncode == 0
    except Exception as e:
        logger.error(f"Error checking for {program} installation: {str(e)}")
        return False


async def verify_rustscan():
    """
    Verify if RustScan is installed.

    Returns:
        bool: True if installed, False otherwise
    """
    return await verify_installation("rustscan")


async def verify_all_installations():
    """
    Verify all required dependencies for RustScan.

    Returns:
        bool: True if all dependencies are installed, False otherwise
    """
    rustscan_installed = await verify_rustscan()

    if not rustscan_installed:
        logger.error("RustScan is not installed. Try running 'cargo install rustscan'")
        return False

    logger.debug("All required RustScan dependencies are properly installed")
    return True


# ===== Result Handling =====


async def save_results(
    results: List[Dict], output_dir: str = None, all_in_one: bool = False
) -> Dict[str, str]:
    """
    Save RustScan results to JSON file(s).

    Args:
        results: List of scan results
        output_dir: Directory to save results (generated if None)
        all_in_one: If True, save all results to a single file

    Returns:
        Dict: Mapping of targets to their result files
    """
    created_files = {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not output_dir:
        output_dir = "scan_results"
    os.makedirs(output_dir, exist_ok=True)

    if all_in_one:
        output_file = f"{output_dir}/rustscan_all_targets_{timestamp}.json"
        data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "filename": output_file,
            },
            "results": results,
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"RustScan combined results saved to {output_file}")
        created_files["all"] = output_file

    else:
        for result in results:
            if not isinstance(result, dict) or "target" not in result:
                continue

            # FIX: Handle non-string targets gracefully
            target = result["target"]
            if not isinstance(target, str):
                # Convert to string or use a default placeholder
                target_str = str(target)
                logger.warning(
                    f"Non-string target encountered: {target_str}. Converting to string."
                )
            else:
                target_str = target

            # Now safely apply string operations
            safe_target = (
                target_str.replace("/", "_").replace(":", "_").replace(".", "-")
            )
            target_file = f"{output_dir}/rustscanpy_{safe_target}_{timestamp}.json"

            target_data = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "filename": target_file,
                    "target": target,
                },
                "results": [result],
            }

            with open(target_file, "w") as f:
                json.dump(target_data, f, indent=2)

            logger.info(f"RustScan results for {target} saved to {target_file}")
            created_files[target_str] = target_file

    return created_files


def extract_service_info(scan_results):
    """
    Extract service information from RustScan results.

    Args:
        scan_results: Results from RustScan (either a list of results or a dict with 'scan_results' key)

    Returns:
        Dict: Mapping of IPs to their open ports with service info
    """
    service_info = {}

    if isinstance(scan_results, dict) and "scan_results" in scan_results:
        scan_results_list = scan_results["scan_results"]
    else:
        scan_results_list = scan_results

    if not isinstance(scan_results_list, list):
        return service_info

    for result in scan_results_list:
        if not isinstance(result, dict):
            continue

        if "scan_results" in result and "ip_results" in result["scan_results"]:
            for ip, ip_data in result["scan_results"]["ip_results"].items():
                if "ports" in ip_data and ip_data["ports"]:
                    service_info[ip] = ip_data["ports"]

    return service_info


def process_scan_results(scan_results, org_domain):
    """
    Process RustScan results and log relevant information.

    Args:
        scan_results: Results from RustScan
        org_domain: Organization domain for output

    Returns:
        dict: Processed results with formatted service info
    """
    processed_results = {"service_info": None, "ports_by_host": {}}

    if scan_results:
        service_info = extract_service_info(scan_results)
        processed_results["service_info"] = service_info
        ports_found = False

        if service_info:
            for ip, ports in service_info.items():
                if ports:  # Check if there are actual ports for this IP
                    ports_found = True
                    port_info = [
                        f"{p['port']}/{p['service'] or 'unknown'}" for p in ports
                    ]
                    processed_results["ports_by_host"][ip] = port_info
                    logger.info(
                        f"{Fore.GREEN}Found open ports on {Fore.YELLOW}{ip}{Fore.GREEN}: {Fore.CYAN}{', '.join(port_info)}{Style.RESET_ALL}"
                    )

        # Only log warning if no ports were actually found
        if not ports_found:
            logger.warning("[!] No open ports were found during RustScan.")

    return processed_results
