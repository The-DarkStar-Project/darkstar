"""
Integration module to bridge RustScanPy port scanner with HydraPy bruteforce.

This module provides functions to:
1. Map service names discovered by RustScan to Hydra protocol names
2. Process scan results to identify bruteforceable services
3. Run Hydra attacks on supported services
"""

import asyncio
import logging
import os
from typing import Dict, List, Optional

from .hydrapy import HydraAttack
from colorama import Fore, Style


logger = logging.getLogger(__name__)

# Mapping of RustScan service names to Hydra protocol names
SERVICE_TO_PROTOCOL = {
    # Standard service names
    "ftp": "ftp",
    "ssh": "ssh",
    "smtp": "smtp",
    "snmp": "snmp",
    "netbios-ssn": "smb",
    "microsoft-ds": "smb",
    "mongodb": "mongodb",
    "mysql": "mysql",
    "postgresql": "postgres",
    # Alternative names that might appear
    "ftpd": "ftp",
    "sshd": "ssh",
    "smtpd": "smtp",
    "snmpd": "snmp",
    "samba": "smb",
    "cifs": "smb",
    "mariadb": "mysql",
    "postgres": "postgres",
    "pgsql": "postgres",
}

SUPPORTED_PROTOCOLS = {
    "ftp",
    "ssh",
    "smtp",
    "snmp",
    "smb",
    "mongodb",
    "mysql",
    "postgres",
}


def get_hydra_protocol(service: str) -> Optional[str]:
    """
    Map a service name from RustScan to the corresponding Hydra protocol.

    Args:
        service: Service name from RustScan

    Returns:
        str or None: Corresponding Hydra protocol or None if not supported
    """
    if not service:
        return None
    service_base = service.lower().split()[0]
    protocol = SERVICE_TO_PROTOCOL.get(service_base)
    if protocol and protocol in SUPPORTED_PROTOCOLS:
        return protocol

    return None


async def process_scan_results_with_hydra(
    scan_results: List[Dict],
    concurrent_limit: int = 3,
    timeout: int = 300,
    org_name: str = "test",
) -> Dict[str, List]:
    """
    Process RustScan results and launch Hydra attacks on supported services.

    Args:
        scan_results: List of scan results from RustScan
        concurrent_limit: Maximum number of concurrent Hydra attacks
        timeout: Timeout for each Hydra attack in seconds

    Returns:
        Dict: Mapping of IPs to lists of Hydra attack results
    """
    service_info = {}
    for result in scan_results:
        if not isinstance(result, dict):
            continue

        if "scan_results" in result and "ip_results" in result["scan_results"]:
            for ip, ip_data in result["scan_results"]["ip_results"].items():
                if "ports" in ip_data and ip_data["ports"]:
                    service_info[ip] = ip_data["ports"]

    if not service_info:
        logger.info("No services found for bruteforcing")
        return {}

    output_dir = f"scan_results/{org_name}/bruteforce"
    os.makedirs(output_dir, exist_ok=True)
    hydra = HydraAttack(output_dir=output_dir)

    tasks = []
    attack_details = []
    sem = asyncio.Semaphore(concurrent_limit)

    for ip, ports in service_info.items():
        for port_data in ports:
            port = port_data.get("port")
            service = port_data.get("service")

            protocol = get_hydra_protocol(service)
            if protocol:
                logger.info(
                    f"Found supported service for bruteforcing: {ip}:{port} - {service} -> {protocol}"
                )

                attack_details.append(
                    {"ip": ip, "port": port, "service": service, "protocol": protocol}
                )

                # Create the attack task
                tasks.append(run_hydra_attack(sem, hydra, ip, protocol, port, timeout))

    if not tasks:
        logger.info("No supported services found for bruteforcing")
        return {}

    logger.info(f"Starting {len(tasks)} Hydra attacks on supported services")
    results = await asyncio.gather(*tasks, return_exceptions=True)
    hydra_results = {}

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            ip = attack_details[i]["ip"]
            logger.error(
                f"Error in Hydra attack on {ip}:{attack_details[i]['port']} "
                f"({attack_details[i]['protocol']}): {str(result)}"
            )

            if ip not in hydra_results:
                hydra_results[ip] = []

            hydra_results[ip].append(
                {
                    "port": attack_details[i]["port"],
                    "protocol": attack_details[i]["protocol"],
                    "status": "error",
                    "error": str(result),
                }
            )
        else:
            # Store the successful result
            ip = result.target
            if ip not in hydra_results:
                hydra_results[ip] = []

            hydra_results[ip].append(
                {
                    "port": result.port,
                    "protocol": result.protocol,
                    "status": result.status,
                    "credentials": result.credentials,
                    "error": result.error,
                }
            )

    return hydra_results


async def run_hydra_attack(sem, hydra, ip, protocol, port, timeout):
    """
    Run a Hydra attack with a semaphore to limit concurrent attacks.

    Args:
        sem: Asyncio semaphore for concurrency control
        hydra: HydraAttack instance
        ip: Target IP address
        protocol: Protocol to attack (ftp, ssh, etc.)
        port: Port number to attack
        timeout: Timeout for the attack in seconds

    Returns:
        AttackResult: Result of the Hydra attack
    """
    async with sem:
        return await hydra.run_attack(
            ip=ip,
            protocol=protocol,
            port=port,
            stop_on_success=True,  # Stop after finding first credentials
            timeout=timeout,
        )


def process_bruteforce_results(bruteforce_results):
    """
    Process bruteforce results and log relevant information.

    Args:
        bruteforce_results: Results from bruteforce attacks

    Returns:
        dict: Processed results with credential counts
    """
    processed_results = {"credentials_found": False, "credentials_by_host": {}}

    if not bruteforce_results:
        logger.info(
            f"{Fore.YELLOW}[!] No bruteforce results available.{Style.RESET_ALL}"
        )
        return processed_results

    for ip, attacks in bruteforce_results.items():
        for attack in attacks:
            if attack["status"] == "success" and attack["credentials"]:
                processed_results["credentials_found"] = True

                if ip not in processed_results["credentials_by_host"]:
                    processed_results["credentials_by_host"][ip] = []

                logger.info(
                    f"{Fore.GREEN}Found credentials for {Fore.YELLOW}{ip}:{attack['port']}"
                    f" ({attack['protocol']}):{Style.RESET_ALL}"
                )

                for cred in attack["credentials"]:
                    if "username" in cred and "password" in cred:
                        credential = {
                            "username": cred["username"],
                            "password": cred["password"],
                            "port": attack["port"],
                            "protocol": attack["protocol"],
                        }
                        processed_results["credentials_by_host"][ip].append(credential)

                        logger.info(
                            f"{Fore.GREEN}    Username: {Fore.CYAN}{cred['username']}{Fore.GREEN} "
                            f"Password: {Fore.CYAN}{cred['password']}{Style.RESET_ALL}"
                        )
                    elif "password" in cred:  # SNMP case
                        credential = {
                            "community_string": cred["password"],
                            "port": attack["port"],
                            "protocol": attack["protocol"],
                        }
                        processed_results["credentials_by_host"][ip].append(credential)

                        logger.info(
                            f"{Fore.GREEN}    Community string: {Fore.CYAN}{cred['password']}{Style.RESET_ALL}"
                        )

    if not processed_results["credentials_found"]:
        logger.info(
            f"{Fore.YELLOW}[!] No credentials were found during bruteforce attacks.{Style.RESET_ALL}"
        )

    logger.info(
        f"{Fore.GREEN}Bruteforce attacks completed on {len(bruteforce_results)} targets"
    )

    return processed_results
