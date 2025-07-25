"""
RustScan port scanner wrapper module.

This module provides a Python wrapper around the RustScan port scanner tool
with asynchronous execution capabilities.
"""

import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict

import dns.asyncresolver

from .rustscan_utils import verify_all_installations, save_results


logger = logging.getLogger(__name__)


@dataclass
class ScanTarget:
    """
    Represents a target to be scanned with additional metadata.

    Attributes:
        target (str): The original target string (domain, IP, or CIDR)
        resolved_ips (List[str]): List of IP addresses resolved from the target
        is_behind_cdn (bool): Flag indicating if the target is behind a CDN
        is_ip (bool): Flag indicating if the target is an IP address
        is_cidr (bool): Flag indicating if the target is a CIDR range
        retry_count (int): Number of retry attempts made so far
        max_retries (int): Maximum number of retry attempts allowed
    """

    target: str  # Can be domain, IP, or CIDR
    resolved_ips: List[str]
    is_behind_cdn: bool
    is_ip: bool = False
    is_cidr: bool = False
    retry_count: int = 0
    max_retries: int = 3


class RustScanner:
    """
    Python wrapper for the RustScan port scanner tool.

    This class provides methods to scan targets for open ports using RustScan,
    with support for various scanning options and asynchronous execution.

    Attributes:
        CDN_RANGES (List[str]): List of CIDR ranges known to belong to CDNs
        batch_size (int): Batch size for RustScan
        ulimit (int): Process limit for RustScan
        timeout (int): Scan timeout in milliseconds
        concurrent_limit (int): Maximum number of concurrent scans
        tries (int): Number of retries for each target
        service_detection (bool): Whether to enable service detection
        retry_delay (int): Delay between retries in seconds
    """

    CDN_RANGES = [
        "103.21.244.0/22",  # Cloudflare
        "173.245.48.0/20",  # Cloudflare
        "104.16.0.0/12",  # Cloudflare
        "13.32.0.0/15",  # AWS CloudFront
        "205.251.192.0/19",  # AWS CloudFront
    ]

    def __init__(
        self,
        batch_size: int = 30000,
        ulimit: int = 45000,
        timeout: int = 3500,
        concurrent_limit: int = 5,
        tries: int = 1,
        service_detection: bool = True,
        retry_delay: int = 30,
    ):
        """
        Initialize the RustScanner with the given parameters.

        Args:
            batch_size: Batch size for RustScan (default: 30000)
            ulimit: Process limit for RustScan (default: 45000)
            timeout: Scan timeout in milliseconds (default: 3500)
            concurrent_limit: Maximum number of concurrent scans (default: 5)
            tries: Number of retries for each target (default: 1)
            service_detection: Whether to enable service detection (default: True)
            retry_delay: Delay between retries in seconds (default: 30)
        """
        self.batch_size = batch_size
        self.ulimit = ulimit
        self.timeout = timeout
        self.concurrent_limit = concurrent_limit
        self.tries = tries
        self.service_detection = service_detection
        self.retry_delay = retry_delay
        self.semaphore = asyncio.Semaphore(concurrent_limit)
        self._cdn_networks = [ipaddress.ip_network(cidr) for cidr in self.CDN_RANGES]

    async def _is_valid_ip(self, ip: str) -> bool:
        """
        Check if a string is a valid IP address.

        Args:
            ip: The string to check

        Returns:
            bool: True if the string is a valid IP address, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    async def _is_valid_cidr(self, cidr: str) -> bool:
        """
        Check if a string is a valid CIDR notation.

        Args:
            cidr: The string to check

        Returns:
            bool: True if the string is a valid CIDR notation, False otherwise
        """
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    async def _expand_cidr(self, cidr: str) -> List[str]:
        """
        Expand a CIDR notation into a list of IP addresses.

        Args:
            cidr: The CIDR notation to expand

        Returns:
            List[str]: List of IP addresses in the CIDR range
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            logger.error(f"Invalid CIDR notation: {cidr}, Error: {str(e)}")
            return []

    async def _is_ip_behind_cdn(self, ip: str) -> bool:
        """
        Check if an IP address is behind a CDN.

        Args:
            ip: The IP address to check

        Returns:
            bool: True if the IP is behind a CDN, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in self._cdn_networks)
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False

    async def _resolve_target(self, target: str) -> ScanTarget:
        """
        Resolve a target to its IP addresses.

        Args:
            target: The target to resolve (domain, IP, or CIDR)

        Returns:
            ScanTarget: ScanTarget object with resolved IP addresses and metadata
        """
        if await self._is_valid_ip(target):
            return ScanTarget(
                target=target,
                resolved_ips=[target],
                is_behind_cdn=await self._is_ip_behind_cdn(target),
                is_ip=True,
            )
        elif await self._is_valid_cidr(target):
            ips = await self._expand_cidr(target)
            return ScanTarget(
                target=target, resolved_ips=ips, is_behind_cdn=False, is_cidr=True
            )
        else:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5

                ips = []

                # Try to resolve IPv4 addresses
                try:
                    a_answers = await resolver.resolve(target, "A")
                    ipv4_ips = [str(rdata) for rdata in a_answers]
                    logger.info(
                        f"Resolved IPv4 addresses for {target}: {', '.join(ipv4_ips)}"
                    )
                    ips.extend(ipv4_ips)
                except Exception as e:
                    logger.debug(f"No IPv4 addresses found for {target}: {str(e)}")

                # Try to resolve IPv6 addresses
                try:
                    aaaa_answers = await resolver.resolve(target, "AAAA")
                    ipv6_ips = [str(rdata) for rdata in aaaa_answers]
                    logger.info(
                        f"Resolved IPv6 addresses for {target}: {', '.jon(ipv6_ips)}"
                    )
                    ips.extend(ipv6_ips)
                except Exception as e:
                    logger.debug(f"No IPv6 addresses found for {target}: {str(e)}")

                if not ips:
                    logger.error(f"No IP addresses found for {target}")
                    return ScanTarget(
                        target=target, resolved_ips=[], is_behind_cdn=False
                    )

                is_behind_cdn = False
                for ip in ips:
                    if await self._is_ip_behind_cdn(ip):
                        is_behind_cdn = True
                        logger.warning(
                            f"Domain {target} appears to be behind a CDN (IP: {ip})"
                        )
                        break

                return ScanTarget(
                    target=target, resolved_ips=ips, is_behind_cdn=is_behind_cdn
                )
            except Exception as e:
                logger.error(f"Error resolving target {target}: {str(e)}")
                return ScanTarget(target=target, resolved_ips=[], is_behind_cdn=False)

    async def _process_discovered_port(self, line: str, scan_results: Dict) -> None:
        """
        Process a line containing discovered port information.

        Args:
            line: The line to process
            scan_results: Dictionary to store the results
        """
        try:
            parts = line.split()
            port = int(parts[3].split("/")[0])
            ip = parts[5]

            if ip not in scan_results["ip_results"]:
                scan_results["ip_results"][ip] = {"ports": []}

            port_entry = {
                "port": port,
                "state": "open",
                "protocol": "tcp",
                "service": None,
                "version": None,
            }
            scan_results["ip_results"][ip]["ports"].append(port_entry)
            logger.info(line)
        except (IndexError, ValueError) as e:
            logger.error(f"Error parsing Discovered line: {line}. {e}")

    async def _process_service_info(
        self, line: str, current_ip: str, scan_results: Dict
    ) -> None:
        """
        Process a line containing service information on a port.

        Args:
            line: The line to process
            current_ip: The current IP being processed
            scan_results: Dictionary to store the results
        """
        try:
            parts = line.strip().split()
            if len(parts) >= 3:
                port = int(parts[0].split("/")[0])
                service = parts[2]

                # Find the IP from scan results that has this port
                for ip, ip_data in scan_results["ip_results"].items():
                    for port_entry in ip_data["ports"]:
                        if port_entry["port"] == port:
                            port_entry["service"] = service
                            if len(parts) > 3:
                                # Get all parts after service name except 'syn-ack'
                                version_parts = [p for p in parts[3:] if p != "syn-ack"]
                                if version_parts:
                                    port_entry["version"] = " ".join(version_parts)
                            logger.info(
                                f"Updated service information for {ip}:{port} - {service}"
                            )
                            break
        except (IndexError, ValueError) as e:
            logger.error(f"Error parsing service line: {line}. {e}")

    async def _is_ipv6(self, ip: str) -> bool:
        """
        Check if an IP address is IPv6.

        Args:
            ip: The IP address to check

        Returns:
            bool: True if the IP is IPv6, False otherwise
        """
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    async def setup_base_command(self, target: ScanTarget) -> List[str]:
        """
        Set up the base command for RustScan.

        Args:
            target: The ScanTarget object

        Returns:
            List[str]: The base command for RustScan
        """
        base_cmd = [
            "rustscan",
            "-a",
            target.target,
            "-b",
            str(self.batch_size),
            "--ulimit",
            str(self.ulimit),
            "-t",
            str(self.timeout),
            "--tries",
            str(self.tries),
            "--accessible",
        ]

        # Check if any of the resolved IPs is IPv6
        has_ipv6 = False
        for ip in target.resolved_ips:
            if await self._is_ipv6(ip):
                has_ipv6 = True
                break

        if self.service_detection:
            nmap_flags = [
                "-Pn",
                "-T4",
                "-n",
            ]  # Nmap flags -> -Pn: No ping, -T4: Aggressive timing template. -n: No DNS resolution
            if has_ipv6:
                nmap_flags.insert(0, "-6")
            base_cmd.extend(["--"] + nmap_flags)

        else:
            if has_ipv6:
                base_cmd.extend(["--", "-6"])

        return base_cmd

    async def _execute_rustscan(self, target: ScanTarget) -> Dict:
        """
        Execute RustScan on a target.

        Args:
            target: The ScanTarget object

        Returns:
            Dict: The scan results
        """
        async with self.semaphore:
            try:
                logger.info(f"Starting scan for {target.target}")

                scan_results = {"ip_results": {}, "warnings": [], "errors": []}

                base_cmd = await self.setup_base_command(target)

                process = await asyncio.create_subprocess_exec(
                    *base_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                current_ip = None

                async def handle_output(stream, is_error=False):
                    nonlocal current_ip
                    while True:
                        line = await stream.readline()
                        if not line:
                            break
                        line_str = line.decode().strip()

                        if is_error:
                            if line_str not in scan_results["errors"]:
                                scan_results["errors"].append(line_str)
                                logger.error(f"RustScan Error: {line_str}")
                        else:
                            if "Scanning" in line_str:
                                try:
                                    # Extract IP from line
                                    start = line_str.find("(") + 1
                                    end = line_str.find(")")
                                    if start > 0 and end > start:
                                        current_ip = line_str[start:end]
                                except Exception as e:
                                    logger.error(
                                        f"Error extracting IP from line: {line_str}. {e}"
                                    )
                            elif "Discovered open port" in line_str:
                                await self._process_discovered_port(
                                    line_str, scan_results
                                )
                            elif (
                                "/tcp" in line_str
                                and "open" in line_str
                                and "Discovered" not in line_str
                            ):
                                await self._process_service_info(
                                    line_str, current_ip, scan_results
                                )
                            elif "Warning: " in line_str:
                                scan_results["warnings"].append(line_str)

                await asyncio.gather(
                    handle_output(process.stdout),
                    handle_output(process.stderr, is_error=True),
                )

                exit_code = await process.wait()

                return {
                    "timestamp": datetime.now().isoformat(),
                    "target": target.target,
                    "is_ip": target.is_ip,
                    "is_cidr": target.is_cidr,
                    "is_behind_cdn": target.is_behind_cdn,
                    "scan_results": scan_results,
                    "status": "completed",
                    "exit_code": exit_code,
                }

            except Exception as e:
                logger.error(f"Error scanning {target.target}: {str(e)}")
                if target.retry_count < target.max_retries:
                    target.retry_count += 1
                    logger.info(
                        f"Retrying scan for {target.target} (Attempt {target.retry_count}/{target.max_retries})"
                    )
                    await asyncio.sleep(self.retry_delay)
                    return await self._execute_rustscan(target)
                return {"target": target.target, "error": str(e), "status": "failed"}

    async def scan_target(self, target: str) -> Dict:
        """
        Scan a single target.

        Args:
            target: The target to scan

        Returns:
            Dict: The scan results
        """
        resolved = await self._resolve_target(target)
        if not resolved.resolved_ips:
            return {"target": target, "error": "Target resolution failed"}
        return await self._execute_rustscan(resolved)

    async def bulk_scan(self, targets: List[str]) -> List[Dict]:
        """
        Scan multiple targets.

        Args:
            targets: List of targets to scan

        Returns:
            List[Dict]: List of scan results
        """
        if not await verify_all_installations():
            return [
                {
                    "error": "Required tools (Rust/Cargo/RustScan) are not installed",
                    "status": "failed",
                    "targets": targets,
                }
            ]

        tasks = []
        for target in targets:
            tasks.append(self.scan_target(target))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                processed_results.append(
                    {
                        "error": str(result),
                        "status": "failed",
                        "type": result.__class__.__name__,
                    }
                )
            else:
                processed_results.append(result)

        return processed_results


async def run(
    rust_scanner: RustScanner,
    targets: List[str],
    output_dir: str = None,
    all_in_one: bool = False,
    run_bruteforce: bool = False,
    bruteforce_timeout: int = 300,
) -> Dict:
    """
    Run a scan on multiple targets, save the results, and optionally run bruteforce attacks.

    Args:
        rust_scanner: RustScanner instance
        targets: List of targets to scan
        output_dir: Directory to save results
        all_in_one: Whether to save all results in one file
        run_bruteforce: Whether to run bruteforce attacks on supported services
        bruteforce_timeout: Timeout for each bruteforce attack in seconds

    Returns:
        Dict: Combined results from scanning and bruteforcing
    """
    try:
        # Run the port scan
        scan_results = await rust_scanner.bulk_scan(targets)
        file_paths = await save_results(scan_results, output_dir, all_in_one)

        combined_results = {
            "scan_results": scan_results,
            "file_paths": file_paths,
            "bruteforce_results": {},
        }

        logger.info(f"Scanning open ports has been completed for {', '.join(targets)}")

        # Run bruteforce if enabled and we're in aggressive mode (with service detection)
        if run_bruteforce and rust_scanner.service_detection:
            try:
                # Import here to avoid circular imports
                from tools.bruteforce.integration import process_scan_results_with_hydra

                logger.info("Starting bruteforce attacks on detected services")

                bruteforce_results = await process_scan_results_with_hydra(
                    scan_results,
                    concurrent_limit=rust_scanner.concurrent_limit,
                    timeout=bruteforce_timeout,
                    org_name=output_dir.split("/")[1] if "/" in output_dir else "test",
                )

                combined_results["bruteforce_results"] = bruteforce_results

                if bruteforce_results:
                    # Log successful credentials found
                    creds_found = False
                    for ip, attacks in bruteforce_results.items():
                        for attack in attacks:
                            if attack["status"] == "success" and attack["credentials"]:
                                creds_found = True
                                logger.info(
                                    f"Found credentials for {ip}:{attack['port']} ({attack['protocol']})"
                                )

                    if not creds_found:
                        logger.info(
                            "No valid credentials were found during bruteforce attacks"
                        )

                    logger.info(
                        f"Completed bruteforce attacks on {len(bruteforce_results)} targets"
                    )

            except ImportError as e:
                logger.error(f"Bruteforce module not available: {str(e)}")
            except Exception as e:
                logger.error(f"Error during bruteforce attacks: {str(e)}")

        return combined_results
    except Exception as e:
        logger.error(f"Error during scan execution: {str(e)}")
        return {"error": str(e), "status": "failed", "targets": targets}


def main():
    """
    Main function for command-line execution.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Async RustScan Scanner")
    parser.add_argument(
        "targets", nargs="+", help="Domains, IPs, or CIDR ranges to scan"
    )
    parser.add_argument("-b", "--batch-size", type=int, default=30000)
    parser.add_argument("-u", "--ulimit", type=int, default=45000)
    parser.add_argument("-t", "--timeout", type=int, default=3500)
    parser.add_argument("-c", "--concurrent", type=int, default=5)
    parser.add_argument("--tries", type=int, default=1)
    parser.add_argument("-nsd", "--no-service-detection", action="store_true")
    parser.add_argument("-o", "--output")

    args = parser.parse_args()

    rust_scanner = RustScanner(
        batch_size=args.batch_size,
        ulimit=args.ulimit,
        timeout=args.timeout,
        concurrent_limit=args.concurrent,
        tries=args.tries,
        service_detection=not args.no_service_detection,
    )

    asyncio.run(run(rust_scanner, args.targets, args.output))


if __name__ == "__main__":
    main()
