#  *
#  * This file is part of Darkstar.
#  *
#  * Darkstar is free software: you can redistribute it and/or modify
#  * it under the terms of the GNU General Public License as published by
#  * the Free Software Foundation, either version 3 of the License, or
#  * (at your option) any later version.
#  *
#  * Darkstar is distributed in the hope that it will be useful,
#  * but WITHOUT ANY WARRANTY; without even the implied warranty of
#  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  * GNU General Public License for more details.
#  *
#  * You should have received a copy of the GNU General Public License
#  * along with Darkstar. If not, see <https://www.gnu.org/licenses/>.
#  *

import argparse
import pandas as pd
import warnings
from scanners.bbot import BBotScanner
from scanners.nuclei import NucleiScanner, NucleiMode
from colorama import Fore, Style, init
from scanners.recon import WordPressDetector
from scanners.asteroid_scanner import AsteroidScanner
from scanners.email import MailSecurityScanner
import asyncio
import os
from scanners.portscan import RustScanner, run_rustscan, process_scan_results
from tools.bruteforce import process_bruteforce_results
from core.utils import (
    categorize_targets,
    create_target_dataframe,
    log_target_summary,
    get_scan_targets,
    prepare_output_directory,
)
import logging
from concurrent.futures import ThreadPoolExecutor
from openvas.openvas_scanner import OpenVASScanner
from typing import Literal
import ipaddress

# Set up basic logging configuration
logger = logging.getLogger("main")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

warnings.filterwarnings("ignore")
init(autoreset=True)


def setup_env_from_args(args=None):
    """Load environment variables from .env file."""
    # Create a minimal argument parser just to grab the --envfile parameter.
    env_parser = argparse.ArgumentParser(add_help=False)
    env_parser.add_argument(
        "-env",
        "--envfile",
        help="envfile location, default is /app/.env",
        default="/app/.env",
        required=False,
    )

    # Only parse sys.argv if args is not provided (for testing)
    if args is None:
        env_args, _ = env_parser.parse_known_args()
    else:
        env_args, _ = env_parser.parse_known_args(args)

    # Load environment from file if it exists
    env_file = env_args.envfile if hasattr(env_args, "envfile") else "/app/.env"
    if os.path.exists(env_file):
        try:
            import dotenv

            dotenv.load_dotenv(env_file)
            logger.info(f"Loaded environment from {env_file}")
        except ImportError:
            logger.warning("python-dotenv not available, loading env manually")
            # Manual .env file loading
            with open(env_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        os.environ[key.strip()] = value.strip()
    else:
        logger.warning(f"Environment file {env_file} not found, using defaults")

    return env_args


class worker:
    """
    Main worker class that orchestrates and executes scanning operations.

    This class is responsible for running the selected scanning modules
    based on the specified mode and managing the workflow between them.

    Attributes:
        all_targets (str): Raw target string from command line arguments
        mode (int): Scan intrusiveness level (1=passive, 2=normal, 3=aggressive)
        org_domain (str): Organization name for database storage
    """

    def __init__(
        self,
        mode: int | None,
        scanner: str | None,
        targets: str,
        org_name: str,
        bruteforce: bool = False,
        bruteforce_timeout: int = 300,
    ):
        self.targets = targets

        self.all_targets = targets
        # Read from file if it exists
        if os.path.exists(self.targets):
            with open(self.targets, "r") as f:
                self.all_targets = ",".join([line.strip() for line in f])

        self.target_df = parse_targets(targets)
        self.mode = mode
        self.scanner = scanner
        self.org_domain = org_name
        self.bruteforce = bruteforce
        self.bruteforce_timeout = bruteforce_timeout

    async def run_bbot(
        self, mode: Literal["passive", "normal", "aggressive", "attack_surface"]
    ):
        logger.info(
            f"{Fore.CYAN}Starting bbot {mode} scan on targets...{Style.RESET_ALL}"
        )

        with ThreadPoolExecutor() as executor:
            bbot_scanner = BBotScanner(self.all_targets, self.org_domain)
            await asyncio.get_event_loop().run_in_executor(
                executor, lambda: bbot_scanner.run(mode=mode)
            )

        # Get the generated filenames
        subdomains_file = (
            f"{bbot_scanner.folder}/{bbot_scanner.foldername}/subdomains.txt"
        )
        ips_file = f"{bbot_scanner.folder}/{bbot_scanner.foldername}/ips.txt"
        emails_file = f"{bbot_scanner.folder}/{bbot_scanner.foldername}/emails.txt"

        targets = [
            target.strip() for target in self.all_targets.split(",") if target.strip()
        ]
        domains = []
        ips = []

        for target in targets:
            try:
                ipaddress.ip_address(target)
                ips.append(target)  # Valid IP address
            except ValueError:
                # If it raises ValueError, it's not a valid IP address, so it's a domain
                domains.append(target)

        if not os.path.exists(subdomains_file):
            with open(subdomains_file, "w") as f:
                # If no subdomains found, write the domains from all_targets directly
                for domain in domains:
                    f.write(f"{domain}\n")

        if not os.path.exists(ips_file):
            with open(ips_file, "w") as f:
                # If no IPs found, write the IPs from all_targets directly
                for ip in ips:
                    f.write(f"{ip}\n")
        
        logger.info("Running Email Security Scanner")

        with ThreadPoolExecutor() as executor:
            email_scanner = MailSecurityScanner(org_name=self.org_domain)
            await asyncio.get_event_loop().run_in_executor(
                executor, lambda: email_scanner.run(subdomains_file, emails_file)
            )

        return {
            "bbot_scanner": bbot_scanner,
            "subdomains_file": subdomains_file,
            "ips_file": ips_file,
            "emails_file": emails_file,
        }

    async def run_port_scan(self, targets):
        logger.info(f"{Fore.CYAN}Starting RustScan on targets...{Style.RESET_ALL}")

        rustscan_dir = prepare_output_directory(self.org_domain, "rustscanpy")

        rust_scanner = RustScanner(
            batch_size=25000,
            ulimit=35000,
            timeout=3500,
            concurrent_limit=2,
            tries=1,
            service_detection=True,
        )

        rustscan_results = await run_rustscan(
            rust_scanner,
            targets,
            output_dir=rustscan_dir,
            all_in_one=False,
            run_bruteforce=self.bruteforce,  # Enable bruteforce if specified
            bruteforce_timeout=self.bruteforce_timeout,
        )

        scan_processed = process_scan_results(rustscan_results, self.org_domain)

        # Process bruteforce results if present
        bruteforce_processed = None
        if (
            isinstance(rustscan_results, dict)
            and "bruteforce_results" in rustscan_results
        ):
            bruteforce_processed = process_bruteforce_results(
                rustscan_results["bruteforce_results"]
            )

        return {
            "rustscan_results": rustscan_results,
            "scan_processed": scan_processed,
            "bruteforce_processed": bruteforce_processed,
        }

    async def run_nuclei(self, target, mode: NucleiMode = NucleiMode.STANDARD):
        logger.info("Running Nuclei scan with mode: {mode.value}")

        with ThreadPoolExecutor() as executor:
            nuclei_scanner = NucleiScanner(target, self.org_domain, mode=mode)
            await asyncio.get_event_loop().run_in_executor(executor, nuclei_scanner.run)

    async def detect_wordpress(self, target):
        with ThreadPoolExecutor() as executor:
            wordpress_domains = await asyncio.get_event_loop().run_in_executor(
                executor, lambda: WordPressDetector().run(target)
            )

        logger.info(
            f"{Fore.GREEN}[+] Wordpress Domains: {Fore.CYAN}{wordpress_domains}{Style.RESET_ALL}"
        )

        return wordpress_domains

    async def detect_wordpress_and_run_nuclei(self, target):
        logger.info(
            f"{Fore.CYAN}Detecting WordPress sites and running Nuclei scan...{Style.RESET_ALL}"
        )
        # Detect WordPress and automatically run WordPress-specific Nuclei
        wordpress_domains = await self.detect_wordpress(target)

        # Immediately kickoff WordPress Nuclei scan if WordPress sites are detected
        if wordpress_domains:
            logger.info(
                f"{Fore.CYAN}Immediately running WordPress-specific Nuclei scan on detected sites...{Style.RESET_ALL}"
            )
            await self.run_nuclei(wordpress_domains, mode=NucleiMode.WORDPRESS)
        else:
            logger.info(
                "No WordPress sites detected, skipping WordPress-specific scans"
            )

    async def run_openvas_scan(self, targets):
        logger.info("Running OpenVAS scan on specified targets")

        openvas_scanner = OpenVASScanner(org_name=self.org_domain)
        await openvas_scanner.scan_targets(targets)

    async def run_asteroid(self, target, mode: Literal["normal", "aggressive"]):
        logger.info("Running Asteroid scan")

        with ThreadPoolExecutor() as executor:
            asteroid_scanner = AsteroidScanner(target, self.org_domain)
            await asyncio.get_event_loop().run_in_executor(
                executor, lambda: asteroid_scanner.run(mode=mode)
            )        

    async def passive_scan(self):
        await self.run_bbot(mode="passive")

    async def normal_scan(self):
        all_scan_targets = get_scan_targets(self.target_df)

        # Run these tasks in parallel
        tasks = [
            self.run_bbot(mode="normal"),
            self.run_port_scan(all_scan_targets),
            self.run_openvas_scan(all_scan_targets),
        ]

        # Run all tasks in parallel
        bbot_results, port_results, _ = await asyncio.gather(*tasks)

        # Now run wordpress detection and nuclei scan, and Asteroid
        tasks = [
            self.detect_wordpress_and_run_nuclei(bbot_results["subdomains_file"]),
            self.run_nuclei(bbot_results["subdomains_file"], mode=NucleiMode.NETWORK),
            self.run_asteroid(bbot_results["subdomains_file"], mode="normal"),
        ]
        await asyncio.gather(*tasks)

    async def aggressive_scan(self):
        all_scan_targets = get_scan_targets(self.target_df)

        # Execute port discovery, bbot and openvas in parallel
        tasks = [
            self.run_bbot(mode="aggressive"),
            self.run_port_scan(all_scan_targets),
            self.run_openvas_scan(all_scan_targets),
        ]

        # Wait for all to complete
        bbot_results, port_results, _ = await asyncio.gather(*tasks)

        # Now run nucle and wordpress detection and nuclei and Asteroid
        tasks = [
            self.run_nuclei(bbot_results["subdomains_file"]),
            self.run_nuclei(bbot_results["subdomains_file"], mode=NucleiMode.NETWORK),
            self.detect_wordpress_and_run_nuclei(bbot_results["subdomains_file"]),
            self.run_asteroid(bbot_results["subdomains_file"], mode="aggressive"),
        ]

        # Wait for all remaining tasks to complete
        await asyncio.gather(*tasks)

    async def attack_surface_scan(self):
        logger.info(f"{Fore.CYAN}Starting Attack Surface Mode...{Style.RESET_ALL}")

        # Execute attack surface scan and wait for completion
        bbot_results = await self.run_bbot(mode="attack_surface")

        logger.info(
            f"{Fore.GREEN}[+] Attack surface mapping completed. Running subsequent scans on discovered assets...{Style.RESET_ALL}"
        )

        # Run RustScan on discovered IPs
        scan_processed = None
        if (
            os.path.exists(bbot_results["ips_file"])
            and os.path.getsize(bbot_results["ips_file"]) > 0
        ):
            logger.info(
                f"{Fore.CYAN}Running RustScan on discovered IPs...{Style.RESET_ALL}"
            )

            # Read IPs from file
            with open(bbot_results["ips_file"], "r") as attack_surface_file:
                discovered_ips = [
                    line.strip()
                    for line in attack_surface_file.readlines()
                    if line.strip()
                ]

            if discovered_ips:
                _, scan_processed, _ = await self.run_port_scan(discovered_ips)
            else:
                logger.warning(
                    f"{Fore.YELLOW}IP file exists but contains no valid IPs{Style.RESET_ALL}"
                )
        else:
            logger.warning(
                f"{Fore.YELLOW}No IPs discovered, skipping RustScan{Style.RESET_ALL}"
            )

        # Write the discovered subdomains from bbot_results["domains_file"] and IP/Port combinations from scan_processed to a file
        with open(f"{self.org_domain}_attack_surface.txt", "w") as attack_surface_file:
            if os.path.exists(bbot_results["subdomains_file"]):
                with open(bbot_results["subdomains_file"], "r") as subdomains_file:
                    subdomains = subdomains_file.readlines()
                    attack_surface_file.writelines(subdomains)

            if scan_processed and "ports_by_host" in scan_processed:
                for ip, ports in scan_processed["ports_by_host"].items():
                    for port in ports:
                        attack_surface_file.write(f"{ip}:{port}\n")

    async def run(self):
        """
        Execute the scanning process based on the selected mode or scanner.

        Uses asynchronous execution to run independent tasks in parallel.
        """
        if self.scanner:
            match self.scanner:
                case "bbot_passive":
                    await self.run_bbot(mode="passive")
                case "bbot_normal":
                    await self.run_bbot(mode="normal")
                case "bbot_aggressive":
                    await self.run_bbot(mode="aggressive")
                case "bbot_attack_surface":
                    await self.run_bbot(mode="attack_surface")
                case "rustscan":
                    all_scan_targets = get_scan_targets(self.target_df)
                    await self.run_port_scan(all_scan_targets)
                case "nuclei":
                    await self.run_nuclei(self.all_targets)
                case "nucleinetwork":
                    await self.run_nuclei(self.all_targets, mode=NucleiMode.NETWORK)
                case "wordpressnuclei":
                    await self.detect_wordpress_and_run_nuclei(self.all_targets)
                case "openvas":
                    all_scan_targets = get_scan_targets(self.target_df)
                    await self.run_openvas_scan(all_scan_targets)
                case "asteroid_normal":
                    await self.run_asteroid(self.all_targets, mode="normal")
                case "asteroid_aggressive":
                    await self.run_asteroid(self.all_targets, mode="aggressive")
                case _:
                    logger.error(
                        f"{Fore.RED}[-] Invalid scanner {self.scanner} specified{Style.RESET_ALL}"
                    )

        else:
            match self.mode:
                case 1:  # 1 - Passive mode
                    await self.passive_scan()
                case 2:  # 2 - Normal mode
                    await self.normal_scan()
                case 3:  # 3 - Aggressive mode
                    await self.aggressive_scan()
                case 4:  # 4 - Attack Surface Mode
                    await self.attack_surface_scan()
                case _:  # Invalid mode
                    logger.error(
                        f"{Fore.RED}[-] Invalid mode {self.mode} specified{Style.RESET_ALL}"
                    )


def parse_targets(targets_str: str) -> pd.DataFrame:
    """
    Parse and categorize targets by type using proper validation.
    Returns:
        pd.DataFrame: DataFrame with targets categorized by type
    """
    targets = [target.strip() for target in targets_str.split(",") if target.strip()]
    if not targets:
        logger.warning(f"{Fore.YELLOW}[!] No valid targets provided{Style.RESET_ALL}")
        return pd.DataFrame()
    categorized = categorize_targets(targets)
    log_target_summary(categorized)

    return create_target_dataframe(categorized)


def setup_parser():
    """
    Set up the command line argument parser for DarkStar.

    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Fill in the CIDR, IP or domain (without http/https) to scan. Separate multiple targets by comma's. Can also be a file with a list of targets (one per line).",
    )
    parser.add_argument(
        "-d",
        "--domain",
        help="The organisation name necessary for database selection",
        required=True,
    )
    parser.add_argument(
        "--bruteforce",
        action="store_true",
        help="Enable bruteforce attacks on discovered services",
    )
    parser.add_argument(
        "--bruteforce-timeout",
        type=int,
        default=300,
        help="Timeout for each bruteforce attack in seconds",
    )
    parser.add_argument(
        "-env",
        "--envfile",
        help="envfile location, default is /app/.env",
        default="/app/.env",
        required=False,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging for debugging purposes",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-m",
        "--mode",
        type=int,
        help="Scan intrusiveness: 1. passive, 2. normal, 3. aggressive, 4. attack surface",
        choices=[1, 2, 3, 4],
    )
    group.add_argument(
        "-s",
        "--scanner",
        type=str,
        help="Select a specific scanner to run (e.g., bbot, nuclei, openvas, asteroid). If not specified, all scanners will be run based on the mode.",
        choices=[
            "bbot_passive",
            "bbot_normal",
            "bbot_aggressive",
            "bbot_attack_surface",
            "rustscan",
            "nuclei",
            "nucleinetwork",
            "wordpressnuclei",
            "openvas",
            "asteroid_normal",
            "asteroid_aggressive",
        ],
    )
    return parser


def display_banner(args):
    """
    Display the DarkStar banner with scan mode, target and domain information.

    Args:
        args: Parsed command line arguments containing mode, target and domain
    """
    logger.info(f"{Fore.BLUE}{'=' * 60}")
    logger.info(f"{Fore.CYAN}DARKSTAR SECURITY SCANNING FRAMEWORK")
    logger.info(
        f"{Fore.CYAN}Mode: {Fore.YELLOW}{args.mode}{Fore.CYAN} | Target(s): {Fore.YELLOW}{args.target}{Fore.CYAN} | Organization: {Fore.YELLOW}{args.domain}"
    )
    logger.info(f"{Fore.BLUE}{'=' * 60}{Style.RESET_ALL}")


def main(args=None):
    """
    Main function that parses arguments and initializes the scanning process.

    Handles command line arguments, parses and categorizes targets by type,
    and initializes the worker to run the scanning process.

    Args:
        args: Command line arguments (for testing)
    """
    # Initialize environment variables
    setup_env_from_args(args)

    # Argument parser
    parser = setup_parser()

    # Parse arguments
    if args is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(args)

    # Verbose logging
    if args.verbose:
        logger.info("Enabling verbose logging")
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    # Banner
    display_banner(args)

    # Display scan mode information
    mode_info = {
        1: f"{Fore.GREEN}PASSIVE MODE{Style.RESET_ALL} - Light reconnaissance without active scanning",
        2: f"{Fore.YELLOW}NORMAL MODE{Style.RESET_ALL} - Standard scanning with passive and selected active modules",
        3: f"{Fore.RED}AGGRESSIVE MODE{Style.RESET_ALL} - Full scanning with all active and aggressive modules",
        4: f"{Fore.RED}ATTACK SURFACE MODE{Style.RESET_ALL} - Attack surface mapping with custom modules",
    }
    if args.mode:
        logger.info(f"Initializing scan in {mode_info[args.mode]}")
    # Run the scanner

    scanner = worker(
        mode=args.mode,
        scanner=args.scanner,
        targets=args.target,
        org_name=args.domain,
        bruteforce=args.bruteforce,
        bruteforce_timeout=args.bruteforce_timeout,
    )

    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
