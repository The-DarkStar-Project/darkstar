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
from scanners.nuclei import NucleiScanner, WordPressNucleiScanner
from colorama import Fore, Style, init
from scanners.recon import WordPressDetector
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

# Set up basic logging configuration
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("main")

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
        target_df (DataFrame): Parsed targets organized by type
        mode (int): Scan intrusiveness level (1=passive, 2=normal, 3=aggressive)
        org_domain (str): Organization name for database storage
    """

    def __init__(
        self,
        mode: int,
        targets: str,
        target_df: pd.DataFrame,
        org_name: str,
        bruteforce: bool = False,
        bruteforce_timeout: int = 300,
    ):
        self.all_targets = targets
        self.target_df = target_df
        self.mode = mode
        self.org_domain = org_name
        self.bruteforce = bruteforce
        self.bruteforce_timeout = bruteforce_timeout

    async def run(self):
        """
        Execute the scanning process based on the selected mode.

        Uses asynchronous execution to run independent tasks in parallel.
        """

        # ? Aggressive mode
        if self.mode == 3:
            all_scan_targets = get_scan_targets(self.target_df)

            # Define all the tasks we'll need to run
            async def run_port_discovery():
                logger.info(
                    f"{Fore.CYAN}Starting RustScan port discovery...{Style.RESET_ALL}"
                )

                # Create the output directory using our utility function
                rustscan_dir = prepare_output_directory(self.org_domain, "rustscanpy")

                # Initialize RustScanner with default settings and enable service detection
                rust_scanner = RustScanner(
                    batch_size=25000,
                    ulimit=35000,
                    timeout=3500,
                    concurrent_limit=2,
                    tries=1,
                    service_detection=True,  # Enable service detection in aggressive mode
                )

                # Run RustScan with individual files per target
                rustscan_results = await run_rustscan(
                    rust_scanner,
                    all_scan_targets,
                    output_dir=rustscan_dir,
                    all_in_one=False,  # Save separate file for each target
                    run_bruteforce=self.bruteforce,  # Enable bruteforce if specified
                    bruteforce_timeout=self.bruteforce_timeout,
                )

                # Process results
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

            async def run_bbot_scan():
                logger.info(
                    f"{Fore.CYAN}Starting bbot aggressive scan...{Style.RESET_ALL}"
                )

                # Run in a thread pool since bbot is likely not async-friendly
                with ThreadPoolExecutor() as executor:
                    bbot_scanner = BBotScanner(self.all_targets, self.org_domain)
                    await asyncio.get_event_loop().run_in_executor(
                        executor, lambda: bbot_scanner.run(mode="aggressive")
                    )

                # Get the generated filename
                filename = (
                    f"{bbot_scanner.folder}/{bbot_scanner.foldername}/subdomains.txt"
                )
                if not os.path.exists(filename):
                    filename = "/tmp/subs.txt"  # Fallback

                return {"bbot_scanner": bbot_scanner, "subdomains_file": filename}

            async def run_nuclei_scan(filename):
                logger.info("Running nuclei scan on discovered subdomains")

                with ThreadPoolExecutor() as executor:
                    nuclei_scanner = NucleiScanner(filename, self.org_domain)
                    await asyncio.get_event_loop().run_in_executor(
                        executor, nuclei_scanner.run
                    )

            async def detect_wordpress(filename):
                with ThreadPoolExecutor() as executor:
                    wordpress_domains = await asyncio.get_event_loop().run_in_executor(
                        executor, lambda: WordPressDetector().run(filename)
                    )

                logger.info(
                    f"{Fore.GREEN}[+] Wordpress Domains: {Fore.CYAN}{wordpress_domains}{Style.RESET_ALL}"
                )

                # Immediately kickoff WordPress Nuclei scan if WordPress sites are detected
                if wordpress_domains:
                    logger.info(
                        f"{Fore.CYAN}Immediately running WordPress-specific Nuclei scan on detected sites...{Style.RESET_ALL}"
                    )
                    await run_wordpress_nuclei(wordpress_domains)
                else:
                    logger.info(
                        "No WordPress sites detected, skipping WordPress-specific scans"
                    )

                return wordpress_domains

            async def run_wordpress_nuclei(domains):
                if domains:
                    logger.info(
                        f"Running WordPress-specific nuclei scan on {len(domains.split(',')) if isinstance(domains, str) else len(domains)} detected WordPress sites"
                    )

                    with ThreadPoolExecutor() as executor:
                        wp_scanner = WordPressNucleiScanner(domains, self.org_domain)
                        await asyncio.get_event_loop().run_in_executor(
                            executor, wp_scanner.run
                        )
                else:
                    logger.info(
                        "No WordPress sites provided, skipping WordPress-specific scans"
                    )

            # Execute port discovery and bbot in parallel
            port_discovery_task = asyncio.create_task(run_port_discovery())
            bbot_task = asyncio.create_task(run_bbot_scan())

            # Wait for both to complete
            port_results, bbot_results = await asyncio.gather(
                port_discovery_task, bbot_task
            )

            # Now run nuclei, wordpress detection
            tasks = [
                run_nuclei_scan(bbot_results["subdomains_file"]),
            ]

            # Detect WordPress and automatically run WordPress-specific Nuclei
            wordpress_domains = await detect_wordpress(bbot_results["subdomains_file"])

            # No need to add WordPress-specific nuclei task as it's now triggered directly after detection
            # tasks.append(run_wordpress_nuclei(wordpress_domains))

            # Wait for all remaining tasks to complete
            await asyncio.gather(*tasks)

        # ? Normal mode
        elif self.mode == 2:
            all_scan_targets = get_scan_targets(self.target_df)

            # Run these tasks in parallel
            tasks = []

            # Define bbot normal task - using only CLI targets
            async def run_bbot_normal():
                logger.info(
                    f"{Fore.CYAN}Starting bbot normal scan using CLI targets...{Style.RESET_ALL}"
                )

                with ThreadPoolExecutor() as executor:
                    bbot_scanner = BBotScanner(self.all_targets, self.org_domain)
                    await asyncio.get_event_loop().run_in_executor(
                        executor, lambda: bbot_scanner.run(mode="normal")
                    )

                return {"bbot_scanner": bbot_scanner}

            tasks.append(run_bbot_normal())

            # Define rustscan task with CLI targets
            async def run_port_scan():
                logger.info(
                    f"{Fore.CYAN}Starting RustScan on CLI targets...{Style.RESET_ALL}"
                )

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
                    all_scan_targets,
                    output_dir=rustscan_dir,
                    all_in_one=False,
                    run_bruteforce=False,
                )

                scan_processed = process_scan_results(rustscan_results, self.org_domain)
                return {"scan_processed": scan_processed}

            tasks.append(run_port_scan())

            # Run all tasks in parallel
            await asyncio.gather(*tasks)

        # ? Passive mode
        elif self.mode == 1:
            logger.info(
                f"{Fore.CYAN}Starting passive scan using CLI targets only...{Style.RESET_ALL}"
            )
            with ThreadPoolExecutor() as executor:
                bbot_scanner = BBotScanner(self.all_targets, self.org_domain)
                await asyncio.get_event_loop().run_in_executor(
                    executor, lambda: bbot_scanner.run(mode="passive")
                )

        # ? Attack Surface Mode
        elif self.mode == 4:
            logger.info(f"{Fore.CYAN}Starting Attack Surface Mode...{Style.RESET_ALL}")

            # First run bbot attack_surface scan and wait for it to complete
            async def run_attack_surface_scan():
                logger.info(
                    f"{Fore.CYAN}Running bbot attack surface scan...{Style.RESET_ALL}"
                )

                with ThreadPoolExecutor() as executor:
                    bbot_scanner = BBotScanner(self.all_targets, self.org_domain)
                    await asyncio.get_event_loop().run_in_executor(
                        executor, lambda: bbot_scanner.run(mode="attack_surface")
                    )

                # Get the generated output files
                subdomains_file = (
                    f"{bbot_scanner.folder}/{bbot_scanner.foldername}/subdomains.txt"
                )
                ips_file = f"{bbot_scanner.folder}/{bbot_scanner.foldername}/ips.txt"

                if not os.path.exists(subdomains_file):
                    subdomains_file = "/tmp/subs.txt"  # Fallback

                if not os.path.exists(ips_file):
                    ips_file = "/tmp/ips.txt"  # Fallback

                return {
                    "bbot_scanner": bbot_scanner,
                    "subdomains_file": subdomains_file,
                    "ips_file": ips_file,
                }

            # Execute attack surface scan and wait for completion
            bbot_results = await run_attack_surface_scan()

            logger.info(
                f"{Fore.GREEN}[+] Attack surface mapping completed. Running subsequent scans on discovered assets...{Style.RESET_ALL}"
            )

            # Now run follow-up scans based on bbot results
            tasks = []

            # Run nuclei on discovered subdomains
            async def run_nuclei_on_discovered():
                if (
                    os.path.exists(bbot_results["subdomains_file"])
                    and os.path.getsize(bbot_results["subdomains_file"]) > 0
                ):
                    logger.info(
                        f"{Fore.CYAN}Running nuclei on discovered subdomains...{Style.RESET_ALL}"
                    )

                    with ThreadPoolExecutor() as executor:
                        nuclei_scanner = NucleiScanner(
                            bbot_results["subdomains_file"], self.org_domain
                        )
                        await asyncio.get_event_loop().run_in_executor(
                            executor, nuclei_scanner.run
                        )
                else:
                    logger.warning(
                        f"{Fore.YELLOW}No subdomains discovered, skipping nuclei scan{Style.RESET_ALL}"
                    )

            tasks.append(run_nuclei_on_discovered())

            # Run RustScan on discovered IPs
            async def run_rustscan_on_discovered():
                if (
                    os.path.exists(bbot_results["ips_file"])
                    and os.path.getsize(bbot_results["ips_file"]) > 0
                ):
                    logger.info(
                        f"{Fore.CYAN}Running RustScan on discovered IPs...{Style.RESET_ALL}"
                    )

                    # Read IPs from file
                    with open(bbot_results["ips_file"], "r") as f:
                        discovered_ips = [
                            line.strip() for line in f.readlines() if line.strip()
                        ]

                    if discovered_ips:
                        rustscan_dir = prepare_output_directory(
                            self.org_domain, "rustscan_discovered"
                        )

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
                            discovered_ips,
                            output_dir=rustscan_dir,
                            all_in_one=False,
                            run_bruteforce=self.bruteforce,
                            bruteforce_timeout=self.bruteforce_timeout,
                        )

                        scan_processed = process_scan_results(
                            rustscan_results, self.org_domain
                        )

                        # Process bruteforce results if present
                        if (
                            isinstance(rustscan_results, dict)
                            and "bruteforce_results" in rustscan_results
                        ):
                            bruteforce_processed = process_bruteforce_results(
                                rustscan_results["bruteforce_results"]
                            )
                    else:
                        logger.warning(
                            f"{Fore.YELLOW}IP file exists but contains no valid IPs{Style.RESET_ALL}"
                        )
                else:
                    logger.warning(
                        f"{Fore.YELLOW}No IPs discovered, skipping RustScan{Style.RESET_ALL}"
                    )

            tasks.append(run_rustscan_on_discovered())

            # Detect WordPress sites among discovered domains and immediately scan them
            async def detect_and_scan_wordpress():
                if (
                    os.path.exists(bbot_results["subdomains_file"])
                    and os.path.getsize(bbot_results["subdomains_file"]) > 0
                ):
                    logger.info(
                        f"{Fore.CYAN}Detecting WordPress sites among discovered domains...{Style.RESET_ALL}"
                    )

                    with ThreadPoolExecutor() as executor:
                        wordpress_domains = (
                            await asyncio.get_event_loop().run_in_executor(
                                executor,
                                lambda: WordPressDetector().run(
                                    bbot_results["subdomains_file"]
                                ),
                            )
                        )

                    logger.info(
                        f"{Fore.GREEN}[+] WordPress Domains: {Fore.CYAN}{wordpress_domains}{Style.RESET_ALL}"
                    )

                    # Immediately run WordPress-specific scans if sites were found
                    if wordpress_domains:
                        logger.info(
                            f"{Fore.CYAN}Immediately running WordPress-specific nuclei scan on detected sites...{Style.RESET_ALL}"
                        )

                        with ThreadPoolExecutor() as executor:
                            wp_scanner = WordPressNucleiScanner(
                                wordpress_domains, self.org_domain
                            )
                            await asyncio.get_event_loop().run_in_executor(
                                executor, wp_scanner.run
                            )
                    else:
                        logger.info(
                            "No WordPress sites found, skipping WordPress-specific scans"
                        )

            tasks.append(detect_and_scan_wordpress())

            # Wait for all tasks to complete
            await asyncio.gather(*tasks)

        # ─── openvas mode via FastAPI ───
        elif self.mode == 5:
            all_scan_targets = get_scan_targets(self.target_df)
            logger.info(
                f"{Fore.CYAN}Discovered Targets: {Fore.YELLOW}{all_scan_targets}{Style.RESET_ALL}"
            )

            # Initialize OpenVAS scanner and run scan
            openvas_scanner = OpenVASScanner(org_name=self.org_domain)
            await openvas_scanner.scan_targets(all_scan_targets)

            logger.info(f"{Fore.GREEN}[+] OpenVAS scanning completed{Style.RESET_ALL}")

        else:
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

    # ? Argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Fill in the CIDR, IP or domain (without http/https) to scan",
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=int,
        required=True,
        help="Scan intrusiveness: 1. passive, 2. normal, 3. aggressive, 4. attack surface",
        choices=[1, 2, 3, 4, 5],
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

    # ? Parse arguments
    if args is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(args)

    # Banner
    logger.info(f"{Fore.BLUE}{'=' * 60}")
    logger.info(f"{Fore.CYAN}DARKSTAR SECURITY SCANNING FRAMEWORK")
    logger.info(
        f"{Fore.CYAN}Mode: {Fore.YELLOW}{args.mode}{Fore.CYAN} | Target(s): {Fore.YELLOW}{args.target}{Fore.CYAN} | Organization: {Fore.YELLOW}{args.domain}"
    )
    logger.info(f"{Fore.BLUE}{'=' * 60}{Style.RESET_ALL}")

    # Parse targets
    target_df = parse_targets(args.target)

    # Display scan mode information
    mode_info = {
        1: f"{Fore.GREEN}PASSIVE MODE{Style.RESET_ALL} - Light reconnaissance without active scanning",
        2: f"{Fore.YELLOW}NORMAL MODE{Style.RESET_ALL} - Standard scanning with passive and selected active modules",
        3: f"{Fore.RED}AGGRESSIVE MODE{Style.RESET_ALL} - Full scanning with all active and aggressive modules",
        4: f"{Fore.RED}ATTACK SURFACE MODE{Style.RESET_ALL} - Attack surface mapping with custom modules",
        5: f"{Fore.RED}Openvas{Style.RESET_ALL} - Testing OpenVAS integration",
    }
    logger.info(f"Initializing scan in {mode_info[args.mode]}")

    # ? Run the scanner
    scanner = worker(
        mode=args.mode,
        targets=args.target,
        target_df=target_df,
        org_name=args.domain,
        bruteforce=args.bruteforce,
        bruteforce_timeout=args.bruteforce_timeout,
    )

    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
