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

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any
from colorama import Fore, Style

from scanners.base_scanner import BaseScanner
from scanners.bbot import BBotScanner
from scanners.nuclei import NucleiScanner, WordPressNucleiScanner
from scanners.recon import WordPressDetector
from scanners.portscan import RustScanner, run_rustscan, process_scan_results
from tools.bruteforce import process_bruteforce_results
from core.utils import prepare_output_directory

logger = logging.getLogger("aggressive_scanner")


class AggressiveScanner(BaseScanner):
    """
    Aggressive scanner implementation for comprehensive scanning.

    This scanner performs full scanning with all active and aggressive modules,
    including port scanning, vulnerability scanning, and WordPress detection.
    """

    async def run(self) -> Dict[str, Any]:
        """
        Execute aggressive scanning with full suite of tools.

        Returns:
            Dict containing comprehensive scan results
        """
        all_scan_targets = self.get_scan_targets()

        # Define port discovery task
        async def run_port_discovery():
            logger.info(
                f"{Fore.CYAN}Starting RustScan port discovery...{Style.RESET_ALL}"
            )

            rustscan_dir = prepare_output_directory(self.org_name, "rustscanpy")

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
                run_bruteforce=self.bruteforce,
                bruteforce_timeout=self.bruteforce_timeout,
            )

            scan_processed = process_scan_results(rustscan_results, self.org_name)

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

        # Define bbot scan task
        async def run_bbot_scan():
            logger.info(f"{Fore.CYAN}Starting bbot aggressive scan...{Style.RESET_ALL}")

            with ThreadPoolExecutor() as executor:
                bbot_scanner = BBotScanner(self.targets, self.org_name)
                await asyncio.get_event_loop().run_in_executor(
                    executor, lambda: bbot_scanner.run(mode="aggressive")
                )

            filename = f"{bbot_scanner.folder}/{bbot_scanner.foldername}/subdomains.txt"
            if not os.path.exists(filename):
                filename = "/tmp/subs.txt"

            return {"bbot_scanner": bbot_scanner, "subdomains_file": filename}

        # Execute port discovery and bbot in parallel
        port_discovery_task = asyncio.create_task(run_port_discovery())
        bbot_task = asyncio.create_task(run_bbot_scan())

        port_results, bbot_results = await asyncio.gather(
            port_discovery_task, bbot_task
        )

        # Run nuclei scan
        async def run_nuclei_scan(filename):
            logger.info("Running nuclei scan on discovered subdomains")

            with ThreadPoolExecutor() as executor:
                nuclei_scanner = NucleiScanner(filename, self.org_name)
                await asyncio.get_event_loop().run_in_executor(
                    executor, nuclei_scanner.run
                )

        # Detect WordPress and run WordPress-specific scans
        async def detect_and_scan_wordpress(filename):
            with ThreadPoolExecutor() as executor:
                wordpress_domains = await asyncio.get_event_loop().run_in_executor(
                    executor, lambda: WordPressDetector().run(filename)
                )

            logger.info(
                f"{Fore.GREEN}[+] WordPress Domains: {Fore.CYAN}{wordpress_domains}{Style.RESET_ALL}"
            )

            if wordpress_domains:
                logger.info(
                    f"{Fore.CYAN}Running WordPress-specific Nuclei scan...{Style.RESET_ALL}"
                )
                with ThreadPoolExecutor() as executor:
                    wp_scanner = WordPressNucleiScanner(
                        wordpress_domains, self.org_name
                    )
                    await asyncio.get_event_loop().run_in_executor(
                        executor, wp_scanner.run
                    )
            else:
                logger.info(
                    "No WordPress sites detected, skipping WordPress-specific scans"
                )

            return wordpress_domains

        # Run final scans
        tasks = [
            run_nuclei_scan(bbot_results["subdomains_file"]),
            detect_and_scan_wordpress(bbot_results["subdomains_file"]),
        ]

        final_results = await asyncio.gather(*tasks)

        return {
            "port_results": port_results,
            "bbot_results": bbot_results,
            "wordpress_domains": final_results[1],
        }
