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

logger = logging.getLogger("attack_surface_scanner")


class AttackSurfaceScanner(BaseScanner):
    """
    Attack surface scanner for comprehensive asset discovery and mapping.

    This scanner focuses on discovering and mapping the complete attack surface
    before conducting targeted scans on discovered assets.
    """

    async def run(self) -> Dict[str, Any]:
        """
        Execute attack surface mapping followed by targeted scans.

        Returns:
            Dict containing attack surface mapping and scan results
        """
        logger.info(f"{Fore.CYAN}Starting Attack Surface Mode...{Style.RESET_ALL}")

        # First run bbot attack_surface scan and wait for completion
        bbot_results = await self._run_attack_surface_scan()

        logger.info(
            f"{Fore.GREEN}[+] Attack surface mapping completed. Running subsequent scans...{Style.RESET_ALL}"
        )

        # Run follow-up scans based on bbot results
        tasks = [
            self._run_nuclei_on_discovered(bbot_results),
            self._run_rustscan_on_discovered(bbot_results),
            self._detect_and_scan_wordpress(bbot_results),
        ]

        scan_results = await asyncio.gather(*tasks)

        return {
            "bbot_results": bbot_results,
            "nuclei_results": scan_results[0],
            "rustscan_results": scan_results[1],
            "wordpress_results": scan_results[2],
        }

    async def _run_attack_surface_scan(self) -> Dict[str, Any]:
        """Run the initial attack surface mapping scan."""
        logger.info(f"{Fore.CYAN}Running bbot attack surface scan...{Style.RESET_ALL}")

        with ThreadPoolExecutor() as executor:
            bbot_scanner = BBotScanner(self.targets, self.org_name)
            await asyncio.get_event_loop().run_in_executor(
                executor, lambda: bbot_scanner.run(mode="attack_surface")
            )

        subdomains_file = (
            f"{bbot_scanner.folder}/{bbot_scanner.foldername}/subdomains.txt"
        )
        ips_file = f"{bbot_scanner.folder}/{bbot_scanner.foldername}/ips.txt"

        if not os.path.exists(subdomains_file):
            subdomains_file = "/tmp/subs.txt"
        if not os.path.exists(ips_file):
            ips_file = "/tmp/ips.txt"

        return {
            "bbot_scanner": bbot_scanner,
            "subdomains_file": subdomains_file,
            "ips_file": ips_file,
        }

    async def _run_nuclei_on_discovered(
        self, bbot_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run nuclei scan on discovered subdomains."""
        if (
            os.path.exists(bbot_results["subdomains_file"])
            and os.path.getsize(bbot_results["subdomains_file"]) > 0
        ):
            logger.info(
                f"{Fore.CYAN}Running nuclei on discovered subdomains...{Style.RESET_ALL}"
            )

            with ThreadPoolExecutor() as executor:
                nuclei_scanner = NucleiScanner(
                    bbot_results["subdomains_file"], self.org_name
                )
                await asyncio.get_event_loop().run_in_executor(
                    executor, nuclei_scanner.run
                )

            return {"nuclei_scanner": nuclei_scanner}
        else:
            logger.warning(
                f"{Fore.YELLOW}No subdomains discovered, skipping nuclei scan{Style.RESET_ALL}"
            )
            return {}

    async def _run_rustscan_on_discovered(
        self, bbot_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run RustScan on discovered IPs."""
        if (
            os.path.exists(bbot_results["ips_file"])
            and os.path.getsize(bbot_results["ips_file"]) > 0
        ):
            logger.info(
                f"{Fore.CYAN}Running RustScan on discovered IPs...{Style.RESET_ALL}"
            )

            with open(bbot_results["ips_file"], "r") as f:
                discovered_ips = [
                    line.strip() for line in f.readlines() if line.strip()
                ]

            if discovered_ips:
                rustscan_dir = prepare_output_directory(
                    self.org_name, "rustscan_discovered"
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
            else:
                logger.warning(
                    f"{Fore.YELLOW}IP file exists but contains no valid IPs{Style.RESET_ALL}"
                )
                return {}
        else:
            logger.warning(
                f"{Fore.YELLOW}No IPs discovered, skipping RustScan{Style.RESET_ALL}"
            )
            return {}

    async def _detect_and_scan_wordpress(
        self, bbot_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Detect and scan WordPress sites among discovered domains."""
        if (
            os.path.exists(bbot_results["subdomains_file"])
            and os.path.getsize(bbot_results["subdomains_file"]) > 0
        ):
            logger.info(
                f"{Fore.CYAN}Detecting WordPress sites among discovered domains...{Style.RESET_ALL}"
            )

            with ThreadPoolExecutor() as executor:
                wordpress_domains = await asyncio.get_event_loop().run_in_executor(
                    executor,
                    lambda: WordPressDetector().run(bbot_results["subdomains_file"]),
                )

            logger.info(
                f"{Fore.GREEN}[+] WordPress Domains: {Fore.CYAN}{wordpress_domains}{Style.RESET_ALL}"
            )

            if wordpress_domains:
                logger.info(
                    f"{Fore.CYAN}Running WordPress-specific nuclei scan...{Style.RESET_ALL}"
                )

                with ThreadPoolExecutor() as executor:
                    wp_scanner = WordPressNucleiScanner(
                        wordpress_domains, self.org_name
                    )
                    await asyncio.get_event_loop().run_in_executor(
                        executor, wp_scanner.run
                    )

                return {
                    "wordpress_domains": wordpress_domains,
                    "wp_scanner": wp_scanner,
                }
            else:
                logger.info(
                    "No WordPress sites found, skipping WordPress-specific scans"
                )
                return {"wordpress_domains": None}
        else:
            logger.warning(
                f"{Fore.YELLOW}No subdomains file available for WordPress detection{Style.RESET_ALL}"
            )
            return {}
