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
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any
from colorama import Fore, Style

from scanners.base_scanner import BaseScanner
from scanners.bbot import BBotScanner
from scanners.portscan import RustScanner, run_rustscan, process_scan_results
from core.utils import prepare_output_directory

logger = logging.getLogger("normal_scanner")


class NormalScanner(BaseScanner):
    """
    Normal scanner implementation for standard scanning.

    This scanner performs a balanced approach with passive reconnaissance
    and selected active scanning modules.
    """

    async def run(self) -> Dict[str, Any]:
        """
        Execute normal scanning with bbot and rustscan in parallel.

        Returns:
            Dict containing scan results
        """
        all_scan_targets = self.get_scan_targets()
        tasks = []

        # Define bbot normal task - using only CLI targets
        async def run_bbot_normal():
            logger.info(
                f"{Fore.CYAN}Starting bbot normal scan using CLI targets...{Style.RESET_ALL}"
            )

            with ThreadPoolExecutor() as executor:
                bbot_scanner = BBotScanner(self.targets, self.org_name)
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
                run_bruteforce=False,
            )

            scan_processed = process_scan_results(rustscan_results, self.org_name)
            return {"scan_processed": scan_processed}

        tasks.append(run_port_scan())

        # Run all tasks in parallel
        results = await asyncio.gather(*tasks)

        return {"bbot_results": results[0], "rustscan_results": results[1]}
