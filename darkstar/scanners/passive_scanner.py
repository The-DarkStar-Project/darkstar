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

logger = logging.getLogger("passive_scanner")


class PassiveScanner(BaseScanner):
    """
    Passive scanner implementation for light reconnaissance.

    This scanner performs passive reconnaissance without active scanning
    to avoid detection and minimize impact on target systems.
    """

    async def run(self) -> Dict[str, Any]:
        """
        Execute passive scanning using only passive reconnaissance tools.

        Returns:
            Dict containing scan results
        """
        logger.info(
            f"{Fore.CYAN}Starting passive scan using CLI targets only...{Style.RESET_ALL}"
        )

        with ThreadPoolExecutor() as executor:
            bbot_scanner = BBotScanner(self.targets, self.org_name)
            await asyncio.get_event_loop().run_in_executor(
                executor, lambda: bbot_scanner.run(mode="passive")
            )

        return {"bbot_scanner": bbot_scanner}
