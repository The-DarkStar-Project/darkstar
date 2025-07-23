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

import logging
import pandas as pd
from abc import ABC, abstractmethod
from typing import List, Dict, Any

logger = logging.getLogger("base_scanner")


class BaseScanner(ABC):
    """
    Abstract base class for all scanners in the Darkstar framework.

    This class defines the common interface and shared functionality
    for all scanning modes.
    """

    def __init__(
        self,
        targets: str,
        target_df: pd.DataFrame,
        org_name: str,
        bruteforce: bool = False,
        bruteforce_timeout: int = 300,
    ):
        """
        Initialize the base scanner.

        Args:
            targets: Raw target string from command line
            target_df: Parsed targets organized by type
            org_name: Organization name for database storage
            bruteforce: Enable bruteforce attacks
            bruteforce_timeout: Timeout for bruteforce attacks
        """
        self.targets = targets
        self.target_df = target_df
        self.org_name = org_name
        self.bruteforce = bruteforce
        self.bruteforce_timeout = bruteforce_timeout
        logger.info(f"Initialized {self.__class__.__name__} for org: {org_name}")

    @abstractmethod
    async def run(self) -> Dict[str, Any]:
        """
        Execute the scanning process.

        This method must be implemented by all scanner subclasses.

        Returns:
            Dict containing scan results and metadata
        """
        pass

    def get_scan_targets(self) -> List[str]:
        """
        Extract scan targets from the target DataFrame.

        Returns:
            List of target strings for scanning
        """
        from core.utils import get_scan_targets

        return get_scan_targets(self.target_df)
