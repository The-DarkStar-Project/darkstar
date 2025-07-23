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

import pandas as pd
from typing import Optional

from scanners.base_scanner import BaseScanner
from scanners.passive_scanner import PassiveScanner
from scanners.normal_scanner import NormalScanner
from scanners.aggressive_scanner import AggressiveScanner
from scanners.attack_surface_scanner import AttackSurfaceScanner
from openvas.openvas_scanner import OpenVASScanner


class ScannerFactory:
    """
    Factory class for creating scanner instances based on mode.

    This factory encapsulates the logic for determining which scanner
    to use based on the scanning mode selected by the user.
    """

    @staticmethod
    def create_scanner(
        mode: int,
        targets: str,
        target_df: pd.DataFrame,
        org_name: str,
        bruteforce: bool = False,
        bruteforce_timeout: int = 300,
    ) -> Optional[BaseScanner]:
        """
        Create a scanner instance based on the specified mode.

        Args:
            mode: Scanning mode (1-5)
            targets: Raw target string
            target_df: Parsed targets DataFrame
            org_name: Organization name
            bruteforce: Enable bruteforce attacks
            bruteforce_timeout: Bruteforce timeout

        Returns:
            Scanner instance or None if mode is invalid
        """
        scanner_map = {
            1: PassiveScanner,
            2: NormalScanner,
            3: AggressiveScanner,
            4: AttackSurfaceScanner,
            5: lambda *args, **kwargs: OpenVASScanner(
                org_name=org_name
            ),  # OpenVAS has different signature
        }

        scanner_class = scanner_map.get(mode)
        if not scanner_class:
            return None

        # Handle OpenVAS special case
        if mode == 5:
            return scanner_class()

        return scanner_class(
            targets=targets,
            target_df=target_df,
            org_name=org_name,
            bruteforce=bruteforce,
            bruteforce_timeout=bruteforce_timeout,
        )

    @staticmethod
    def get_mode_description(mode: int) -> str:
        """
        Get a human-readable description of the scanning mode.

        Args:
            mode: Scanning mode

        Returns:
            Mode description string
        """
        descriptions = {
            1: "PASSIVE MODE - Light reconnaissance without active scanning",
            2: "NORMAL MODE - Standard scanning with passive and selected active modules",
            3: "AGGRESSIVE MODE - Full scanning with all active and aggressive modules",
            4: "ATTACK SURFACE MODE - Attack surface mapping with custom modules",
            5: "OPENVAS MODE - Testing OpenVAS integration",
        }

        return descriptions.get(mode, "UNKNOWN MODE")
