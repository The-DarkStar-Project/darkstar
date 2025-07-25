"""
Base functionality for Nuclei scanners in the Darkstar framework.

This module provides common utilities and base classes for all Nuclei-based
vulnerability scanners.
"""

import logging
import re
import threading
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseNucleiScanner(ABC):
    """
    Base class for Nuclei vulnerability scanners.

    Provides common functionality for different Nuclei scanner variants.

    Attributes:
        org_name (str): Organization name for database storage
        keywords (list): Severity levels to detect in the output
    """

    def __init__(self, org_name: str):
        self.org_name = org_name
        self.keywords = ["unknown", "low", "medium", "high", "critical"]

    @staticmethod
    def remove_ansi_codes(s: str) -> str:
        """
        Remove ANSI color codes from strings.

        Args:
            s: String that may contain ANSI codes

        Returns:
            Clean string without ANSI codes
        """
        # This regex matches ANSI escape sequences
        ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
        return ansi_escape.sub("", s)

    @abstractmethod
    def scan_nuclei(self) -> None:
        """Execute the Nuclei scan and process results."""
        pass

    def run(self) -> None:
        """
        Start the Nuclei scan in a separate thread.

        Creates and starts a new thread to execute the Nuclei scan
        asynchronously, allowing the main program to continue.
        """
        logger.info(f"Launching {self.__class__.__name__} scanner in background thread")
        thread = threading.Thread(target=self.scan_nuclei)
        thread.start()
        logger.info(f"{self.__class__.__name__} scanner thread started")

    def extract_url_from_output(self, output_line: str) -> str:
        """
        Extract URL from Nuclei output line.

        Args:
            output_line: Line of output from Nuclei scanner

        Returns:
            Extracted URL or 'unknown' if not found
        """
        try:
            url = re.search(r"(?P<url>https?://[^\s]+)", output_line).group("url")
            return url
        except AttributeError:
            try:
                url = re.search(r"(?P<url>http?://[^\s]+)", output_line).group("url")
                return url
            except AttributeError:
                try:
                    # Find it port based by x:443 or x:80
                    url = re.search(r"(?P<url>[^\s]+:[0-9]+)", output_line).group("url")
                    # cut off port
                    return url.split(":")[0]
                except AttributeError:
                    return "unknown"

    def extract_host_from_url(self, url: str) -> str:
        """
        Extract hostname from URL.

        Args:
            url: URL to process

        Returns:
            Hostname extracted from URL
        """
        domain = url
        # Replace https:// http:// www.
        domain = domain.replace("https://", "")
        domain = domain.replace("http://", "")
        domain = domain.replace("www.", "")

        # If has / in it, stop at /
        if "/" in domain:
            domain = domain.split("/")[0]

        return domain

    def extract_severity(self, output_line: str) -> str:
        """
        Extract severity level from Nuclei output.

        Args:
            output_line: Line of output from Nuclei scanner

        Returns:
            Severity level (low, medium, high, critical, or unknown)
        """
        if "unknown" in output_line:
            return "low"  # Map unknown to low severity
        elif "low" in output_line:
            return "low"
        elif "medium" in output_line:
            return "medium"
        elif "high" in output_line:
            return "high"
        elif "critical" in output_line:
            return "critical"
        return "unknown"
