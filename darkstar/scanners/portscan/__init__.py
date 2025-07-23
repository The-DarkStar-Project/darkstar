"""
Port scanning functionality for the Darkstar framework.

Provides tools for discovering open ports and services on target systems
using efficient, modern port scanning techniques.
"""

# Re-export all the necessary components
from .rustscanpy import RustScanner, run as run_rustscan
from .rustscan_utils import process_scan_results

__all__ = ["RustScanner", "run_rustscan", "process_scan_results"]
