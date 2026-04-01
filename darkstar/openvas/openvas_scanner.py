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
import datetime
import logging
import os
import requests
import xml.etree.ElementTree as ET
from colorama import Fore, Style
from typing import List, Dict, Any

from .openvas_connector import OpenVASAPIClient
try:
    from ..core.db_helper import insert_vulnerability_to_database
    from ..core.models.vulnerability import Vulnerability
except ImportError:
    # Compatibility path for top-level imports used by some tests/tools.
    from core.db_helper import insert_vulnerability_to_database
    from core.models.vulnerability import Vulnerability

logger = logging.getLogger("openvas_scanner")


class OpenVASScanner:
    """
    OpenVAS scanner class that handles vulnerability scanning through OpenVAS API.

    This class provides functionality to:
    - Create targets and tasks in OpenVAS
    - Start scanning tasks
    - Monitor task progress
    - Retrieve and process scan reports
    - Parse vulnerabilities and store in database
    """

    def __init__(self, org_name: str, base_url: str = None):
        """
        Initialize OpenVAS scanner.

        Args:
            org_name: Organization name for database storage
            base_url: OpenVAS API base URL (defaults to Docker service URL)
        """
        self.org_name = org_name
        self.base_url = base_url or os.getenv(
            "OPENVAS_API_URL", "http://openvas-api:8008"
        )
        self.vulnerabilities = []
        logger.info(
            f"{Fore.CYAN}OpenVAS Scanner initialized for org: {org_name}{Style.RESET_ALL}"
        )
        logger.info(
            f"{Fore.CYAN}Using OpenVAS API URL: {self.base_url}{Style.RESET_ALL}"
        )

    async def scan_targets(self, targets: List[str]) -> None:
        """
        Main scanning method that orchestrates the entire OpenVAS scanning process.

        Args:
            targets: List of target hosts/IPs to scan
        """
        logger.info(
            f"{Fore.CYAN}Starting OpenVAS scan for targets: {Fore.YELLOW}{targets}{Style.RESET_ALL}"
        )

        async with OpenVASAPIClient(base_url=self.base_url) as openvas:
            # 1) Create all targets in parallel
            create_tasks = [
                openvas.create_target(
                    name=f"Discovered {target} - {datetime.datetime.now()}",
                    hosts=[target],
                )
                for target in targets
            ]
            created = await asyncio.gather(*create_tasks, return_exceptions=True)

            # Filter out errors and extract real target IDs
            target_results = []
            for idx, res in enumerate(created):
                if isinstance(res, Exception):
                    logger.error(f"Failed to create target for {targets[idx]}: {res}")
                else:
                    logger.info(f"Created target {res['id']} for {res['name']}")
                    target_results.append(res)

            # 2) For each new target, create a scan task
            task_creates = [
                openvas.create_task(name=f"Scan for {t['name']}", target_id=t["id"])
                for t in target_results
            ]

            tasks = await asyncio.gather(*task_creates, return_exceptions=True)

            # Collect only the successful task infos
            task_results = []
            for idx, res in enumerate(tasks):
                if isinstance(res, Exception):
                    logger.error(
                        f"Failed to create task for target {target_results[idx]['id']}: {res}"
                    )
                else:
                    logger.info(f"Created task {res['id']} ({res['name']})")
                    task_results.append(res)

            # 3) Start each task
            start_calls = [openvas.start_task(task["id"]) for task in task_results]
            starts = await asyncio.gather(*start_calls, return_exceptions=True)

            for idx, res in enumerate(starts):
                if isinstance(res, Exception):
                    logger.error(
                        f"Failed to start task {task_results[idx]['id']}: {res}"
                    )
                else:
                    logger.info(f"Started task {task_results[idx]['id']}: {res}")

            # Extract report IDs from task start responses
            task_info = []
            for idx, (task, start_res) in enumerate(zip(task_results, starts)):
                if not isinstance(start_res, Exception):
                    logger.info(
                        f"{Fore.CYAN}Processing task {task['id']} start response: {start_res}{Style.RESET_ALL}"
                    )
                    # The start response should now contain report_id explicitly
                    report_id = None
                    if isinstance(start_res, dict):
                        report_id = start_res.get("report_id")
                        logger.info(
                            f"{Fore.CYAN}Extracted report_id: {report_id}{Style.RESET_ALL}"
                        )
                    else:
                        logger.warning(
                            f"{Fore.YELLOW}Start response is not a dict, type: {type(start_res)}{Style.RESET_ALL}"
                        )

                    task_info.append(
                        {
                            "task_id": task["id"],
                            "task_name": task["name"],
                            "report_id": report_id,
                            "completed": False,
                        }
                    )
                    logger.info(
                        f"Task {task['id']} started with report ID: {report_id}"
                    )
                else:
                    logger.error(f"Task start failed: {start_res}")

            logger.info(
                f"{Fore.CYAN}Created task_info with {len(task_info)} tasks to monitor{Style.RESET_ALL}"
            )

            # Start background monitoring
            monitor_task = asyncio.create_task(
                self.monitor_task_queue(openvas, task_info)
            )

            # Wait for all tasks to complete
            await asyncio.gather(monitor_task, return_exceptions=True)

        logger.info(
            f"{Fore.GREEN}[+] OpenVAS: created {len(target_results)} targets and {len(task_results)} tasks, all completed{Style.RESET_ALL}"
        )

    async def monitor_task_queue(
        self, openvas_client: OpenVASAPIClient, task_info: List[Dict[str, Any]]
    ) -> None:
        """
        Monitor OpenVAS tasks in the background until all are completed.

        Args:
            openvas_client: OpenVASAPIClient instance
            task_info: List of task information dictionaries with task_id, task_name, report_id, completed
        """
        logger.info(
            f"{Fore.CYAN}Starting background monitoring of {len(task_info)} OpenVAS tasks...{Style.RESET_ALL}"
        )

        # Create output directory for reports
        reports_dir = (
            f"openvas_reports_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        os.makedirs(reports_dir, exist_ok=True)
        logger.info(
            f"{Fore.CYAN}Reports will be saved to: {reports_dir}{Style.RESET_ALL}"
        )

        while True:
            await asyncio.sleep(30)  # Check every 30 seconds

            # Check if all tasks are completed
            completed_count = sum(1 for task in task_info if task["completed"])
            total_count = len(task_info)

            if completed_count == total_count:
                logger.info(
                    f"{Fore.GREEN}[+] All {total_count} OpenVAS tasks completed!{Style.RESET_ALL}"
                )
                break

            logger.info(
                f"{Fore.CYAN}Progress: {completed_count}/{total_count} tasks completed{Style.RESET_ALL}"
            )

            # Check the status of incomplete tasks
            for task in task_info:
                if task["completed"]:
                    continue

                try:
                    status_resp = await openvas_client.get_task_status(task["task_id"])
                    current_status = status_resp.get("status", "Unknown")

                    logger.info(
                        f"{Fore.CYAN}Task {task['task_id']} ({task['task_name']}): {current_status}{Style.RESET_ALL}"
                    )

                    # Check if task is completed
                    if current_status in ["Done", "Stopped"]:
                        if task["report_id"]:
                            try:
                                logger.info(
                                    f"{Fore.CYAN}Fetching report for completed task {task['task_id']} with report_id: {task['report_id']}...{Style.RESET_ALL}"
                                )
                                logger.info(
                                    f"{Fore.CYAN}Making API call to: {openvas_client._client.base_url}/reports/{task['report_id']}{Style.RESET_ALL}"
                                )

                                # Use the report_id that was captured when the task was started
                                report_xml = await openvas_client.get_report(
                                    task["report_id"]
                                )

                                if report_xml and len(report_xml.strip()) > 0:
                                    # Save report as XML file
                                    report_filename = f"{reports_dir}/report_{task['task_id']}_{task['task_name'].replace(' ', '_')}.xml"
                                    with open(
                                        report_filename, "w", encoding="utf-8"
                                    ) as f:
                                        f.write(report_xml)

                                    # Parse the report for vulnerabilities
                                    await self.parse_results_to_vulns(report_filename)

                                    logger.info(
                                        f"{Fore.GREEN}[+] Report saved: {report_filename} ({len(report_xml)} bytes){Style.RESET_ALL}"
                                    )
                                    task["completed"] = True
                                else:
                                    logger.warning(
                                        f"{Fore.YELLOW}[!] Report retrieved but empty for task {task['task_id']}{Style.RESET_ALL}"
                                    )
                                    task["completed"] = True

                            except Exception as e:
                                logger.error(
                                    f"{Fore.RED}[-] Failed to fetch report for task {task['task_id']} with report_id {task['report_id']}: {e}{Style.RESET_ALL}"
                                )
                                task["completed"] = (
                                    True  # Mark as completed to avoid infinite retry
                                )
                        else:
                            logger.warning(
                                f"{Fore.YELLOW}[!] Task {task['task_id']} completed but no report ID available{Style.RESET_ALL}"
                            )
                            task["completed"] = True

                    elif current_status in ["Failed", "Interrupted"]:
                        logger.error(
                            f"{Fore.RED}[-] Task {task['task_id']} failed with status: {current_status}{Style.RESET_ALL}"
                        )
                        task["completed"] = True  # Mark as completed to stop monitoring

                except Exception as e:
                    logger.error(
                        f"{Fore.RED}[-] Error checking status for task {task['task_id']}: {e}{Style.RESET_ALL}"
                    )

    async def parse_results_to_vulns(self, report_file: str) -> None:
        """
        Process vulnerability findings from an OpenVAS report.

        Parses an XML report file, extracts vulnerability information,
        and converts it to Vulnerability objects for database storage.

        Args:
            report_file: Path to the XML report file
        """
        logger.info(
            f"{Fore.BLUE}[*] Processing findings from report: {report_file}{Style.RESET_ALL}"
        )
        try:
            tree = ET.parse(report_file)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(
                f"{Fore.RED}[!] Error parsing report XML: {str(e)}{Style.RESET_ALL}"
            )
            return

        vulnerability_count = 0
        skipped_count = 0

        # Process each <result> element
        for result in root.findall(".//result"):
            try:
                name = result.find("name").text
            except Exception:
                continue

            # Skip known false positives
            if any(
                skip in name
                for skip in [
                    "httpOnly",
                    "Certificate Expired",
                    "Weak Encryption",
                    "Missing `secure`",
                    "VNC Server Unencrypted",
                    "Weak Cipher",
                    "Vulnerable Cipher",
                ]
            ):
                skipped_count += 1
                continue

            nvt = result.find("nvt")
            try:
                cve = nvt.find("cve").text  # May be "NOCVE"
            except Exception:
                cve = "NOCVE"

            # Default values
            exploit = False
            epss = 0.0

            port = result.find("port").text
            threat = result.find("threat").text
            severity = result.find(
                "severity"
            ).text  # This is used later as cvss info if needed
            poc2 = result.find("description").text
            endsolution = ""

            # If a valid CVE is provided, check EPSS from FIRST
            if cve != "NOCVE":
                try:
                    response_epss = requests.get(
                        f"https://api.first.org/data/v1/epss?cve={cve}"
                    )
                    if response_epss.status_code == 200:
                        data = response_epss.json().get("data", [])
                        if data:
                            epss = float(data[0].get("percentile", 0))
                            if epss >= 0.65:
                                exploit = True
                except Exception as e:
                    logger.warning(f"Failed to fetch EPSS for {cve}: {e}")

            host_ip = result.find("host").text
            qod = result.find("qod")
            qod_value = qod.find("value").text  # Confidence (as a string)

            # Create a Vulnerability object using the provided class.
            # If a CVE is available, let the vulnerability auto-enrich by passing cve_number.
            if cve != "NOCVE":
                vuln = Vulnerability(
                    title=name,
                    affected_item=host_ip,
                    tool="OpenVAS",
                    confidence=int(qod_value),
                    severity=severity,
                    host=host_ip,
                    cve_number=cve,
                )
            else:
                # When there is no CVE, include extra information directly.
                vuln = Vulnerability(
                    title=name,
                    affected_item=host_ip,
                    tool="OpenVAS",
                    confidence=int(qod_value),
                    severity=severity,
                    host=host_ip,
                    summary=poc2,
                    impact=threat,
                    solution=endsolution,
                    poc=poc2,
                    cvss=severity,
                    epss=epss,
                )

            # Add the vulnerability to our local list
            self.vulnerabilities.append(vuln)
            vulnerability_count += 1
            logger.info(f"Found vulnerability: {vuln.title} on {vuln.affected_item}")

        # Insert all vulnerabilities to database
        for vuln in self.vulnerabilities:
            insert_vulnerability_to_database(vuln=vuln, org_name=self.org_name)

        logger.info(
            f"{Fore.GREEN}[+] Processed {vulnerability_count} vulnerabilities ({skipped_count} skipped as false positives){Style.RESET_ALL}"
        )
