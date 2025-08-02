import os
from urllib.parse import urlparse
import json
import logging

from core.db_helper import insert_vulnerability_to_database
from core.models.vulnerability import Vulnerability

# Add the asteroid module to the path
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "asteroid"))
from asteroid import Asteroid

logger = logging.getLogger(__name__)


class AsteroidScanner:
    def __init__(self, target: str, org_name: str):
        self.target = target
        self.list_of_targets = self._process_target(target)
        self.org_name = org_name

        self.output_dir = "/app/asteroid_output"
        # Create a directory for the ouptput if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def _process_target(self, target):
        """Process the target input to ensure it is a list of URLs starting with http or https."""
        if os.path.exists(target):
            with open(target, "r") as f:
                list_of_targets = [line.strip() for line in f if line.strip()]
        else:
            list_of_targets = [t.strip() for t in target.split(",")]

        for i, target in enumerate(list_of_targets):
            if not str(target).startswith("http") and not str(target).startswith(
                "https://"
            ):
                list_of_targets[i] = "http://" + str(
                    target
                )  # TODO: check if http or https

        return list_of_targets

    def vulns_to_db(self):
        """Insert vulnerabilities from the output JSON files into the database."""
        for t in self.list_of_targets:
            target_name = urlparse(t).netloc
            target_dir = os.path.join(self.output_dir, target_name)
            vulns_file = os.path.join(target_dir, "vulns.json")

            with open(vulns_file) as f:
                vulns = json.load(f)
            for vuln in vulns:
                vuln_obj = Vulnerability.from_dict(vuln)
                insert_vulnerability_to_database(vuln_obj, self.org_name)
        logger.info(
            "Vulnerabilities found by Asteroid successfully inserted into the database."
        )

    def normal(self):
        logger.info("Running Asteroid scanner in normal mode")
        modules = [
            "katana",
            "gau",
            "extensioninspector",
            "vulnscan",
            "retirejs",
        ]
        asteroid = Asteroid(
            target=self.target,
            output_dir=self.output_dir,
            specific_modules=",".join(modules),
            rerun=True,
            module_args={
                "search_vulns_api_key": os.getenv("SEARCH_VULNS_API_KEY", ""),
            },
        )
        asteroid.run()

    def aggressive(self):
        logger.info("Running Asteroid scanner in aggressive mode")
        modules = "all"
        asteroid = Asteroid(
            target=self.target,
            output_dir=self.output_dir,
            specific_modules=modules,
            rerun=True,
            module_args={
                "forms": True,
                "search_vulns_api_key": os.getenv("SEARCH_VULNS_API_KEY", ""),
            },
        )
        asteroid.run()

    def run(self, mode: str):
        """
        Run the Asteroid scanner with the specified mode.

        Args:
            mode (str): The mode to run the scanner in ('normal' or 'aggressive').
        """
        if mode == "normal":
            self.normal()
        elif mode == "aggressive":
            self.aggressive()
        else:
            raise ValueError("Invalid mode. Use 'normal' or 'aggressive'.")

        self.vulns_to_db()
