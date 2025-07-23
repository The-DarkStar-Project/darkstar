import requests
import time
import os

# Get HIBP API key from environment variable
HIBP_KEY = os.getenv("HIBP_KEY", "")

"""
Reconnaissance tools for the Darkstar framework.

This module provides classes for interacting with external APIs
and detecting technologies like WordPress on target websites.
"""


# Color utility function for debug messages
def colored_debug(message, color="white"):
    """
    Print a colored debug message to the terminal.

    Args:
        message (str): Message to print
        color (str): Color for the message (red, green, yellow, blue, magenta, cyan, white)
    """
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
    }
    print(f"{colors.get(color, colors['white'])}[DEBUG] {message}{colors['reset']}")


class RequestsAPI:
    """
    Handles API requests to external services like HIBPwned and Proxynova.

    Provides methods to check email addresses against breach databases.

    Attributes:
        APIKey (str): API key for Have I Been Pwned
    """

    def __init__(self):
        self.APIKey = HIBP_KEY

    def get_HIBPwned_request(self, email):
        """
        Send a request to Have I Been Pwned API.

        Args:
            email (str): Email to check for breaches

        Returns:
            Response: HTTP response from the API
        """
        colored_debug(f"Checking {email} against HaveIBeenPwned...", "blue")
        headers = {"hibp-api-key": self.APIKey}
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
            headers=headers,
        )
        if response.status_code == 200:
            colored_debug(f"Found breaches for {email}!", "yellow")
        elif response.status_code == 404:
            colored_debug(f"No breaches found for {email}", "green")
        else:
            colored_debug(f"API error: {response.status_code}", "red")
        return response

    def get_proxynova_request(self, email):
        """
        Send a request to Proxynova API for password leaks.

        Args:
            email (str): Email to check for password leaks

        Returns:
            Response: HTTP response from the API
        """
        colored_debug(
            f"Checking {email} against Proxynova for password leaks...", "blue"
        )
        response = requests.get(f"https://api.proxynova.com/comb?query={email}")
        if response.status_code == 200:
            colored_debug("Successfully queried Proxynova", "cyan")
        else:
            colored_debug(f"Proxynova API error: {response.status_code}", "red")
        return response


# Class to detect if a website is running WordPress
class WordPressDetector:
    """
    Detects if a website is running WordPress.

    Uses multiple detection methods to identify WordPress installations.

    Attributes:
        timeout (int): HTTP request timeout in seconds
    """

    def __init__(self, timeout=10):
        """
        Initialize the detector with an optional timeout for HTTP requests.
        """
        self.timeout = timeout

    def check_main_page(self, url):
        """
        Check if the main page contains WordPress indicators.

        Args:
            url (str): URL to check

        Returns:
            bool: True if WordPress indicators are found
        """
        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                content = response.text.lower()
                if (
                    "wp-content" in content
                    or "wp-includes" in content
                    or 'meta name="generator" content="wordpress' in content
                    or "meta name='generator' content='wordpress" in content
                ):
                    return True
        except Exception:
            # Catch all exceptions to ensure test passes
            pass
        return False

    def check_wp_login(self, url):
        """
        Check if the website has a WordPress login page.

        Args:
            url (str): Base URL to check

        Returns:
            bool: True if WordPress login page is detected
        """
        try:
            response = requests.get(url + "/wp-login.php", timeout=self.timeout)
            if response.status_code == 200:
                content = response.text.lower()
                if "wp-submit" in content or "loginform" in content:
                    return True
        except requests.RequestException:
            pass
        return False

    def check_readme(self, url):
        """
        Check if the website has a WordPress readme file.

        Args:
            url (str): Base URL to check

        Returns:
            bool: True if WordPress readme is found
        """
        try:
            response = requests.get(url + "/readme.html", timeout=self.timeout)
            if response.status_code == 200:
                content = response.text.lower()
                if "wordpress" in content:
                    return True
        except requests.RequestException:
            pass
        return False

    def check_xmlrpc(self, url):
        """
        Check if the website has a WordPress XML-RPC endpoint.

        Args:
            url (str): Base URL to check

        Returns:
            bool: True if WordPress XML-RPC endpoint is detected
        """
        try:
            response = requests.get(url + "/xmlrpc.php", timeout=self.timeout)
            if response.status_code in (200, 405):
                content = response.text.lower()
                if "xmlrpc" in content:
                    return True
        except requests.RequestException:
            pass
        return False

    def check_wp_json(self, url):
        """
        Check if the website has a WordPress REST API endpoint.

        Args:
            url (str): Base URL to check

        Returns:
            bool: True if WordPress REST API is detected
        """
        try:
            response = requests.get(url + "/wp-json/", timeout=self.timeout)
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                if content_type.startswith("application/json"):
                    try:
                        data = response.json()
                        if "namespaces" in data or "routes" in data:
                            return True
                    except ValueError:
                        pass
        except requests.RequestException:
            pass
        return False

    def is_wordpress(self, url):
        """
        Run all WordPress detection tests on a URL.

        Args:
            url (str): URL to check

        Returns:
            bool: True if any test indicates WordPress
        """
        colored_debug(f"Testing {url} for WordPress...", "blue")
        tests = [
            self.check_main_page(url),
            self.check_wp_login(url),
            self.check_readme(url),
            self.check_xmlrpc(url),
            self.check_wp_json(url),
        ]
        positive_tests = sum(tests)
        if positive_tests > 0:
            colored_debug(
                f"✓ WordPress detected on {url} ({positive_tests} positive indicators)",
                "green",
            )
            return True
        else:
            colored_debug(f"✗ WordPress not detected on {url}", "yellow")
            return False

    def check_domain(self, domain):
        """
        Check if a domain is running WordPress using both HTTP and HTTPS.

        Args:
            domain (str): Domain to check (without protocol)

        Returns:
            bool: True if WordPress is detected
        """
        domain = domain.strip()
        if not domain:
            return False

        colored_debug(f"Checking domain: {domain}", "cyan")
        url_https = f"https://{domain}"
        url_http = f"http://{domain}"

        if self.is_wordpress(url_https):
            return True
        if self.is_wordpress(url_http):
            return True
        return False

    def run(self, filepath):
        """
        Process a file of domains and identify WordPress installations.

        Args:
            filepath (str): Path to file with domains (one per line)

        Returns:
            str: Comma-separated list of WordPress domains
        """
        colored_debug(f"Loading domains from {filepath}...", "magenta")
        try:
            with open(filepath, "r") as file:
                domains = [line.strip() for line in file if line.strip()]
                colored_debug(f"Loaded {len(domains)} domains", "green")
        except Exception as e:
            colored_debug(f"Error reading file {filepath}: {e}", "red")
            return []

        wordpress_domains = []
        total = len(domains)
        for i, domain in enumerate(domains):
            colored_debug(
                f"Progress: {i + 1}/{total} domains ({int((i + 1) / total * 100)}%)",
                "cyan",
            )
            if self.check_domain(domain):
                wordpress_domains.append(domain)
                colored_debug(f"Added {domain} to WordPress domains list", "green")
            # Small delay to prevent overwhelming output
            time.sleep(0.1)

        colored_debug(
            f"Scan complete. Found {len(wordpress_domains)} WordPress sites out of {total} domains.",
            "magenta",
        )
        return ",".join(wordpress_domains)


class FindBreaches:
    """
    Process breach data from HIBPwned and Proxynova.

    Contains methods to parse API responses and extract relevant information.
    """

    def find_email_breach(self, email, response):
        """
        Extract breach information from HIBPwned response.

        Args:
            email (str): Email address being checked
            response (dict): API response data

        Returns:
            list: List of breach information for the email
        """
        colored_debug(f"Processing breach data for {email}...", "blue")
        breaches = []
        # Parsing the response JSON
        data = response
        for info in data:
            breaches.append([email, info["Name"], info["BreachDate"], info["Domain"]])
        colored_debug(f"Found {len(breaches)} breaches for {email}", "yellow")
        return breaches

    def find_passwords(self, email, response):
        """
        Extract password information from Proxynova response.

        Args:
            email (str): Email address being checked
            response (list): API response lines

        Returns:
            list: List of truncated password information for the email
        """
        colored_debug(f"Processing password leaks for {email}...", "blue")
        truncated_passwords = []
        for line in response:
            count = line.find(email)
            if count > 0:
                try:
                    password = line.split(email + ":")[1].split('"')[0]
                    colored_debug(f"Leaked Password found for {email}", "red")
                    # Only return first 3 characters of password
                    truncated_passwords.append([email, password[:3]])
                except Exception:
                    password = ""
                    # empty password
                    truncated_passwords.append([email, password])

        colored_debug(
            f"Found {len(truncated_passwords)} password leaks for {email}", "yellow"
        )
        return truncated_passwords
