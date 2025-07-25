import time
from scanners.recon import RequestsAPI, FindBreaches
from core.db_helper import (
    insert_email_data,
    insert_breached_email_data,
    insert_password_data,
)
import random
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ? response codes HTTP
SUCCES = 200
PAGE_NOT_FOUND = 404
# ? Too many calls
TOO_MANY_CALLS = 429

# If true we scan for password leaks
PASSWORD_SCANNING = True

"""
Integration with Have I Been Pwned API to check for breached accounts.

This module provides functionality to check email addresses against
the Have I Been Pwned database to identify accounts that have been
involved in known data breaches.
"""


class HIBPwned:
    """
    Handles the checking of email addresses against breach databases.

    Utilizes the Have I Been Pwned API and Proxynova to discover if
    email addresses have been compromised in data breaches, including
    passwords when available.

    Attributes:
        org_name (str): Organization name for database storage
        emails (list): List of email addresses to check
    """

    def __init__(self, email_file: str, org_name: str):
        """
        Initialize the HIBPwned checker with a file of email addresses.

        Args:
            email_file (str): Path to file containing email addresses (one per line)
            org_name (str): Organization name for database storage
        """
        self.org_name = org_name
        self.emails = []

        print(f"{Fore.BLUE}[*] Loading emails from {email_file}{Style.RESET_ALL}")
        try:
            with open(email_file, "r") as file:
                self.emails = file.readlines()
            print(
                f"{Fore.GREEN}[+] Loaded {len(self.emails)} email addresses{Style.RESET_ALL}"
            )
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Email file not found: {email_file}{Style.RESET_ALL}")
            self.emails = []
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading email file: {str(e)}{Style.RESET_ALL}")
            self.emails = []

    def run(self):
        """
        Check all loaded emails against the breach databases.

        Processes each email address through the HIBPwned API and
        optionally the Proxynova service to find breaches and passwords.
        Results are stored in the database.
        """
        if not self.emails:
            print(f"{Fore.YELLOW}[!] No emails to check. Exiting.{Style.RESET_ALL}")
            return

        # Initialize the RequestsAPI class
        api = RequestsAPI()

        # Initialize the FindBreaches class
        find_breaches = FindBreaches()

        # Store email in the database as email_input, as online discoverd emails
        print(
            f"{Fore.BLUE}[*] Storing {len(self.emails)} emails in database{Style.RESET_ALL}"
        )
        insert_email_data(self.emails, self.org_name)

        total_emails = len(self.emails)
        breached_count = 0
        password_count = 0

        for index, email in enumerate(self.emails):
            email = email.strip()
            print(
                f"{Fore.CYAN}[{index + 1}/{total_emails}] Checking email: {email}{Style.RESET_ALL}"
            )

            # Check for breaches
            attempts = 0
            max_attempts = 5
            while attempts < max_attempts:
                attempts += 1
                # Get the response from the HIBPwned API
                response = api.get_HIBPwned_request(email)
                if response.status_code == SUCCES:
                    breaches = find_breaches.find_email_breach(email, response.json())
                    if breaches:
                        breached_count += len(breaches)
                        print(
                            f"{Fore.YELLOW}[!] Found {len(breaches)} breaches for {email}{Style.RESET_ALL}"
                        )
                        # ? Insert to the email_leaks table
                        insert_breached_email_data(breaches, self.org_name)
                    else:
                        print(
                            f"{Fore.GREEN}[✓] No breaches found for {email}{Style.RESET_ALL}"
                        )
                    break
                elif response.status_code == TOO_MANY_CALLS:
                    x = random.randint(6, 20)
                    print(
                        f"{Fore.YELLOW}[!] Rate limited. Attempt {attempts}/{max_attempts} - Sleeping for {x} seconds{Style.RESET_ALL}"
                    )
                    time.sleep(x)
                elif response.status_code == PAGE_NOT_FOUND:
                    print(
                        f"{Fore.GREEN}[✓] No breaches found for {email}{Style.RESET_ALL}"
                    )
                    break
                else:
                    print(
                        f"{Fore.RED}[!] Error checking breaches: HTTP {response.status_code}{Style.RESET_ALL}"
                    )
                    break

            # If we are scanning for passwords
            if PASSWORD_SCANNING:
                print(
                    f"{Fore.BLUE}[*] Checking for password leaks: {email}{Style.RESET_ALL}"
                )
                attempts = 0
                while attempts < max_attempts:
                    attempts += 1
                    # Get the response from the Proxynova API
                    response = api.get_proxynova_request(email)
                    if response.status_code == SUCCES:
                        passwords = find_breaches.find_passwords(
                            email, response.text.splitlines()
                        )
                        if passwords:
                            password_count += len(passwords)
                            print(
                                f"{Fore.RED}[!] Found {len(passwords)} leaked passwords for {email}{Style.RESET_ALL}"
                            )
                            # ? Insert to the password_leaks table
                            insert_password_data(passwords, self.org_name)
                        else:
                            print(
                                f"{Fore.GREEN}[✓] No password leaks found for {email}{Style.RESET_ALL}"
                            )
                        break
                    elif response.status_code == TOO_MANY_CALLS:
                        x = random.randint(6, 20)
                        print(
                            f"{Fore.YELLOW}[!] Password API rate limited. Attempt {attempts}/{max_attempts} - Sleeping for {x} seconds{Style.RESET_ALL}"
                        )
                        time.sleep(x)
                    else:
                        print(
                            f"{Fore.RED}[!] Error checking passwords: HTTP {response.status_code}{Style.RESET_ALL}"
                        )
                        break

        # Summary at the end
        print(f"\n{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Scan completed!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total emails checked: {total_emails}{Style.RESET_ALL}")
        print(
            f"{Fore.YELLOW}[*] Total breaches found: {breached_count}{Style.RESET_ALL}"
        )
        if PASSWORD_SCANNING:
            print(
                f"{Fore.RED}[*] Total password leaks found: {password_count}{Style.RESET_ALL}"
            )
        print(f"{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}")
