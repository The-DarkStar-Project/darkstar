import unittest
import sys
import os
from unittest.mock import patch, MagicMock, mock_open

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.HIBPwned import HIBPwned, SUCCES, PAGE_NOT_FOUND, TOO_MANY_CALLS


class TestHIBPwned(unittest.TestCase):
    """Test the HIBPwned class functionality."""

    def test_initialization(self):
        """Test initializing the HIBPwned checker."""
        email_content = "test1@example.com\ntest2@example.com\n"
        with patch("builtins.open", mock_open(read_data=email_content)):
            checker = HIBPwned("/path/to/emails.txt", "test_org")
            self.assertEqual(checker.org_name, "test_org")
            self.assertEqual(
                checker.emails, ["test1@example.com\n", "test2@example.com\n"]
            )

    @patch("modules.HIBPwned.insert_email_data")
    @patch("modules.HIBPwned.RequestsAPI")
    @patch("modules.HIBPwned.FindBreaches")
    def test_run_with_breached_emails(
        self, mock_find_breaches, mock_api, mock_insert_email
    ):
        """Test running the breach checker with emails that have breaches."""
        # Setup email file content
        email_content = "test1@example.com\ntest2@example.com\n"

        # Mock API responses
        mock_hibp_response = MagicMock()
        mock_hibp_response.status_code = SUCCES
        mock_hibp_response.json.return_value = [{"breach": "data"}]

        mock_proxynova_response = MagicMock()
        mock_proxynova_response.status_code = SUCCES
        mock_proxynova_response.text = "test1@example.com:password1"

        # Setup API instance and its methods
        mock_api_instance = MagicMock()
        mock_api_instance.get_HIBPwned_request.return_value = mock_hibp_response
        mock_api_instance.get_proxynova_request.return_value = mock_proxynova_response
        mock_api.return_value = mock_api_instance

        # Setup FindBreaches instance and its methods
        mock_find_breaches_instance = MagicMock()
        mock_find_breaches_instance.find_email_breach.return_value = [
            ["test1@example.com", "Breach1", "2020-01-01", "breach.com"]
        ]
        mock_find_breaches_instance.find_passwords.return_value = [
            ["test1@example.com", "pas"]
        ]
        mock_find_breaches.return_value = mock_find_breaches_instance

        with patch("builtins.open", mock_open(read_data=email_content)):
            with patch(
                "modules.HIBPwned.insert_breached_email_data"
            ) as mock_insert_breached:
                with patch(
                    "modules.HIBPwned.insert_password_data"
                ) as mock_insert_password:
                    checker = HIBPwned("/path/to/emails.txt", "test_org")
                    checker.run()

        # Verify the databases were updated
        mock_insert_email.assert_called_once()
        mock_insert_breached.assert_called()
        mock_insert_password.assert_called()

        # Verify the API calls were made
        self.assertEqual(mock_api_instance.get_HIBPwned_request.call_count, 2)
        self.assertEqual(mock_api_instance.get_proxynova_request.call_count, 2)

    @patch("modules.HIBPwned.insert_email_data")
    @patch("modules.HIBPwned.RequestsAPI")
    @patch("modules.HIBPwned.FindBreaches")
    def test_run_with_not_found_emails(
        self, mock_find_breaches, mock_api, mock_insert_email
    ):
        """Test running the breach checker with emails that have no breaches."""
        # Setup email file content
        email_content = "clean@example.com\n"

        # Mock API responses - not found
        mock_hibp_response = MagicMock()
        mock_hibp_response.status_code = PAGE_NOT_FOUND

        mock_proxynova_response = MagicMock()
        mock_proxynova_response.status_code = SUCCES
        mock_proxynova_response.text = ""

        # Setup API instance and its methods
        mock_api_instance = MagicMock()
        mock_api_instance.get_HIBPwned_request.return_value = mock_hibp_response
        mock_api_instance.get_proxynova_request.return_value = mock_proxynova_response
        mock_api.return_value = mock_api_instance

        # Setup FindBreaches instance and its methods
        mock_find_breaches_instance = MagicMock()
        mock_find_breaches_instance.find_passwords.return_value = []
        mock_find_breaches.return_value = mock_find_breaches_instance

        with patch("builtins.open", mock_open(read_data=email_content)):
            with patch(
                "modules.HIBPwned.insert_breached_email_data"
            ) as mock_insert_breached:
                with patch(
                    "modules.HIBPwned.insert_password_data"
                ) as mock_insert_password:
                    checker = HIBPwned("/path/to/emails.txt", "test_org")
                    checker.run()

        # Verify no breach data was inserted
        mock_insert_email.assert_called_once()
        mock_insert_breached.assert_not_called()
        mock_insert_password.assert_called_once()

        # Verify the API calls were made
        mock_api_instance.get_HIBPwned_request.assert_called_once()
        mock_api_instance.get_proxynova_request.assert_called_once()

    @patch("modules.HIBPwned.insert_email_data")
    @patch("modules.HIBPwned.RequestsAPI")
    @patch("modules.HIBPwned.time.sleep")
    def test_run_with_rate_limit(self, mock_sleep, mock_api, mock_insert_email):
        """Test handling of rate limits from the APIs."""
        # Setup email file content
        email_content = "test@example.com\n"

        # Mock API responses - rate limit then success
        mock_hibp_response_limit = MagicMock()
        mock_hibp_response_limit.status_code = TOO_MANY_CALLS

        mock_hibp_response_success = MagicMock()
        mock_hibp_response_success.status_code = SUCCES
        mock_hibp_response_success.json.return_value = []

        mock_proxynova_response_limit = MagicMock()
        mock_proxynova_response_limit.status_code = TOO_MANY_CALLS

        mock_proxynova_response_success = MagicMock()
        mock_proxynova_response_success.status_code = SUCCES
        mock_proxynova_response_success.text = ""

        # Setup API instance and its methods to return rate limit first, then success
        mock_api_instance = MagicMock()
        mock_api_instance.get_HIBPwned_request.side_effect = [
            mock_hibp_response_limit,
            mock_hibp_response_success,
        ]
        mock_api_instance.get_proxynova_request.side_effect = [
            mock_proxynova_response_limit,
            mock_proxynova_response_success,
        ]
        mock_api.return_value = mock_api_instance

        # Run the checker
        with patch("builtins.open", mock_open(read_data=email_content)):
            with patch("modules.HIBPwned.random.randint", return_value=10):
                with patch("modules.HIBPwned.FindBreaches") as mock_find_breaches:
                    mock_find_breaches_instance = MagicMock()
                    mock_find_breaches_instance.find_email_breach.return_value = []
                    mock_find_breaches_instance.find_passwords.return_value = []
                    mock_find_breaches.return_value = mock_find_breaches_instance

                    with patch(
                        "modules.HIBPwned.insert_breached_email_data"
                    ) as mock_insert_breached:
                        with patch(
                            "modules.HIBPwned.insert_password_data"
                        ) as mock_insert_password:
                            checker = HIBPwned("/path/to/emails.txt", "test_org")
                            checker.run()

        # Verify that sleep was called for rate limiting
        mock_sleep.assert_called()

        # Verify the API calls were made twice for each service due to rate limiting
        self.assertEqual(mock_api_instance.get_HIBPwned_request.call_count, 2)
        self.assertEqual(mock_api_instance.get_proxynova_request.call_count, 2)

        # Verify database operations were called correctly
        mock_insert_email.assert_called_once()
        mock_insert_breached.assert_called_once()
        mock_insert_password.assert_called_once()


if __name__ == "__main__":
    unittest.main()
