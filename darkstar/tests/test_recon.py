import unittest
import requests
from unittest.mock import patch, MagicMock
from modules.recon import RequestsAPI, WordPressDetector, FindBreaches


class TestRequestsAPI(unittest.TestCase):
    """Test cases for the RequestsAPI class."""

    @patch("modules.recon.HIBP_KEY", "test_api_key")
    @patch("modules.recon.requests.get")
    def test_get_HIBPwned_request(self, mock_get):
        """Test that get_HIBPwned_request sends the correct request."""
        # Setup mock
        mock_response = MagicMock()
        mock_get.return_value = mock_response

        # Create API instance and call method
        api = RequestsAPI()
        result = api.get_HIBPwned_request("test@example.com")

        # Check that the request was made correctly
        mock_get.assert_called_once_with(
            "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com?truncateResponse=false",
            headers={"hibp-api-key": "test_api_key"},
        )
        self.assertEqual(result, mock_response)

    @patch("modules.recon.requests.get")
    def test_get_proxynova_request(self, mock_get):
        """Test that get_proxynova_request sends the correct request."""
        # Setup mock
        mock_response = MagicMock()
        mock_get.return_value = mock_response

        # Create API instance and call method
        api = RequestsAPI()
        result = api.get_proxynova_request("test@example.com")

        # Check that the request was made correctly
        mock_get.assert_called_once_with(
            "https://api.proxynova.com/comb?query=test@example.com"
        )
        self.assertEqual(result, mock_response)


class TestWordPressDetector(unittest.TestCase):
    """Test cases for the WordPressDetector class."""

    def test_initialization(self):
        """Test that WordPressDetector is correctly initialized."""
        detector = WordPressDetector(timeout=5)
        self.assertEqual(detector.timeout, 5)

        # Test default timeout
        detector = WordPressDetector()
        self.assertEqual(detector.timeout, 10)

    @patch("modules.recon.requests.get")
    def test_check_main_page_positive(self, mock_get):
        """Test that check_main_page correctly identifies WordPress sites."""
        # Setup mock for positive case
        mock_response = MagicMock()
        mock_response.status_code = 200
        # Changed to match exactly what the method is looking for
        mock_response.text = '<html><head><meta name="generator" content="WordPress 5.7"></head><body>Test</body></html>'
        mock_get.return_value = mock_response

        detector = WordPressDetector()
        result = detector.check_main_page("https://example.com")
        self.assertTrue(result)

        # Test another indicator
        mock_response.text = "<html><head></head><body><link rel='stylesheet' href='wp-content/themes/default/style.css'></body></html>"
        result = detector.check_main_page("https://example.com")
        self.assertTrue(result)

    @patch("modules.recon.requests.get")
    def test_check_main_page_negative(self, mock_get):
        """Test that check_main_page correctly identifies non-WordPress sites."""
        # Setup mock for negative case
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><head></head><body>Regular site</body></html>"
        mock_get.return_value = mock_response

        detector = WordPressDetector()
        result = detector.check_main_page("https://example.com")
        self.assertFalse(result)

    @patch("modules.recon.requests.get")
    def test_check_main_page_exception(self, mock_get):
        """Test that check_main_page handles exceptions gracefully."""
        # Setup mock to raise the specific RequestException
        mock_get.side_effect = requests.RequestException("Connection error")

        detector = WordPressDetector()
        result = detector.check_main_page("https://example.com")
        self.assertFalse(result)

    @patch("modules.recon.WordPressDetector.check_main_page")
    def test_is_wordpress(self, mock_check_main_page):
        """Test that is_wordpress checks for WordPress indicators."""
        # Setup mock
        mock_check_main_page.return_value = True

        detector = WordPressDetector()
        result = detector.is_wordpress("https://example.com")

        mock_check_main_page.assert_called_once_with("https://example.com")
        self.assertTrue(result)

    @patch("modules.recon.WordPressDetector.is_wordpress")
    def test_check_domain(self, mock_is_wordpress):
        """Test that check_domain tries both HTTP and HTTPS."""
        # Setup mock
        mock_is_wordpress.side_effect = [
            False,
            True,
        ]  # First HTTPS fails, then HTTP succeeds

        detector = WordPressDetector()
        result = detector.check_domain("example.com")

        # Check that both protocols were tried
        mock_is_wordpress.assert_any_call("https://example.com")
        mock_is_wordpress.assert_any_call("http://example.com")
        self.assertTrue(result)

    @patch("modules.recon.WordPressDetector.check_domain")
    def test_run(self, mock_check_domain):
        """Test that run processes a file of domains correctly."""
        # Setup mock
        mock_check_domain.side_effect = [True, False, True]

        # Create a temporary file with test domains
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False) as temp_file:
            temp_file.write("example1.com\nexample2.com\nexample3.com")
            file_path = temp_file.name

        # Test the run method
        detector = WordPressDetector()
        result = detector.run(file_path)

        # Check the result
        self.assertEqual(result, "example1.com,example3.com")

        # Clean up
        import os

        os.unlink(file_path)


class TestFindBreaches(unittest.TestCase):
    """Test cases for the FindBreaches class."""

    def test_find_email_breach(self):
        """Test that find_email_breach correctly parses breach data."""
        # Test data
        email = "test@example.com"
        response = [
            {"Name": "Breach1", "BreachDate": "2021-01-01", "Domain": "site1.com"},
            {"Name": "Breach2", "BreachDate": "2022-02-02", "Domain": "site2.com"},
        ]

        # Call the method
        finder = FindBreaches()
        result = finder.find_email_breach(email, response)

        # Check the result
        expected = [
            ["test@example.com", "Breach1", "2021-01-01", "site1.com"],
            ["test@example.com", "Breach2", "2022-02-02", "site2.com"],
        ]
        self.assertEqual(result, expected)

    def test_find_passwords(self):
        """Test that find_passwords correctly parses password data."""
        # Test data
        email = "test@example.com"
        response = [
            "some other line",
            'Line containing test@example.com:password123"',
            'Line containing test@example.com:another_password" and more text',
        ]

        # Call the method
        finder = FindBreaches()
        result = finder.find_passwords(email, response)

        # Check the result
        expected = [["test@example.com", "pas"], ["test@example.com", "ano"]]
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
