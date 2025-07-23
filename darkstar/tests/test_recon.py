import pytest
import requests
import tempfile
import os
from unittest.mock import patch, MagicMock
from darkstar.scanners.recon import RequestsAPI, WordPressDetector, FindBreaches


class TestRequestsAPI:
    """Test cases for the RequestsAPI class."""

    def test_get_hibpwned_request(self):
        """Test that get_HIBPwned_request sends the correct request."""
        with (
            patch("darkstar.scanners.recon.HIBP_KEY", "test_api_key"),
            patch("darkstar.scanners.recon.requests.get") as mock_get,
        ):
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
            assert result == mock_response

    def test_get_proxynova_request(self):
        """Test that get_proxynova_request sends the correct request."""
        with patch("darkstar.scanners.recon.requests.get") as mock_get:
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
            assert result == mock_response


class TestWordPressDetector:
    """Test cases for the WordPressDetector class."""

    @pytest.mark.parametrize(
        "timeout,expected",
        [
            (5, 5),
            (None, 10),  # Test default timeout
        ],
    )
    def test_initialization(self, timeout, expected):
        """Test that WordPressDetector is correctly initialized."""
        if timeout is None:
            detector = WordPressDetector()
        else:
            detector = WordPressDetector(timeout=timeout)
        assert detector.timeout == expected

    @pytest.mark.parametrize(
        "html_content,expected",
        [
            # Test WordPress generator meta tag
            (
                '<html><head><meta name="generator" content="WordPress 5.7"></head><body>Test</body></html>',
                True,
            ),
            # Test wp-content theme link
            (
                "<html><head></head><body><link rel='stylesheet' href='wp-content/themes/default/style.css'></body></html>",
                True,
            ),
            # Test wp-includes
            (
                "<html><head></head><body><script src='wp-includes/js/jquery.js'></script></body></html>",
                True,
            ),
            # Test non-WordPress site
            ("<html><head></head><body>Regular site</body></html>", False),
        ],
    )
    def test_check_main_page(self, html_content, expected):
        """Test that check_main_page correctly identifies WordPress sites."""
        with patch("darkstar.scanners.recon.requests.get") as mock_get:
            # Setup mock
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = html_content
            mock_get.return_value = mock_response

            detector = WordPressDetector()
            result = detector.check_main_page("https://example.com")
            assert result == expected

    def test_check_main_page_request_exception(self):
        """Test that check_main_page handles exceptions gracefully."""
        with patch("darkstar.scanners.recon.requests.get") as mock_get:
            # Setup mock to raise the specific RequestException
            mock_get.side_effect = requests.RequestException("Connection error")

            detector = WordPressDetector()
            result = detector.check_main_page("https://example.com")
            assert result is False

    def test_check_main_page_non_200_status(self):
        """Test that check_main_page returns False for non-200 status codes."""
        with patch("darkstar.scanners.recon.requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response

            detector = WordPressDetector()
            result = detector.check_main_page("https://example.com")
            assert result is False

    def test_is_wordpress(self):
        """Test that is_wordpress checks for WordPress indicators."""
        with (
            patch(
                "darkstar.scanners.recon.WordPressDetector.check_main_page"
            ) as mock_check_main_page,
            patch(
                "darkstar.scanners.recon.WordPressDetector.check_wp_login"
            ) as mock_wp_login,
            patch(
                "darkstar.scanners.recon.WordPressDetector.check_readme"
            ) as mock_readme,
            patch(
                "darkstar.scanners.recon.WordPressDetector.check_xmlrpc"
            ) as mock_xmlrpc,
            patch(
                "darkstar.scanners.recon.WordPressDetector.check_wp_json"
            ) as mock_wp_json,
        ):
            # Setup mocks - only one needs to return True
            mock_check_main_page.return_value = True
            mock_wp_login.return_value = False
            mock_readme.return_value = False
            mock_xmlrpc.return_value = False
            mock_wp_json.return_value = False

            detector = WordPressDetector()
            result = detector.is_wordpress("https://example.com")

            # Verify all checks were called
            mock_check_main_page.assert_called_once_with("https://example.com")
            mock_wp_login.assert_called_once_with("https://example.com")
            mock_readme.assert_called_once_with("https://example.com")
            mock_xmlrpc.assert_called_once_with("https://example.com")
            mock_wp_json.assert_called_once_with("https://example.com")
            assert result is True

    @pytest.mark.parametrize(
        "https_result,http_result,expected",
        [
            (True, False, True),  # HTTPS succeeds
            (False, True, True),  # HTTP succeeds
            (False, False, False),  # Both fail
            (True, True, True),  # Both succeed (should return on first)
        ],
    )
    def test_check_domain(self, https_result, http_result, expected):
        """Test that check_domain tries both HTTP and HTTPS."""
        with patch(
            "darkstar.scanners.recon.WordPressDetector.is_wordpress"
        ) as mock_is_wordpress:
            # Setup mock to return different values for HTTPS and HTTP
            mock_is_wordpress.side_effect = (
                [https_result, http_result] if not https_result else [https_result]
            )

            detector = WordPressDetector()
            result = detector.check_domain("example.com")

            # Verify HTTPS was always tried first
            mock_is_wordpress.assert_any_call("https://example.com")

            # If HTTPS failed, HTTP should be tried
            if not https_result:
                mock_is_wordpress.assert_any_call("http://example.com")

            assert result == expected

    @pytest.mark.parametrize(
        "domain_results,expected_domains",
        [
            ([True, False, True], "example1.com,example3.com"),
            ([False, False, False], ""),
            ([True, True, True], "example1.com,example2.com,example3.com"),
        ],
    )
    def test_run(self, domain_results, expected_domains):
        """Test that run processes a file of domains correctly."""
        # Create a temporary file with test domains
        with tempfile.NamedTemporaryFile("w", delete=False) as temp_file:
            temp_file.write("example1.com\nexample2.com\nexample3.com")
            file_path = temp_file.name

        try:
            # Test the run method with direct patching to avoid coroutine issues
            with patch.object(WordPressDetector, "check_domain") as mock_check_domain:
                # Ensure the mock returns simple boolean values, not coroutines
                mock_check_domain.side_effect = domain_results

                detector = WordPressDetector()
                result = detector.run(file_path)

                # Check the result
                assert result == expected_domains

                # Verify all domains were checked
                assert mock_check_domain.call_count == len(domain_results)
        finally:
            # Clean up
            os.unlink(file_path)

    def test_run_empty_file(self):
        """Test that run handles empty files correctly."""
        # Create an empty temporary file
        with tempfile.NamedTemporaryFile("w", delete=False) as temp_file:
            file_path = temp_file.name

        try:
            with patch.object(WordPressDetector, "check_domain") as mock_check_domain:
                detector = WordPressDetector()
                result = detector.run(file_path)

                assert result == ""
                mock_check_domain.assert_not_called()
        finally:
            os.unlink(file_path)


class TestFindBreaches:
    """Test cases for the FindBreaches class."""

    @pytest.mark.parametrize(
        "email,response_data,expected",
        [
            # Test single breach
            (
                "test@example.com",
                [
                    {
                        "Name": "Breach1",
                        "BreachDate": "2021-01-01",
                        "Domain": "site1.com",
                    }
                ],
                [["test@example.com", "Breach1", "2021-01-01", "site1.com"]],
            ),
            # Test multiple breaches
            (
                "test@example.com",
                [
                    {
                        "Name": "Breach1",
                        "BreachDate": "2021-01-01",
                        "Domain": "site1.com",
                    },
                    {
                        "Name": "Breach2",
                        "BreachDate": "2022-02-02",
                        "Domain": "site2.com",
                    },
                ],
                [
                    ["test@example.com", "Breach1", "2021-01-01", "site1.com"],
                    ["test@example.com", "Breach2", "2022-02-02", "site2.com"],
                ],
            ),
            # Test empty response
            ("test@example.com", [], []),
        ],
    )
    def test_find_email_breach(self, email, response_data, expected):
        """Test that find_email_breach correctly parses breach data."""
        finder = FindBreaches()
        result = finder.find_email_breach(email, response_data)
        assert result == expected

    @pytest.mark.parametrize(
        "email,response_lines,expected",
        [
            # Test password extraction
            (
                "test@example.com",
                [
                    "some other line",
                    'Line containing test@example.com:password123"',
                    'Line containing test@example.com:another_password" and more text',
                ],
                [["test@example.com", "pas"], ["test@example.com", "ano"]],
            ),
            # Test no matches
            (
                "test@example.com",
                [
                    "some other line",
                    "no email here",
                    "different@email.com:password",
                ],
                [],
            ),
            # Test empty response
            ("test@example.com", [], []),
        ],
    )
    def test_find_passwords(self, email, response_lines, expected):
        """Test that find_passwords correctly parses password data."""
        finder = FindBreaches()
        result = finder.find_passwords(email, response_lines)
        assert result == expected


# Fixtures for common test setup
@pytest.fixture
def api_instance():
    """Fixture to provide a RequestsAPI instance."""
    return RequestsAPI()


@pytest.fixture
def wordpress_detector():
    """Fixture to provide a WordPressDetector instance."""
    return WordPressDetector()


@pytest.fixture
def breach_finder():
    """Fixture to provide a FindBreaches instance."""
    return FindBreaches()


# Integration tests
class TestIntegration:
    """Integration tests for the recon module."""

    def test_api_initialization(self, api_instance):
        """Test that API instance initializes correctly."""
        assert hasattr(api_instance, "APIKey")

    def test_wordpress_detector_initialization(self, wordpress_detector):
        """Test that WordPress detector initializes correctly."""
        assert wordpress_detector.timeout == 10
        assert hasattr(wordpress_detector, "check_main_page")
        assert hasattr(wordpress_detector, "check_wp_login")
        assert hasattr(wordpress_detector, "check_readme")
        assert hasattr(wordpress_detector, "check_xmlrpc")
        assert hasattr(wordpress_detector, "check_wp_json")

    def test_breach_finder_initialization(self, breach_finder):
        """Test that breach finder initializes correctly."""
        assert hasattr(breach_finder, "find_email_breach")
        assert hasattr(breach_finder, "find_passwords")
