import pytest
from pytest_mock import MockerFixture
import sys
import os

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.hibp.HIBPwned import HIBPwned, SUCCES, PAGE_NOT_FOUND, TOO_MANY_CALLS


@pytest.fixture
def sample_emails():
    """Fixture providing sample email content."""
    return "test1@example.com\ntest2@example.com\n"


@pytest.fixture
def single_email():
    """Fixture providing single email content."""
    return "test@example.com\n"


@pytest.fixture
def clean_email():
    """Fixture providing clean email content."""
    return "clean@example.com\n"


@pytest.fixture
def mock_api(mocker: MockerFixture):
    """Fixture providing a mocked API instance."""
    return mocker.patch("tools.hibp.HIBPwned.RequestsAPI")


@pytest.fixture
def mock_find_breaches(mocker: MockerFixture):
    """Fixture providing a mocked FindBreaches instance."""
    return mocker.patch("tools.hibp.HIBPwned.FindBreaches")


@pytest.fixture
def mock_db_functions(mocker: MockerFixture):
    """Fixture providing mocked database functions."""
    mock_email = mocker.patch("tools.hibp.HIBPwned.insert_email_data")
    mock_breached = mocker.patch("tools.hibp.HIBPwned.insert_breached_email_data")
    mock_password = mocker.patch("tools.hibp.HIBPwned.insert_password_data")

    return {
        "email": mock_email,
        "breached": mock_breached,
        "password": mock_password,
    }


class TestHIBPwnedInitialization:
    """Test the HIBPwned class initialization."""

    def test_initialization(self, mocker: MockerFixture, sample_emails):
        """Test initializing the HIBPwned checker."""
        mock_open_file = mocker.mock_open(read_data=sample_emails)
        mocker.patch("builtins.open", mock_open_file)

        checker = HIBPwned("/path/to/emails.txt", "test_org")
        assert checker.org_name == "test_org"
        assert checker.emails == ["test1@example.com\n", "test2@example.com\n"]

    def test_initialization_file_not_found(self, mocker: MockerFixture):
        """Test initialization when email file doesn't exist."""
        mocker.patch("builtins.open", side_effect=FileNotFoundError())

        checker = HIBPwned("/nonexistent/emails.txt", "test_org")
        assert checker.org_name == "test_org"
        assert checker.emails == []

    def test_initialization_file_error(self, mocker: MockerFixture):
        """Test initialization when there's an error reading the file."""
        mocker.patch("builtins.open", side_effect=Exception("Read error"))

        checker = HIBPwned("/path/to/emails.txt", "test_org")
        assert checker.org_name == "test_org"
        assert checker.emails == []


class TestHIBPwnedRun:
    """Test the HIBPwned run functionality."""

    def test_run_with_no_emails(
        self, mocker: MockerFixture, mock_api, mock_find_breaches, mock_db_functions
    ):
        """Test running with no emails loaded."""
        mock_open_file = mocker.mock_open(read_data="")
        mocker.patch("builtins.open", mock_open_file)

        checker = HIBPwned("/path/to/emails.txt", "test_org")
        checker.emails = []  # Explicitly set to empty
        checker.run()

        # Verify no API calls were made
        mock_api.return_value.get_HIBPwned_request.assert_not_called()
        mock_api.return_value.get_proxynova_request.assert_not_called()

    def test_run_with_breached_emails(
        self,
        mocker: MockerFixture,
        sample_emails,
        mock_api,
        mock_find_breaches,
        mock_db_functions,
    ):
        """Test running the breach checker with emails that have breaches."""
        # Mock API responses
        mock_hibp_response = mocker.Mock()
        mock_hibp_response.status_code = SUCCES
        mock_hibp_response.json.return_value = [{"breach": "data"}]

        mock_proxynova_response = mocker.Mock()
        mock_proxynova_response.status_code = SUCCES
        mock_proxynova_response.text = "test1@example.com:password1"

        # Setup API instance
        mock_api_instance = mocker.Mock()
        mock_api_instance.get_HIBPwned_request.return_value = mock_hibp_response
        mock_api_instance.get_proxynova_request.return_value = mock_proxynova_response
        mock_api.return_value = mock_api_instance

        # Setup FindBreaches instance
        mock_find_breaches_instance = mocker.Mock()
        mock_find_breaches_instance.find_email_breach.return_value = [
            ["test1@example.com", "Breach1", "2020-01-01", "breach.com"]
        ]
        mock_find_breaches_instance.find_passwords.return_value = [
            ["test1@example.com", "password1"]
        ]
        mock_find_breaches.return_value = mock_find_breaches_instance

        mock_open_file = mocker.mock_open(read_data=sample_emails)
        mocker.patch("builtins.open", mock_open_file)

        checker = HIBPwned("/path/to/emails.txt", "test_org")
        checker.run()

        # Verify the databases were updated
        mock_db_functions["email"].assert_called_once()
        mock_db_functions["breached"].assert_called()
        mock_db_functions["password"].assert_called()

        # Verify the API calls were made
        assert mock_api_instance.get_HIBPwned_request.call_count == 2
        assert mock_api_instance.get_proxynova_request.call_count == 2

    def test_run_with_clean_emails(
        self,
        mocker: MockerFixture,
        clean_email,
        mock_api,
        mock_find_breaches,
        mock_db_functions,
    ):
        """Test running the breach checker with emails that have no breaches or passwords."""
        # Mock API responses - success but no data found
        mock_hibp_response = mocker.Mock()
        mock_hibp_response.status_code = SUCCES
        mock_hibp_response.json.return_value = []

        mock_proxynova_response = mocker.Mock()
        mock_proxynova_response.status_code = SUCCES
        mock_proxynova_response.text = ""

        # Setup API instance
        mock_api_instance = mocker.Mock()
        mock_api_instance.get_HIBPwned_request.return_value = mock_hibp_response
        mock_api_instance.get_proxynova_request.return_value = mock_proxynova_response
        mock_api.return_value = mock_api_instance

        # Setup FindBreaches instance - no breaches or passwords found
        mock_find_breaches_instance = mocker.Mock()
        mock_find_breaches_instance.find_email_breach.return_value = []
        mock_find_breaches_instance.find_passwords.return_value = []
        mock_find_breaches.return_value = mock_find_breaches_instance

        mock_open_file = mocker.mock_open(read_data=clean_email)
        mocker.patch("builtins.open", mock_open_file)

        checker = HIBPwned("/path/to/emails.txt", "test_org")
        checker.run()

        # Verify only email data was inserted (not breach or password data since lists are empty)
        mock_db_functions["email"].assert_called_once()
        mock_db_functions[
            "breached"
        ].assert_not_called()  # Not called when no breaches found
        mock_db_functions[
            "password"
        ].assert_not_called()  # Not called when no passwords found

        # Verify the API calls were made
        mock_api_instance.get_HIBPwned_request.assert_called_once()
        mock_api_instance.get_proxynova_request.assert_called_once()

    def test_run_with_not_found_emails(
        self,
        mocker: MockerFixture,
        clean_email,
        mock_api,
        mock_find_breaches,
        mock_db_functions,
    ):
        """Test running the breach checker with emails that return 404."""
        # Mock API responses - not found
        mock_hibp_response = mocker.Mock()
        mock_hibp_response.status_code = PAGE_NOT_FOUND

        mock_proxynova_response = mocker.Mock()
        mock_proxynova_response.status_code = SUCCES
        mock_proxynova_response.text = ""

        # Setup API instance
        mock_api_instance = mocker.Mock()
        mock_api_instance.get_HIBPwned_request.return_value = mock_hibp_response
        mock_api_instance.get_proxynova_request.return_value = mock_proxynova_response
        mock_api.return_value = mock_api_instance

        # Setup FindBreaches instance
        mock_find_breaches_instance = mocker.Mock()
        mock_find_breaches_instance.find_passwords.return_value = []
        mock_find_breaches.return_value = mock_find_breaches_instance

        mock_open_file = mocker.mock_open(read_data=clean_email)
        mocker.patch("builtins.open", mock_open_file)

        checker = HIBPwned("/path/to/emails.txt", "test_org")
        checker.run()

        # Verify only email data was inserted
        mock_db_functions["email"].assert_called_once()
        mock_db_functions["breached"].assert_not_called()
        mock_db_functions["password"].assert_not_called()

        # Verify the API calls were made
        mock_api_instance.get_HIBPwned_request.assert_called_once()
        mock_api_instance.get_proxynova_request.assert_called_once()


class TestHIBPwnedRateLimit:
    """Test rate limiting functionality."""

    def test_run_with_rate_limit(
        self,
        mocker: MockerFixture,
        single_email,
        mock_api,
        mock_find_breaches,
        mock_db_functions,
    ):
        """Test handling of rate limits from the APIs."""
        # Mock sleep to avoid actual delays in tests
        mock_sleep = mocker.patch("tools.hibp.HIBPwned.time.sleep")

        # Mock API responses - rate limit then success
        mock_hibp_response_limit = mocker.Mock()
        mock_hibp_response_limit.status_code = TOO_MANY_CALLS

        mock_hibp_response_success = mocker.Mock()
        mock_hibp_response_success.status_code = SUCCES
        mock_hibp_response_success.json.return_value = []

        mock_proxynova_response_limit = mocker.Mock()
        mock_proxynova_response_limit.status_code = TOO_MANY_CALLS

        mock_proxynova_response_success = mocker.Mock()
        mock_proxynova_response_success.status_code = SUCCES
        mock_proxynova_response_success.text = ""

        # Setup API instance to return rate limit first, then success
        mock_api_instance = mocker.Mock()
        mock_api_instance.get_HIBPwned_request.side_effect = [
            mock_hibp_response_limit,
            mock_hibp_response_success,
        ]
        mock_api_instance.get_proxynova_request.side_effect = [
            mock_proxynova_response_limit,
            mock_proxynova_response_success,
        ]
        mock_api.return_value = mock_api_instance

        # Setup FindBreaches instance
        mock_find_breaches_instance = mocker.Mock()
        mock_find_breaches_instance.find_email_breach.return_value = []
        mock_find_breaches_instance.find_passwords.return_value = []
        mock_find_breaches.return_value = mock_find_breaches_instance

        # Mock random sleep time
        mocker.patch("tools.hibp.HIBPwned.random.randint", return_value=10)

        mock_open_file = mocker.mock_open(read_data=single_email)
        mocker.patch("builtins.open", mock_open_file)

        checker = HIBPwned("/path/to/emails.txt", "test_org")
        checker.run()

        # Verify that sleep was called for rate limiting
        mock_sleep.assert_called()

        # Verify the API calls were made twice for each service due to rate limiting
        assert mock_api_instance.get_HIBPwned_request.call_count == 2
        assert mock_api_instance.get_proxynova_request.call_count == 2

        # Verify database operations were called correctly (no data found, so no breach/password inserts)
        mock_db_functions["email"].assert_called_once()
        mock_db_functions["breached"].assert_not_called()
        mock_db_functions["password"].assert_not_called()


class TestHIBPwnedAPIResponses:
    """Test different API response scenarios."""

    @pytest.mark.parametrize(
        "hibp_status,proxynova_status,expected_breaches,expected_passwords",
        [
            (SUCCES, SUCCES, True, True),
            (PAGE_NOT_FOUND, SUCCES, False, True),
            (SUCCES, PAGE_NOT_FOUND, True, False),
            (PAGE_NOT_FOUND, PAGE_NOT_FOUND, False, False),
            (500, 500, False, False),  # Server errors
        ],
    )
    def test_api_response_combinations(
        self,
        mocker: MockerFixture,
        hibp_status,
        proxynova_status,
        expected_breaches,
        expected_passwords,
        single_email,
        mock_api,
        mock_find_breaches,
        mock_db_functions,
    ):
        """Test various combinations of API responses."""
        # Mock API responses
        mock_hibp_response = mocker.Mock()
        mock_hibp_response.status_code = hibp_status
        if hibp_status == SUCCES:
            mock_hibp_response.json.return_value = [{"breach": "data"}]

        mock_proxynova_response = mocker.Mock()
        mock_proxynova_response.status_code = proxynova_status
        if proxynova_status == SUCCES:
            mock_proxynova_response.text = "test@example.com:password1"
        else:
            mock_proxynova_response.text = ""

        # Setup API instance
        mock_api_instance = mocker.Mock()
        mock_api_instance.get_HIBPwned_request.return_value = mock_hibp_response
        mock_api_instance.get_proxynova_request.return_value = mock_proxynova_response
        mock_api.return_value = mock_api_instance

        # Setup FindBreaches instance
        mock_find_breaches_instance = mocker.Mock()
        if expected_breaches and hibp_status == SUCCES:
            mock_find_breaches_instance.find_email_breach.return_value = [
                ["test@example.com", "Breach1", "2020-01-01", "breach.com"]
            ]
        else:
            mock_find_breaches_instance.find_email_breach.return_value = []

        if expected_passwords and proxynova_status == SUCCES:
            mock_find_breaches_instance.find_passwords.return_value = [
                ["test@example.com", "password1"]
            ]
        else:
            mock_find_breaches_instance.find_passwords.return_value = []
        mock_find_breaches.return_value = mock_find_breaches_instance

        mock_open_file = mocker.mock_open(read_data=single_email)
        mocker.patch("builtins.open", mock_open_file)

        checker = HIBPwned("/path/to/emails.txt", "test_org")
        checker.run()

        # Verify database operations
        mock_db_functions["email"].assert_called_once()

        if expected_breaches and hibp_status == SUCCES:
            mock_db_functions["breached"].assert_called()
        else:
            mock_db_functions["breached"].assert_not_called()

        if expected_passwords and proxynova_status == SUCCES:
            mock_db_functions["password"].assert_called()
        else:
            mock_db_functions["password"].assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
