import pytest
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from httpx import HTTPStatusError
import tempfile
import os

from darkstar.openvas.openvas_connector import (
    OpenVASAPIClient,
    create_target,
    list_targets,
    create_task,
    list_tasks,
    start_task,
    get_task_status,
    get_report,
)
from darkstar.openvas.openvas_scanner import OpenVASScanner


class TestOpenVASAPIClient:
    """Test cases for the OpenVASAPIClient class."""

    @pytest.fixture
    def client(self):
        """Fixture to provide an OpenVASAPIClient instance."""
        return OpenVASAPIClient(base_url="http://test-openvas:8008")

    @pytest.fixture
    def mock_httpx_client(self):
        """Fixture to provide a mocked httpx.AsyncClient."""
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_context_manager_entry_exit(self, client):
        """Test that the client can be used as an async context manager."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            async with client as c:
                assert c is client
                assert client._client is mock_client
                mock_client_class.assert_called_once_with(
                    base_url="http://test-openvas:8008"
                )

            mock_client.aclose.assert_called_once()

    @pytest.mark.parametrize(
        "name,hosts,port_range,port_list_id,expected_payload",
        [
            (
                "test-target",
                ["192.168.1.1"],
                "1-65535",
                None,
                {
                    "name": "test-target",
                    "hosts": ["192.168.1.1"],
                    "port_range": "1-65535",
                },
            ),
            (
                "multi-target",
                ["192.168.1.1", "192.168.1.2"],
                "80,443",
                "port-list-123",
                {
                    "name": "multi-target",
                    "hosts": ["192.168.1.1", "192.168.1.2"],
                    "port_range": "80,443",
                    "port_list_id": "port-list-123",
                },
            ),
            (
                "single-host",
                ["10.0.0.1"],
                "22",
                None,
                {"name": "single-host", "hosts": ["10.0.0.1"], "port_range": "22"},
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_create_target(
        self,
        client,
        mock_httpx_client,
        name,
        hosts,
        port_range,
        port_list_id,
        expected_payload,
    ):
        """Test target creation with various parameters."""
        expected_response = {"id": "target-123", "name": name}
        mock_response = MagicMock()
        mock_response.json.return_value = expected_response
        mock_httpx_client.post.return_value = mock_response

        client._client = mock_httpx_client

        kwargs = {"port_range": port_range}
        if port_list_id:
            kwargs["port_list_id"] = port_list_id

        result = await client.create_target(name, hosts, **kwargs)

        mock_httpx_client.post.assert_called_once_with(
            "/targets", json=expected_payload
        )
        mock_response.raise_for_status.assert_called_once()
        assert result == expected_response

    @pytest.mark.asyncio
    async def test_create_target_http_error(self, client, mock_httpx_client):
        """Test that HTTP errors are properly raised during target creation."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = HTTPStatusError(
            "Bad Request", request=MagicMock(), response=MagicMock()
        )
        mock_httpx_client.post.return_value = mock_response

        client._client = mock_httpx_client

        with pytest.raises(HTTPStatusError):
            await client.create_target("test", ["192.168.1.1"])

    @pytest.mark.asyncio
    async def test_list_targets(self, client, mock_httpx_client):
        """Test listing targets."""
        expected_targets = [
            {"id": "target-1", "name": "Target 1", "hosts": ["192.168.1.1"]},
            {"id": "target-2", "name": "Target 2", "hosts": ["192.168.1.2"]},
        ]
        mock_response = MagicMock()
        mock_response.json.return_value = expected_targets
        mock_httpx_client.get.return_value = mock_response

        client._client = mock_httpx_client

        result = await client.list_targets()

        mock_httpx_client.get.assert_called_once_with("/targets")
        mock_response.raise_for_status.assert_called_once()
        assert result == expected_targets

    @pytest.mark.parametrize(
        "name,target_id,expected_payload",
        [
            (
                "scan-task-1",
                "target-123",
                {"name": "scan-task-1", "target_id": "target-123"},
            ),
            (
                "weekly-scan",
                "target-456",
                {"name": "weekly-scan", "target_id": "target-456"},
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_create_task(
        self, client, mock_httpx_client, name, target_id, expected_payload
    ):
        """Test task creation with various parameters."""
        expected_response = {"id": "task-789", "name": name, "target_id": target_id}
        mock_response = MagicMock()
        mock_response.json.return_value = expected_response
        mock_httpx_client.post.return_value = mock_response

        client._client = mock_httpx_client

        result = await client.create_task(name, target_id)

        mock_httpx_client.post.assert_called_once_with("/tasks", json=expected_payload)
        mock_response.raise_for_status.assert_called_once()
        assert result == expected_response

    @pytest.mark.asyncio
    async def test_list_tasks(self, client, mock_httpx_client):
        """Test listing tasks."""
        expected_tasks = [
            {"id": "task-1", "name": "Task 1", "status": "Running"},
            {"id": "task-2", "name": "Task 2", "status": "Done"},
        ]
        mock_response = MagicMock()
        mock_response.json.return_value = expected_tasks
        mock_httpx_client.get.return_value = mock_response

        client._client = mock_httpx_client

        result = await client.list_tasks()

        mock_httpx_client.get.assert_called_once_with("/tasks")
        mock_response.raise_for_status.assert_called_once()
        assert result == expected_tasks

    @pytest.mark.asyncio
    async def test_start_task(self, client, mock_httpx_client):
        """Test starting a task."""
        task_id = "task-123"
        expected_response = {
            "task_id": task_id,
            "report_id": "report-456",
            "status": "Running",
        }
        mock_response = MagicMock()
        mock_response.json.return_value = expected_response
        mock_httpx_client.post.return_value = mock_response

        client._client = mock_httpx_client

        result = await client.start_task(task_id)

        mock_httpx_client.post.assert_called_once_with(f"/tasks/{task_id}/start")
        mock_response.raise_for_status.assert_called_once()
        assert result == expected_response

    @pytest.mark.parametrize(
        "task_id,expected_status",
        [
            ("task-123", {"status": "Running", "progress": 45}),
            ("task-456", {"status": "Done", "progress": 100}),
            ("task-789", {"status": "Failed", "error": "Connection timeout"}),
        ],
    )
    @pytest.mark.asyncio
    async def test_get_task_status(
        self, client, mock_httpx_client, task_id, expected_status
    ):
        """Test getting task status with various statuses."""
        mock_response = MagicMock()
        mock_response.json.return_value = expected_status
        mock_httpx_client.get.return_value = mock_response

        client._client = mock_httpx_client

        result = await client.get_task_status(task_id)

        mock_httpx_client.get.assert_called_once_with(f"/tasks/{task_id}/status")
        mock_response.raise_for_status.assert_called_once()
        assert result == expected_status

    @pytest.mark.asyncio
    async def test_get_report(self, client, mock_httpx_client):
        """Test getting a report."""
        report_id = "report-123"
        expected_xml = "<report><vulnerability>test</vulnerability></report>"
        mock_response = MagicMock()
        mock_response.text = expected_xml
        mock_httpx_client.get.return_value = mock_response

        client._client = mock_httpx_client

        result = await client.get_report(report_id)

        mock_httpx_client.get.assert_called_once_with(f"/reports/{report_id}")
        mock_response.raise_for_status.assert_called_once()
        assert result == expected_xml


class TestOpenVASConnectorConvenienceFunctions:
    """Test the convenience functions that wrap the client."""

    @pytest.mark.asyncio
    async def test_create_target_convenience(self):
        """Test the convenience create_target function."""
        with patch(
            "darkstar.openvas.openvas_connector.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.create_target.return_value = {"id": "target-123"}
            mock_client_class.return_value = mock_client

            result = await create_target("test", ["192.168.1.1"], port_range="80")

            mock_client.create_target.assert_called_once_with(
                "test", ["192.168.1.1"], port_range="80"
            )
            assert result == {"id": "target-123"}

    @pytest.mark.asyncio
    async def test_list_targets_convenience(self):
        """Test the convenience list_targets function."""
        with patch(
            "darkstar.openvas.openvas_connector.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.list_targets.return_value = [{"id": "target-1"}]
            mock_client_class.return_value = mock_client

            result = await list_targets()

            mock_client.list_targets.assert_called_once()
            assert result == [{"id": "target-1"}]

    @pytest.mark.asyncio
    async def test_create_task_convenience(self):
        """Test the convenience create_task function."""
        with patch(
            "darkstar.openvas.openvas_connector.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.create_task.return_value = {
                "id": "task-789",
                "name": "test-task",
            }
            mock_client_class.return_value = mock_client

            result = await create_task("test-task", "target-123")

            mock_client.create_task.assert_called_once_with("test-task", "target-123")
            assert result == {"id": "task-789", "name": "test-task"}

    @pytest.mark.asyncio
    async def test_list_tasks_convenience(self):
        """Test the convenience list_tasks function."""
        with patch(
            "darkstar.openvas.openvas_connector.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.list_tasks.return_value = [
                {"id": "task-1", "name": "Task 1", "status": "Running"},
                {"id": "task-2", "name": "Task 2", "status": "Done"},
            ]
            mock_client_class.return_value = mock_client

            result = await list_tasks()

            mock_client.list_tasks.assert_called_once()
            assert result == [
                {"id": "task-1", "name": "Task 1", "status": "Running"},
                {"id": "task-2", "name": "Task 2", "status": "Done"},
            ]

    @pytest.mark.asyncio
    async def test_start_task_convenience(self):
        """Test the convenience start_task function."""
        with patch(
            "darkstar.openvas.openvas_connector.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.start_task.return_value = {"report_id": "report-123"}
            mock_client_class.return_value = mock_client

            result = await start_task("task-456")

            mock_client.start_task.assert_called_once_with("task-456")
            assert result == {"report_id": "report-123"}

    @pytest.mark.parametrize(
        "task_id,expected_status",
        [
            ("task-running", {"status": "Running", "progress": 45}),
            ("task-done", {"status": "Done", "progress": 100}),
            ("task-failed", {"status": "Failed", "error": "Connection timeout"}),
            ("task-queued", {"status": "Queued", "progress": 0}),
        ],
    )
    @pytest.mark.asyncio
    async def test_get_task_status_convenience(self, task_id, expected_status):
        """Test the convenience get_task_status function with various statuses."""
        with patch(
            "darkstar.openvas.openvas_connector.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get_task_status.return_value = expected_status
            mock_client_class.return_value = mock_client

            result = await get_task_status(task_id)

            mock_client.get_task_status.assert_called_once_with(task_id)
            assert result == expected_status

    @pytest.mark.parametrize(
        "report_id,report_content",
        [
            (
                "report-xml",
                "<?xml version='1.0'?><report><vulnerability>SQLi</vulnerability></report>",
            ),
            ("report-empty", "<?xml version='1.0'?><report></report>"),
            (
                "report-large",
                "<?xml version='1.0'?><report>"
                + "<result>" * 100
                + "</result>" * 100
                + "</report>",
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_get_report_convenience(self, report_id, report_content):
        """Test the convenience get_report function with various report types."""
        with patch(
            "darkstar.openvas.openvas_connector.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get_report.return_value = report_content
            mock_client_class.return_value = mock_client

            result = await get_report(report_id)

            mock_client.get_report.assert_called_once_with(report_id)
            assert result == report_content

    @pytest.mark.asyncio
    async def test_convenience_functions_with_errors(self):
        """Test that convenience functions properly propagate errors."""
        with patch(
            "darkstar.openvas.openvas_connector.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.create_task.side_effect = HTTPStatusError(
                "Server Error", request=MagicMock(), response=MagicMock()
            )
            mock_client_class.return_value = mock_client

            with pytest.raises(HTTPStatusError):
                await create_task("failing-task", "target-123")

    @pytest.mark.asyncio
    async def test_convenience_functions_with_kwargs(self):
        """Test that convenience functions properly pass through kwargs."""
        with patch(
            "darkstar.openvas.openvas_connector.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.create_task.return_value = {"id": "task-with-kwargs"}
            mock_client_class.return_value = mock_client

            # Test create_task with additional kwargs
            result = await create_task("test-task", "target-123", custom_param="value")

            mock_client.create_task.assert_called_once_with(
                "test-task", "target-123", custom_param="value"
            )
            assert result == {"id": "task-with-kwargs"}


class TestOpenVASScanner:
    """Test cases for the OpenVASScanner class."""

    @pytest.fixture
    def scanner(self):
        """Fixture to provide an OpenVASScanner instance."""
        return OpenVASScanner(org_name="test-org", base_url="http://test-openvas:8008")

    @pytest.fixture
    def sample_xml_report(self):
        """Fixture providing a sample OpenVAS XML report."""
        return """<?xml version="1.0" encoding="UTF-8"?>
        <report>
            <result>
                <name>SQL Injection</name>
                <nvt>
                    <cve>CVE-2023-12345</cve>
                </nvt>
                <port>80/tcp</port>
                <threat>High</threat>
                <severity>7.5</severity>
                <description>SQL injection vulnerability found</description>
                <host>192.168.1.1</host>
                <qod>
                    <value>95</value>
                </qod>
            </result>
            <result>
                <name>httpOnly Flag Missing</name>
                <nvt>
                    <cve>NOCVE</cve>
                </nvt>
                <port>443/tcp</port>
                <threat>Low</threat>
                <severity>2.0</severity>
                <description>httpOnly flag missing on cookies</description>
                <host>192.168.1.2</host>
                <qod>
                    <value>80</value>
                </qod>
            </result>
            <result>
                <name>Buffer Overflow</name>
                <nvt>
                    <cve>CVE-2023-67890</cve>
                </nvt>
                <port>22/tcp</port>
                <threat>Critical</threat>
                <severity>9.8</severity>
                <description>Buffer overflow in SSH service</description>
                <host>192.168.1.3</host>
                <qod>
                    <value>99</value>
                </qod>
            </result>
        </report>"""

    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.org_name == "test-org"
        assert scanner.base_url == "http://test-openvas:8008"
        assert scanner.vulnerabilities == []

    def test_scanner_initialization_with_env_var(self):
        """Test scanner initialization with environment variable."""
        with patch.dict(os.environ, {"OPENVAS_API_URL": "http://env-openvas:9009"}):
            scanner = OpenVASScanner("env-org")
            assert scanner.base_url == "http://env-openvas:9009"

    @pytest.mark.asyncio
    async def test_scan_targets_success(self, scanner):
        """Test successful scanning of targets."""
        targets = ["192.168.1.1", "192.168.1.2"]

        with patch(
            "darkstar.openvas.openvas_scanner.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client_class.return_value = mock_client

            # Mock target creation
            mock_client.create_target.side_effect = [
                {"id": "target-1", "name": "Discovered 192.168.1.1 - 2025-07-23"},
                {"id": "target-2", "name": "Discovered 192.168.1.2 - 2025-07-23"},
            ]

            # Mock task creation
            mock_client.create_task.side_effect = [
                {"id": "task-1", "name": "Scan for target-1"},
                {"id": "task-2", "name": "Scan for target-2"},
            ]

            # Mock task starting
            mock_client.start_task.side_effect = [
                {"report_id": "report-1"},
                {"report_id": "report-2"},
            ]

            # Mock monitor_task_queue
            with patch.object(scanner, "monitor_task_queue") as mock_monitor:
                mock_monitor.return_value = None

                await scanner.scan_targets(targets)

                # Verify calls
                assert mock_client.create_target.call_count == 2
                assert mock_client.create_task.call_count == 2
                assert mock_client.start_task.call_count == 2
                mock_monitor.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_targets_with_errors(self, scanner):
        """Test scanning targets with some failures."""
        targets = ["192.168.1.1", "192.168.1.2"]

        with patch(
            "darkstar.openvas.openvas_scanner.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client_class.return_value = mock_client

            # Mock target creation with one failure
            mock_client.create_target.side_effect = [
                {"id": "target-1", "name": "Discovered 192.168.1.1 - 2025-07-23"},
                Exception("Target creation failed"),
            ]

            # Mock task creation
            mock_client.create_task.return_value = {
                "id": "task-1",
                "name": "Scan for target-1",
            }

            # Mock task starting
            mock_client.start_task.return_value = {"report_id": "report-1"}

            with patch.object(scanner, "monitor_task_queue") as mock_monitor:
                mock_monitor.return_value = None

                await scanner.scan_targets(targets)

                # Only one target should succeed
                assert mock_client.create_target.call_count == 2
                assert mock_client.create_task.call_count == 1
                assert mock_client.start_task.call_count == 1

    @pytest.mark.parametrize(
        "task_status,should_complete",
        [
            ("Done", True),
            ("Stopped", True),
            ("Failed", True),
            ("Interrupted", True),
            ("Running", False),
            ("Queued", False),
        ],
    )
    @pytest.mark.asyncio
    async def test_monitor_task_queue_status_handling(
        self, scanner, task_status, should_complete
    ):
        """Test task monitoring with different status values."""
        mock_client = AsyncMock()
        task_info = [
            {
                "task_id": "task-1",
                "task_name": "Test Task",
                "report_id": "report-1",
                "completed": False,
            }
        ]

        mock_client.get_task_status.return_value = {"status": task_status}
        mock_client.get_report.return_value = "<report></report>"

        with (
            patch("os.makedirs"),
            patch("builtins.open", mock_open()),
            patch.object(scanner, "parse_results_to_vulns") as mock_parse,
            patch("asyncio.sleep") as mock_sleep,
        ):
            # Mock sleep to avoid waiting in tests
            mock_sleep.side_effect = [None, Exception("Break loop")]

            try:
                await scanner.monitor_task_queue(mock_client, task_info)
            except Exception:
                pass  # Expected to break the loop

            assert task_info[0]["completed"] == should_complete
            if should_complete and task_status in ["Done", "Stopped"]:
                mock_client.get_report.assert_called_once_with("report-1")
                mock_parse.assert_called_once()

    @pytest.mark.asyncio
    async def test_parse_results_to_vulns(self, scanner, sample_xml_report):
        """Test parsing of XML report to vulnerabilities."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(sample_xml_report)
            report_file = f.name

        try:
            with (
                patch("requests.get") as mock_requests,
                patch(
                    "darkstar.openvas.openvas_scanner.insert_vulnerability_to_database"
                ) as mock_insert,
                patch(
                    "darkstar.core.models.vulnerability.Vulnerability.cve_enricher"
                ) as mock_cve_enricher,
            ):
                # Mock EPSS API response
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {"data": [{"percentile": 0.8}]}
                mock_requests.return_value = mock_response

                # Mock the CVE enricher to avoid subprocess calls
                mock_cve_enricher.return_value = {
                    "cvss": "7.5",
                    "epss": "0.8",
                    "summary": "Test CVE summary",
                    "impact": "High impact",
                    "solution": "Update software",
                }

                await scanner.parse_results_to_vulns(report_file)

                # Should have 2 vulnerabilities (one is skipped due to httpOnly)
                assert len(scanner.vulnerabilities) == 2

                # Check first vulnerability (SQL Injection)
                vuln1 = scanner.vulnerabilities[0]
                assert vuln1.title == "SQL Injection"
                assert vuln1.affected_item == "192.168.1.1"
                assert vuln1.tool == "OpenVAS"
                assert vuln1.confidence == 95

                # Check second vulnerability (Buffer Overflow)
                vuln2 = scanner.vulnerabilities[1]
                assert vuln2.title == "Buffer Overflow"
                assert vuln2.affected_item == "192.168.1.3"
                assert vuln2.confidence == 99

                # Verify database insertions
                assert mock_insert.call_count == 2

        finally:
            os.unlink(report_file)

    @pytest.mark.asyncio
    async def test_parse_results_invalid_xml(self, scanner):
        """Test parsing of invalid XML report."""
        invalid_xml = "This is not valid XML"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(invalid_xml)
            report_file = f.name

        try:
            await scanner.parse_results_to_vulns(report_file)

            # Should not crash and vulnerabilities should remain empty
            assert len(scanner.vulnerabilities) == 0

        finally:
            os.unlink(report_file)

    @pytest.mark.asyncio
    async def test_parse_results_nocve_vulnerability(self, scanner):
        """Test parsing vulnerability without CVE."""
        nocve_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <report>
            <result>
                <name>Custom Vulnerability</name>
                <nvt>
                    <cve>NOCVE</cve>
                </nvt>
                <port>8080/tcp</port>
                <threat>Medium</threat>
                <severity>5.0</severity>
                <description>Custom vulnerability description</description>
                <host>10.0.0.1</host>
                <qod>
                    <value>85</value>
                </qod>
            </result>
        </report>"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(nocve_xml)
            report_file = f.name

        try:
            with patch(
                "darkstar.openvas.openvas_scanner.insert_vulnerability_to_database"
            ) as mock_insert:
                await scanner.parse_results_to_vulns(report_file)

                assert len(scanner.vulnerabilities) == 1
                vuln = scanner.vulnerabilities[0]
                assert vuln.title == "Custom Vulnerability"
                assert vuln.summary == "Custom vulnerability description"
                mock_insert.assert_called_once()

        finally:
            os.unlink(report_file)

    def test_scanner_with_custom_base_url(self):
        """Test scanner initialization with custom base URL."""
        custom_url = "http://custom-openvas:7007"
        scanner = OpenVASScanner("custom-org", base_url=custom_url)
        assert scanner.base_url == custom_url
        assert scanner.org_name == "custom-org"


# Integration-style tests
class TestOpenVASIntegration:
    """Integration tests for OpenVAS components."""

    @pytest.mark.asyncio
    async def test_full_workflow_simulation(self):
        """Test a simulated full workflow from target creation to report parsing."""
        scanner = OpenVASScanner("integration-test")

        with patch(
            "darkstar.openvas.openvas_scanner.OpenVASAPIClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client_class.return_value = mock_client

            # Simulate successful workflow
            mock_client.create_target.return_value = {
                "id": "target-1",
                "name": "Test Target",
            }
            mock_client.create_task.return_value = {"id": "task-1", "name": "Test Task"}
            mock_client.start_task.return_value = {"report_id": "report-1"}
            mock_client.get_task_status.return_value = {"status": "Done"}
            mock_client.get_report.return_value = """<?xml version="1.0" encoding="UTF-8"?>
            <report>
                <result>
                    <name>Test Vulnerability</name>
                    <nvt><cve>CVE-2023-12345</cve></nvt>
                    <port>80/tcp</port>
                    <threat>High</threat>
                    <severity>7.5</severity>
                    <description>Test description</description>
                    <host>192.168.1.1</host>
                    <qod><value>95</value></qod>
                </result>
            </report>"""

            with (
                patch("os.makedirs"),
                patch("builtins.open", mock_open()),
                patch.object(scanner, "parse_results_to_vulns") as mock_parse,
                patch("asyncio.sleep", side_effect=[None, Exception("Break")]),
            ):
                mock_parse.return_value = None

                # This should complete without errors
                try:
                    await scanner.scan_targets(["192.168.1.1"])
                except Exception:
                    pass  # Expected from breaking the monitoring loop

                # Verify the workflow was followed
                mock_client.create_target.assert_called_once()
                mock_client.create_task.assert_called_once()
                mock_client.start_task.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])
