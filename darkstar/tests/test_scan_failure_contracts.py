import pytest

from darkstar.main import worker


pytestmark = pytest.mark.unit


def _orchestrator(mocker):
    scanner = object.__new__(worker)
    scanner.target_df = object()
    scanner.org_domain = "tenant"
    scanner.bruteforce = False
    scanner.bruteforce_timeout = 30
    scanner.run_bbot = mocker.AsyncMock(
        return_value={"primary_targets_file": "/tmp/primary-targets.txt"}
    )
    scanner.run_port_scan = mocker.AsyncMock(return_value={})
    scanner.run_openvas_scan = mocker.AsyncMock(return_value=None)
    scanner.run_nuclei = mocker.AsyncMock(return_value=None)
    scanner.detect_wordpress_and_run_nuclei = mocker.AsyncMock(return_value=None)
    scanner.run_asteroid = mocker.AsyncMock(return_value=None)
    scanner.run_external_vulnerability_scanner = mocker.AsyncMock(return_value=None)
    return scanner


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["normal", "aggressive"])
async def test_scan_modes_propagate_downstream_failures(mode, mocker):
    scanner = _orchestrator(mocker)
    mocker.patch("darkstar.main.get_scan_targets", return_value=["192.0.2.10"])
    scanner.run_nuclei.side_effect = RuntimeError("templates unavailable")

    with pytest.raises(RuntimeError, match="nuclei-standard.*templates unavailable"):
        await getattr(scanner, f"{mode}_scan")()


@pytest.mark.asyncio
async def test_normal_scan_rejects_missing_primary_target_file(mocker):
    scanner = _orchestrator(mocker)
    mocker.patch("darkstar.main.get_scan_targets", return_value=["192.0.2.10"])
    scanner.run_bbot.return_value = {"primary_targets_file": None}

    with pytest.raises(RuntimeError, match="no primary target file"):
        await scanner.normal_scan()


@pytest.mark.asyncio
async def test_rustscan_target_failure_is_not_processed_as_success(mocker):
    scanner = _orchestrator(mocker)
    mocker.patch("darkstar.main.prepare_output_directory", return_value="/tmp/rustscan")
    mocker.patch(
        "darkstar.main.run_rustscan",
        new=mocker.AsyncMock(
            return_value={
                "scan_results": [
                    {
                        "target": "192.0.2.10",
                        "status": "failed",
                        "error": "rustscan timed out",
                    }
                ]
            }
        ),
    )
    process_results = mocker.patch("darkstar.main.process_scan_results")

    with pytest.raises(RuntimeError, match="192.0.2.10.*timed out"):
        await worker.run_port_scan(scanner, ["192.0.2.10"])

    process_results.assert_not_called()
