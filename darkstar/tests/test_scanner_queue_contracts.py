from contextlib import nullcontext

import pytest

from darkstar.core import db_helper


pytestmark = pytest.mark.unit


def test_capability_filter_is_applied_before_queue_limit(mocker):
    cursor = mocker.Mock()
    cursor.fetchone.side_effect = [
        {"max_parallel_jobs": 1},
        {"running": 0},
        {
            "id": 51,
            "payload_json": "{}",
            "scanner": "nuclei",
            "scan_mode": None,
            "org_db_name": "tenant",
            "scan_id": 7,
        },
    ]
    connection = mocker.Mock()
    connection.cursor.return_value = cursor
    mocker.patch.object(
        db_helper,
        "DatabaseConnectionManager",
        return_value=nullcontext(connection),
    )
    mocker.patch.object(db_helper, "_ensure_organizations_registry")
    mocker.patch.object(db_helper, "update_scan_status")

    result = db_helper.claim_next_scanner_job(
        "node-1",
        capabilities=["scanner:nuclei"],
    )

    select_calls = [
        call
        for call in cursor.execute.call_args_list
        if "SELECT *" in call.args[0] and "FROM scanner_jobs" in call.args[0]
    ]
    assert len(select_calls) == 1
    queue_query = select_calls[0].args[0]
    assert "LOWER(COALESCE" in queue_query
    assert "IN (%s)" in queue_query
    assert "LIMIT 1" in queue_query
    assert select_calls[0].args[1] == ("node-1", "nuclei")
    assert result["id"] == 51
