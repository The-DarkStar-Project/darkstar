from contextlib import nullcontext

import pytest

from darkstar.core import db_helper


pytestmark = pytest.mark.unit


@pytest.fixture()
def user_database(mocker):
    cursor = mocker.Mock()
    cursor.fetchone.side_effect = [{"id": 7}, {"org_db_name": "org_alpha"}]
    connection = mocker.Mock()
    connection.cursor.return_value = cursor
    mocker.patch.object(db_helper, "DatabaseConnectionManager", return_value=nullcontext(connection))
    mocker.patch.object(db_helper, "_ensure_organizations_registry")
    mocker.patch.object(db_helper, "get_user_by_id", return_value={"id": 7})
    return cursor, connection


@pytest.mark.parametrize(
    "memberships",
    [
        [],
        [{"org_db_name": "org_beta", "role": "tenant_admin"}],
        [{"org_db_name": "org_alpha", "role": "platform_admin"}],
        [
            {"org_db_name": "org_alpha", "role": "viewer"},
            {"org_db_name": "org_beta", "role": "viewer"},
        ],
    ],
)
@pytest.mark.parametrize("password", [None, "ChangedPassword1!"])
def test_tenant_cannot_change_or_assign_global_accounts(user_database, memberships, password):
    cursor, connection = user_database
    cursor.fetchall.return_value = memberships

    with pytest.raises(PermissionError, match="platform administrator"):
        db_helper.create_or_update_user(
            "shared@example.test", password, "Changed name", "org_alpha", "tenant_admin",
            restrict_to_org=True,
        )

    assert all(call.args[0].lstrip().startswith("SELECT") for call in cursor.execute.call_args_list)
    connection.commit.assert_not_called()


@pytest.mark.parametrize("new_user", [False, True])
def test_tenant_can_manage_its_own_users(user_database, new_user):
    cursor, connection = user_database
    cursor.fetchone.side_effect = [None if new_user else {"id": 7}, {"org_db_name": "org_alpha"}]
    cursor.fetchall.return_value = [{"org_db_name": "org_alpha", "role": "viewer"}]

    result = db_helper.create_or_update_user(
        "local@example.test", "LocalPassword1!", "Local user", "org_alpha", "tenant_admin",
        restrict_to_org=True,
    )

    assert result == {"id": 7}
    connection.commit.assert_called_once()


def test_platform_admin_can_manage_shared_accounts(user_database):
    cursor, connection = user_database

    result = db_helper.create_or_update_user(
        "shared@example.test", "UpdatedPassword1!", "Shared user", "org_alpha", "viewer",
        restrict_to_org=False,
    )

    assert result == {"id": 7}
    cursor.fetchall.assert_not_called()
    connection.commit.assert_called_once()
