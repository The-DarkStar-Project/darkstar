from contextlib import nullcontext

import mysql.connector
import pytest

from darkstar.core import db_helper as db


pytestmark = pytest.mark.unit


@pytest.fixture()
def organization_database(mocker):
    cursor = mocker.Mock()
    cursor.fetchone.return_value = None
    connection = mocker.Mock()
    connection.cursor.return_value = cursor
    manager = mocker.patch.object(db, "DatabaseConnectionManager", return_value=nullcontext(connection))
    mocker.patch.object(db, "_ensure_organizations_registry")
    mocker.patch.object(db, "_lock_organization")
    schema = mocker.patch.object(db, "_apply_org_schema")
    return cursor, connection, manager, schema


@pytest.mark.parametrize("name", ["", " \t\n", "!!!", "ééé", "a" * 101, "a" * 65])
def test_invalid_organization_names_do_not_touch_database(organization_database, name):
    _cursor, _connection, manager, _schema = organization_database
    with pytest.raises(ValueError):
        db.create_organization(name)
    manager.assert_not_called()


def test_create_organization_initializes_schema_before_publishing(organization_database):
    cursor, connection, _manager, schema = organization_database

    def initialize(cursor):
        assert not any("INSERT INTO organizations" in call.args[0] for call in cursor.execute.call_args_list)
        cursor.execute("CREATE TABLE provisioning_test (id INT)")

    schema.side_effect = initialize
    organization = db.create_organization("  Acme Security  ")

    assert organization == {"org_name": "Acme Security", "org_db_name": "org_acme_security", "role": "tenant_admin"}
    schema.assert_called_once_with(cursor)
    connection.commit.assert_called_once()
    insert = next(call for call in cursor.execute.call_args_list if "INSERT INTO organizations" in call.args[0])
    assert insert.args[1][0:2] == ("Acme Security", "org_acme_security")
    assert insert.args[1][4] == "tenant_admin"
    assert insert.args[1][5] is None
    assert len(insert.args[1][3]) == 64
    assert not any("DROP DATABASE" in call.args[0] for call in cursor.execute.call_args_list)


def test_duplicate_organization_does_not_change_existing_schema(organization_database):
    cursor, connection, _manager, schema = organization_database
    cursor.fetchone.return_value = {"org_db_name": "org_acme_security"}
    with pytest.raises(db.OrganizationAlreadyExistsError):
        db.create_organization("Acme-Security")
    schema.assert_not_called()
    connection.commit.assert_not_called()
    assert all(call.args[0].startswith("SELECT") for call in cursor.execute.call_args_list)


@pytest.mark.parametrize("errno", [1007, 1044])
def test_existing_database_or_create_failure_is_never_dropped(organization_database, errno):
    cursor, _connection, _manager, schema = organization_database

    def execute(statement, *_args):
        if statement.startswith("CREATE DATABASE"):
            raise mysql.connector.Error("Cannot create database", errno=errno)

    cursor.execute.side_effect = execute
    error = db.OrganizationAlreadyExistsError if errno == 1007 else mysql.connector.Error
    with pytest.raises(error):
        db.create_organization("Acme")
    schema.assert_not_called()
    assert not any("DROP DATABASE" in call.args[0] for call in cursor.execute.call_args_list)


def test_schema_failure_drops_partial_database_without_publishing(organization_database):
    cursor, connection, _manager, schema = organization_database
    schema.side_effect = mysql.connector.Error("Schema failed")
    with pytest.raises(mysql.connector.Error, match="Schema failed"):
        db.create_organization("Acme")
    cursor.execute.assert_any_call("DROP DATABASE `org_acme`")
    assert not any("INSERT INTO organizations" in call.args[0] for call in cursor.execute.call_args_list)
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()


def test_duplicate_registry_insert_cleans_up_only_new_database(organization_database):
    cursor, _connection, _manager, _schema = organization_database

    def execute(statement, *_args):
        if "INSERT INTO organizations" in statement:
            raise mysql.connector.IntegrityError("Duplicate name", errno=1062)

    cursor.execute.side_effect = execute
    with pytest.raises(db.OrganizationAlreadyExistsError):
        db.create_organization("Acme")
    cursor.execute.assert_any_call("DROP DATABASE `org_acme`")


def test_commit_failure_rolls_back_before_dropping_database(organization_database, mocker):
    cursor, connection, _manager, _schema = organization_database
    calls = mocker.Mock()
    calls.attach_mock(connection.rollback, "rollback")
    calls.attach_mock(cursor.execute, "execute")
    connection.commit.side_effect = mysql.connector.Error("Commit failed")

    with pytest.raises(mysql.connector.Error, match="Commit failed"):
        db.create_organization("Acme")

    assert calls.mock_calls[-2:] == [mocker.call.rollback(), mocker.call.execute("DROP DATABASE `org_acme`")]


def test_bootstrap_still_reuses_existing_organization(organization_database):
    cursor, _connection, _manager, schema = organization_database
    cursor.fetchone.return_value = {"org_db_name": "org_platform_admin"}

    assert db._ensure_organization_record(cursor, "platform_admin", "unused", "platform_admin") == "org_platform_admin"

    cursor.execute.assert_any_call("CREATE DATABASE IF NOT EXISTS `org_platform_admin`")
    schema.assert_called_once()
    assert not any("INSERT INTO organizations" in call.args[0] for call in cursor.execute.call_args_list)
