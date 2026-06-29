import os
import subprocess
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_mariadb_compose_uses_darkstar_bootstrap_scripts():
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yaml").read_text())
    mariadb = compose["services"]["mariadb"]

    assert mariadb["entrypoint"] == [
        "/bin/bash",
        "/usr/local/bin/darkstar-mariadb-entrypoint.sh",
    ]
    assert mariadb["command"] == ["mysqld"]
    assert (
        "./docker/mariadb-entrypoint.sh:/usr/local/bin/darkstar-mariadb-entrypoint.sh:ro"
        in mariadb["volumes"]
    )
    assert (
        "./sql/init-darkstar.sh:/docker-entrypoint-initdb.d/10-init-darkstar.sh:ro"
        in mariadb["volumes"]
    )
    assert (
        "./sql/init.sql:/docker-entrypoint-initdb.d/darkstar-schema.sql.template:ro"
        in mariadb["volumes"]
    )
    assert "./sql/init.sql:/docker-entrypoint-initdb.d/init.sql" not in mariadb["volumes"]
    assert mariadb["healthcheck"]["start_period"] == "30s"


@pytest.mark.unit
def test_darkstar_schema_is_database_and_user_agnostic():
    schema = (REPO_ROOT / "sql" / "init.sql").read_text()

    assert "CREATE TABLE IF NOT EXISTS vulnerability" in schema
    assert "CREATE DATABASE IF NOT EXISTS test" not in schema
    assert "USE test" not in schema
    assert "data_miner" not in schema
    assert "GRANT " not in schema


@pytest.mark.unit
def test_mariadb_init_script_uses_env_database_and_scoped_tenant_grants():
    script = (REPO_ROOT / "sql" / "init-darkstar.sh").read_text()

    assert "MARIADB_DATABASE" in script
    assert "MARIADB_USER" in script
    assert "darkstar-schema.sql.template" in script
    assert "GRANT ALL PRIVILEGES ON \\`org\\_%\\`.*" in script
    assert "GRANT CREATE, ALTER, DROP ON *.*" not in script
    assert "data_miner" not in script


@pytest.mark.unit
def test_mariadb_entrypoint_only_repairs_uninitialized_partial_aria_bootstrap():
    script = (REPO_ROOT / "docker" / "mariadb-entrypoint.sh").read_text()

    assert 'system_database="${datadir}/mysql"' in script
    assert 'aria_control="${datadir}/aria_log_control"' in script
    assert '[[ ! -d "${system_database}" && -e "${aria_control}" ]]' in script
    assert "aria_size" in script
    assert "rm -f" in script
    assert 'exec docker-entrypoint.sh "$@"' in script


@pytest.mark.unit
def test_mariadb_bootstrap_scripts_have_valid_bash_syntax():
    scripts = [
        REPO_ROOT / "docker" / "mariadb-entrypoint.sh",
        REPO_ROOT / "sql" / "init-darkstar.sh",
    ]

    for script in scripts:
        assert os.access(script, os.R_OK)
        subprocess.run(["bash", "-n", str(script)], check=True)
