"""sql/init.sql must describe the same schema the application creates at runtime.

These drifted apart before: init.sql was missing all 13 control-plane and
endpoint-module tables, so a database seeded from that file alone had no
authentication, and two `preferred_node_id` columns were missing as well.
"""

import re
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
INIT_SQL = REPOSITORY_ROOT / "sql" / "init.sql"
DB_HELPER = REPOSITORY_ROOT / "darkstar" / "core" / "db_helper.py"

CREATE_TABLE_RE = re.compile(
    r"CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\((.*?)\n\s*\)", re.S
)


def _tables(source: str) -> dict[str, set[str]]:
    """Map every declared table to the set of column names it declares."""
    tables = {}
    for name, body in CREATE_TABLE_RE.findall(source):
        columns = set()
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            if not line or line.startswith("--"):
                continue
            if re.match(
                r"(PRIMARY KEY|UNIQUE KEY|INDEX|KEY|FOREIGN KEY|CONSTRAINT)\b",
                line,
                re.I,
            ):
                continue
            column = line.split()[0].strip("`")
            columns.add(column)
        tables[name] = columns
    return tables


@pytest.fixture(scope="module")
def schemas():
    return _tables(INIT_SQL.read_text(encoding="utf-8")), _tables(
        DB_HELPER.read_text(encoding="utf-8")
    )


def test_init_sql_declares_every_table_the_code_creates(schemas):
    init_tables, code_tables = schemas
    missing = sorted(set(code_tables) - set(init_tables))
    assert not missing, (
        "sql/init.sql is missing tables the application creates at runtime: "
        f"{missing}. A database seeded from this file alone would be incomplete."
    )


def test_init_sql_and_code_agree_on_columns(schemas):
    init_tables, code_tables = schemas
    drift = {}
    for table, code_columns in code_tables.items():
        init_columns = init_tables.get(table)
        if init_columns is None:
            continue  # reported by the test above
        # Columns added later live in ORG_SCHEMA_MIGRATION_STATEMENTS, so the
        # code side is the authority; init.sql may not lag behind it.
        missing = code_columns - init_columns
        if missing:
            drift[table] = sorted(missing)
    assert not drift, f"sql/init.sql lags behind the runtime schema: {drift}"


def test_migration_added_columns_are_present_in_init_sql():
    """Columns introduced by a migration must also exist for fresh installs."""
    source = DB_HELPER.read_text(encoding="utf-8")
    init_sql = INIT_SQL.read_text(encoding="utf-8")
    init_tables = _tables(init_sql)

    block = re.search(
        r"ORG_SCHEMA_MIGRATION_STATEMENTS = \[(.*?)\n\]", source, re.S
    )
    assert block, "ORG_SCHEMA_MIGRATION_STATEMENTS not found"

    missing = []
    for table, column in re.findall(
        r"ALTER TABLE (\w+) ADD COLUMN IF NOT EXISTS (\w+)", block.group(1)
    ):
        if table in init_tables and column not in init_tables[table]:
            missing.append(f"{table}.{column}")
    assert not missing, (
        "these columns are added by a migration but absent from sql/init.sql, "
        f"so a fresh install would not have them: {sorted(missing)}"
    )
