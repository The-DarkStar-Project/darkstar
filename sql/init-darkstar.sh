#!/usr/bin/env bash
set -Eeuo pipefail

schema_file="/docker-entrypoint-initdb.d/darkstar-schema.sql.template"
root_password="${MARIADB_ROOT_PASSWORD:-${MYSQL_ROOT_PASSWORD:-}}"
database="${MARIADB_DATABASE:-${MYSQL_DATABASE:-}}"
app_user="${MARIADB_USER:-${MYSQL_USER:-}}"

if [[ -z "${root_password}" ]]; then
  echo "[Darkstar MariaDB init] MARIADB_ROOT_PASSWORD or MYSQL_ROOT_PASSWORD is required." >&2
  exit 1
fi

if [[ -z "${database}" ]]; then
  echo "[Darkstar MariaDB init] MARIADB_DATABASE or MYSQL_DATABASE is required." >&2
  exit 1
fi

if [[ -z "${app_user}" ]]; then
  echo "[Darkstar MariaDB init] MARIADB_USER or MYSQL_USER is required." >&2
  exit 1
fi

if [[ ! -r "${schema_file}" ]]; then
  echo "[Darkstar MariaDB init] Missing schema file: ${schema_file}" >&2
  exit 1
fi

quote_identifier() {
  local value="${1//\`/\`\`}"
  printf '`%s`' "${value}"
}

quote_literal() {
  local value="${1//\\/\\\\}"
  value="${value//\'/\'\'}"
  printf "'%s'" "${value}"
}

mariadb_cmd=(mariadb --protocol=socket -uroot -p"${root_password}")
database_identifier="$(quote_identifier "${database}")"
app_user_literal="$(quote_literal "${app_user}")"

echo "[Darkstar MariaDB init] Applying schema to ${database}."
"${mariadb_cmd[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS ${database_identifier};
SQL
"${mariadb_cmd[@]}" "${database}" < "${schema_file}"

echo "[Darkstar MariaDB init] Granting tenant database privileges to ${app_user}."
"${mariadb_cmd[@]}" <<SQL
GRANT ALL PRIVILEGES ON \`org\_%\`.* TO ${app_user_literal}@'%';
FLUSH PRIVILEGES;
SQL
