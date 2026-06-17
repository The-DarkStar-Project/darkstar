#!/usr/bin/env bash
set -Eeuo pipefail

datadir="${MARIADB_DATADIR:-/var/lib/mysql}"
system_database="${datadir}/mysql"
aria_control="${datadir}/aria_log_control"

if [[ ! -d "${system_database}" && -e "${aria_control}" ]]; then
  aria_size="$(wc -c < "${aria_control}" 2>/dev/null || printf '0')"

  if [[ "${aria_size}" =~ ^[0-9]+$ && "${aria_size}" -lt 52 ]]; then
    echo "[Darkstar MariaDB] Removing partial Aria bootstrap files from an uninitialized datadir."
    rm -f \
      "${aria_control}" \
      "${datadir}"/aria_log.* \
      "${datadir}"/ib_logfile* \
      "${datadir}"/ibdata1 \
      "${datadir}"/ibtmp1 \
      "${datadir}"/multi-master.info
  fi
fi

exec docker-entrypoint.sh "$@"
