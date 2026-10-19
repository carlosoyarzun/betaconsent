#!/usr/bin/env bash
# Gobierna: plan v2 H1-01. Clúster PostgreSQL TEMPORAL para los tests de integración (fuera del repo; nunca el Postgres de uso diario).
#   eval "$(beta/scripts/pg-temp.sh start)"   # crea el clúster en un directorio temporal, exporta TEST_DATABASE_URL y PSQL
#   npm run test:integration
#   beta/scripts/pg-temp.sh stop <dir>        # apaga y borra el clúster
set -euo pipefail
PGBIN="${PGBIN:-$(ls -d /Applications/Postgres.app/Contents/Versions/latest/bin 2>/dev/null || dirname "$(command -v initdb)")}"
case "${1:-}" in
  start)
    dir="$(mktemp -d "${TMPDIR:-/tmp}/consent-beta-pg.XXXXXX")"
    port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
    pw="$(openssl rand -hex 12)"
    printf '%s' "$pw" > "$dir/pw"
    "$PGBIN/initdb" -D "$dir/data" -U beta_super --pwfile="$dir/pw" --auth=scram-sha-256 --encoding=UTF8 >/dev/null
    "$PGBIN/pg_ctl" -D "$dir/data" -l "$dir/pg.log" -w -o "-p $port -c listen_addresses=127.0.0.1 -c unix_socket_directories=$dir -c fsync=off" start >/dev/null
    echo "export TEST_DATABASE_URL='postgresql://beta_super:$pw@127.0.0.1:$port/postgres'; export PSQL='$PGBIN/psql'; export PG_TEMP_DIR='$dir'"
    ;;
  stop)
    dir="${2:?directorio del clúster}"
    "$PGBIN/pg_ctl" -D "$dir/data" -m immediate stop >/dev/null || true
    rm -rf "$dir"
    ;;
  *) echo "uso: $0 start | stop <dir>" >&2; exit 2 ;;
esac
