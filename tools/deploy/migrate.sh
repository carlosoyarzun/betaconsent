#!/usr/bin/env bash
# Gobierna: orden de Carlos 2026-10-18 (PR-F). Envoltorio de tools/deploy/migrate.ts para el servidor: carga las contrasenas de roles de
# /etc/consent/roles.env (root:root 0600), como root pasa a ser el usuario de SO postgres, conecta como superusuario "postgres" por el socket de Unix (peer) y delega en migrate.ts.
#   sudo tools/deploy/migrate.sh --phase cluster|database|cluster-post|local-grants|fixtures|all [--dry-run]
# Variables opcionales: PGHOST (default /var/run/postgresql), PGPORT, PGUSER (default postgres), CNS_DB_NAME (default consent), CNS_ETC_DIR.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ETC_DIR="${CNS_ETC_DIR:-/etc/consent}"
NODE_BIN="$(command -v node)"
[ -f "$ETC_DIR/roles.env" ] || { echo "migrate: falta $ETC_DIR/roles.env (ejecute install.sh primero)." >&2; exit 1; }
set -a
# shellcheck disable=SC1091
. "$ETC_DIR/roles.env"
set +a
export PGHOST="${PGHOST:-/var/run/postgresql}" PGUSER="${PGUSER:-postgres}"
export CNS_DB_NAME="${CNS_DB_NAME:-consent}"
# Los puertos TCP del migrador (consent_migrator no usa peer): por defecto 127.0.0.1 y el PGPORT.
# Sin root (pruebas, o un usuario que ya es superusuario de Postgres) no se cambia de usuario.
if [ "$(id -u)" != 0 ]; then exec "$NODE_BIN" "$ROOT/tools/deploy/migrate.ts" "$@"; fi
# -m conserva el entorno (contrasenas) sin ponerlas en argv; el usuario postgres solo necesita leer $ROOT (world-readable).
exec runuser -u postgres -m -- "$NODE_BIN" "$ROOT/tools/deploy/migrate.ts" "$@"
