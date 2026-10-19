#!/usr/bin/env bash
# Gobierna: orden de Carlos 2026-10-18 (PR-F, paquete de instalacion manual, modo sintetico).
# Verificacion posterior a la instalacion. Solo lectura; no imprime secretos. Sale con 0 si todo pasa y con 1 si algo falla.
#   sudo tools/deploy/verify.sh [--no-systemd] [--public URL]
#   --no-systemd   omite las comprobaciones de systemctl (pruebas en una maquina sin systemd)
#   --public URL   ademas hace GET URL/healthz (por ejemplo https://consent.lectorpro.cl) a traves de nginx
# Variables: CNS_ETC_DIR (default /etc/consent), CNS_DB_NAME (default consent), CNS_WEB_PORT (default 3000), PGHOST/PGPORT/PGUSER/PGDATABASE para psql.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ETC_DIR="${CNS_ETC_DIR:-/etc/consent}"
DB_NAME="${CNS_DB_NAME:-consent}"
PORT="${CNS_WEB_PORT:-3000}"
SYSTEMD=1
PUBLIC=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-systemd) SYSTEMD=0 ;;
    --public) PUBLIC="${2:?--public necesita URL}"; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "verify: opcion desconocida: $1" >&2; exit 2 ;;
  esac
  shift
done

FAILS=0
ok()   { echo "  [ OK ] $*"; }
bad()  { echo "  [FAIL] $*"; FAILS=$((FAILS + 1)); }
warn() { echo "  [WARN] $*"; }

echo "1. Servicios y timers (systemd)"
if [ "$SYSTEMD" = 1 ]; then
  for u in consent-web.service consent-worker.service; do
    if systemctl is-active --quiet "$u"; then ok "$u activo"; else bad "$u NO esta activo (journalctl -u ${u%.service} -n 50)"; fi
  done
  for t in consent-reconciler.timer consent-chain-verifier.timer consent-breakglass-watch.timer; do
    if systemctl is-active --quiet "$t"; then ok "$t activo"; else bad "$t NO esta activo (systemctl start $t)"; fi
  done
  for u in consent-reconciler.service consent-chain-verifier.service consent-breakglass-watch.service; do
    if systemctl is-failed --quiet "$u"; then bad "$u quedo en failed (journalctl -u ${u%.service} -n 50)"; fi
  done
else
  warn "omitido (--no-systemd)"
fi

echo "2. Web: puerto y /healthz"
if command -v ss >/dev/null 2>&1; then
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q "^127\.0\.0\.1:${PORT}$"; then ok "escuchando en 127.0.0.1:${PORT}"; else bad "nadie escucha en 127.0.0.1:${PORT}"; fi
else
  warn "sin 'ss'; se comprueba solo por HTTP"
fi
if body="$(curl -fsS --max-time 5 "http://127.0.0.1:${PORT}/healthz" 2>/dev/null)" && echo "$body" | grep -q '"status":"ok"'; then ok "GET /healthz -> 200 $body"; else bad "GET http://127.0.0.1:${PORT}/healthz fallo"; fi
if [ -n "$PUBLIC" ]; then
  if body="$(curl -fsS --max-time 10 "${PUBLIC%/}/healthz" 2>/dev/null)" && echo "$body" | grep -q '"status":"ok"'; then ok "GET ${PUBLIC%/}/healthz (nginx + TLS) -> 200"; else bad "GET ${PUBLIC%/}/healthz fallo (nginx, TLS o DNS)"; fi
fi

echo "3. Migraciones aplicadas (ops.schema_migration)"
PSQL=(psql -X -A -t -q -d "$DB_NAME" -c)
if [ "$(id -u)" = 0 ] && command -v runuser >/dev/null 2>&1 && [ -z "${PGHOST:-}" ]; then PSQL=(runuser -u postgres -- psql -X -A -t -q -d "$DB_NAME" -c); fi
EXPECT="$(grep -l '^-- scope: database' "$ROOT"/db/migrations/*.sql 2>/dev/null | wc -l | tr -d ' ')"
LAST_EXPECT="$(grep -l '^-- scope: database' "$ROOT"/db/migrations/*.sql 2>/dev/null | sed -E 's#.*/([0-9]{4})_.*#\1#' | sort | tail -1)"
if got="$("${PSQL[@]}" "SELECT count(*) || '|' || coalesce(max(version), '-') FROM ops.schema_migration" 2>/dev/null)" && [ -n "$got" ]; then
  if [ "$got" = "${EXPECT}|${LAST_EXPECT}" ]; then ok "migraciones de base aplicadas: $EXPECT (ultima $LAST_EXPECT)"; else bad "ops.schema_migration = $got; se esperaba ${EXPECT}|${LAST_EXPECT} (ejecute tools/deploy/migrate.sh --phase all)"; fi
  if cat="$("${PSQL[@]}" "SELECT environment || '/' || data_class FROM ops.db_catalog" 2>/dev/null)" && [ "$cat" = "LOCAL/SYNTHETIC" ]; then ok "ops.db_catalog = LOCAL/SYNTHETIC"; else bad "ops.db_catalog = '${cat:-?}' (se esperaba LOCAL/SYNTHETIC)"; fi
else
  bad "no se pudo consultar ops.schema_migration en la base '$DB_NAME' (psql, permisos o migraciones sin aplicar)"
fi

echo "4. Archivos de entorno ($ETC_DIR)"
if [ -d "$ETC_DIR" ]; then
  shopt -s nullglob
  for f in "$ETC_DIR"/*.env; do
    name="$(basename "$f")"
    mode="$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null)"
    if [ "$mode" = "600" ]; then ok "$name modo 0600"; else bad "$name modo $mode (debe ser 0600 root:root)"; fi
    if [ "$name" != "roles.env" ] && grep -nE '%%|<[A-Za-z]|CHANGE_ME|<SECRETO>' "$f" >/dev/null 2>&1; then bad "$name contiene valores de ejemplo o marcadores sin reemplazar"; fi
    if [ "$name" != "roles.env" ] && ! grep -q '^CNS_ENVIRONMENT=LOCAL$' "$f"; then bad "$name: CNS_ENVIRONMENT no es LOCAL"; fi
  done
  for need in web worker reconciler chain-verifier roles; do [ -f "$ETC_DIR/$need.env" ] || bad "falta $ETC_DIR/$need.env (install.sh)"; done
  if [ -f "$ETC_DIR/web.env" ]; then
    for v in CNS_ALLOWED_ORIGIN CNS_SESSION_SECRET CNS_OTP_SECRET CNS_CHAIN_REF_SECRET CNS_DECISION_MAKER_REF_SECRET CNS_STAFF_ROSTER_CURSOR_SECRET; do grep -q "^${v}=." "$ETC_DIR/web.env" || bad "web.env: falta $v"; done
    grep -q '^CNS_ALLOWED_ORIGIN=https://' "$ETC_DIR/web.env" || bad "web.env: CNS_ALLOWED_ORIGIN debe ser https:// (cookies Secure)"
  fi
else
  bad "no existe $ETC_DIR"
fi

echo "5. Paquete"
[ -f "$ROOT/node_modules/pg/package.json" ] && ok "node_modules/pg presente" || bad "falta node_modules/pg (npm ci --omit=dev --ignore-scripts)"
[ -f "$ROOT/dist/index.html" ] && ok "dist/index.html presente (SPA)" || warn "sin dist/index.html: el web no arranca (la SPA es el unico modo de UI)"
[ -f "$ROOT/VERSION" ] && ok "VERSION: $(tr '\n' ' ' < "$ROOT/VERSION")" || warn "sin VERSION"

echo
if [ "$FAILS" = 0 ]; then echo "verify: TODO OK (modo sintetico)."; exit 0; fi
echo "verify: $FAILS comprobacion(es) fallaron." >&2; exit 1
