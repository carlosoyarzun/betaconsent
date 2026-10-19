#!/usr/bin/env bash
# Gobierna: orden de Carlos 2026-10-18 (PR-F, paquete de instalacion manual, modo sintetico), ADR-003 rev. 7 (host propio), ADR-010 rev. 4 INV-DBR-02
# (un usuario de SO y un rol LOGIN de Postgres por proceso). Solo datos sinteticos.
#
# Instala el paquete YA descomprimido en /opt/consent-app (npm ci --omit=dev --ignore-scripts hecho). Idempotente: se puede repetir; NO sobrescribe
# secretos ni env existentes (salvo --regenerate-env). NO migra la base ni arranca servicios (eso lo hacen migrate.sh y systemctl, ver README-DEPLOY.md).
#
#   sudo tools/deploy/install.sh [--dry-run] [--origin URL] [--db-host H] [--db-port P] [--db-name N] [--regenerate-env]
#   tools/deploy/install.sh --render-only DIR      (sin root ni cambios en el SO: solo escribe roles.env y los <proceso>.env en DIR; para pruebas)
#
# --dry-run: muestra lo que haria; nunca imprime secretos y no escribe nada.
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX_DEFAULT="$(cd "$HERE/../.." && pwd)"
PREFIX="${CNS_PREFIX:-$PREFIX_DEFAULT}"
ETC_DIR="${CNS_ETC_DIR:-/etc/consent}"
UNIT_DIR="${CNS_SYSTEMD_DIR:-/etc/systemd/system}"
ORIGIN="https://consent.lectorpro.cl"
DB_HOST="127.0.0.1"
DB_PORT="5432"
DB_NAME="consent"
DRY=0
REGEN=0
RENDER_ONLY=""

# Procesos con env generado (los 5 habilitados o habilitables). verifier no se genera: requiere parametros PENDING (ver .env.example).
ENV_PROCESSES="web worker platform reconciler chain-verifier"
OS_USERS="consent-web consent-worker consent-platform consent-verifier consent-reconciler consent-chain-verifier"
ENABLE_UNITS="consent-web.service consent-worker.service consent-reconciler.timer consent-chain-verifier.timer consent-breakglass-watch.timer"
ROLE_KEYS="CONSENT_MIGRATOR APP_RW WORKER PLATFORM_RW INTEGRITY_VERIFIER INTEGRITY_RECONCILER INTEGRITY_CHAIN_VERIFIER"
SECRET_KEYS="SESSION OTP CHAIN_REF DMREF ROSTER_CURSOR"

die() { echo "install: ERROR: $*" >&2; exit 1; }
say() { echo "install: $*"; }
act() { if [ "$DRY" = 1 ]; then echo "install: [dry-run] $*"; else say "$*"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --regenerate-env) REGEN=1 ;;
    --origin) ORIGIN="${2:?--origin necesita valor}"; shift ;;
    --db-host) DB_HOST="${2:?}"; shift ;;
    --db-port) DB_PORT="${2:?}"; shift ;;
    --db-name) DB_NAME="${2:?}"; shift ;;
    --render-only) RENDER_ONLY="${2:?--render-only necesita un directorio}"; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) die "opcion desconocida: $1" ;;
  esac
  shift
done

case "$ORIGIN" in https://*) ;; *) die "--origin debe empezar por https:// (las cookies __Host-* son Secure)" ;; esac
case "$ORIGIN" in */) die "--origin sin barra final" ;; esac
case "$DB_NAME" in [a-z]*) ;; *) die "--db-name invalido" ;; esac
case "$DB_PORT" in ''|*[!0-9]*) die "--db-port invalido" ;; esac

[ -n "$RENDER_ONLY" ] && ETC_DIR="$RENDER_ONLY"
if [ -z "$RENDER_ONLY" ] && [ -z "${CNS_PREFIX:-}" ] && [ "$PREFIX" != "/opt/consent-app" ]; then
  msg="el paquete debe estar en /opt/consent-app (las unidades systemd usan esa ruta); esta en $PREFIX."
  if [ "$DRY" = 1 ]; then echo "install: [dry-run] AVISO: $msg" >&2; else die "$msg"; fi
fi
EXAMPLE="$HERE/.env.example"
[ -f "$EXAMPLE" ] || EXAMPLE="$PREFIX/.env.example"
[ -f "$EXAMPLE" ] || die "no encuentro .env.example"

# ---------- 1. Prerrequisitos ----------
NODE_BIN="$(command -v node || true)"
check_prereqs() {
  local problems=0
  if [ -z "$RENDER_ONLY" ] && [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then echo "install: ERROR: ejecutar como root (sudo)." >&2; problems=1; fi
  if [ -z "$NODE_BIN" ]; then echo "install: ERROR: no hay 'node' en el PATH (se requiere Node 24)." >&2; problems=1
  else
    local v; v="$("$NODE_BIN" -p 'process.versions.node')"
    case "$v" in 24.*) ;; *) echo "install: ERROR: Node $v; el paquete exige Node 24 (package.json engines 24.21.0; type-stripping nativo)." >&2; problems=1 ;; esac
    [ "$v" = "24.21.0" ] || say "aviso: Node $v difiere del 24.21.0 de package.json engines (CI usa 24.21.0)."
    case "$NODE_BIN" in /home/*|/root/*|/Users/*) echo "install: ERROR: node en $NODE_BIN; las unidades usan ProtectHome=true y no lo veran. Instale Node en /usr/bin o /usr/local/bin." >&2; problems=1 ;; esac
  fi
  command -v openssl >/dev/null 2>&1 || { echo "install: ERROR: falta openssl." >&2; problems=1; }
  [ -d "$PREFIX/node_modules/pg" ] || { echo "install: ERROR: falta $PREFIX/node_modules/pg: ejecute 'npm ci --omit=dev --ignore-scripts' en $PREFIX." >&2; problems=1; }
  [ -f "$PREFIX/src/server/entrypoints/web/main.ts" ] || { echo "install: ERROR: $PREFIX no contiene src/ (paquete mal descomprimido)." >&2; problems=1; }
  if [ ! -f "$PREFIX/dist/index.html" ]; then echo "install: ERROR: la SPA requiere $PREFIX/dist/index.html." >&2; problems=1; fi
  if [ -z "$RENDER_ONLY" ] && ! command -v systemctl >/dev/null 2>&1; then echo "install: ERROR: no hay systemd (systemctl)." >&2; problems=1; fi
  [ "$problems" = 0 ] || die "prerrequisitos incumplidos (arriba)."
}
if [ "$DRY" = 1 ]; then
  # En dry-run los prerrequisitos se informan pero no abortan antes de mostrar el plan completo.
  ( check_prereqs ) || say "[dry-run] hay prerrequisitos incumplidos; el plan sigue para que pueda revisarlo."
else
  check_prereqs
fi

# ---------- 2. Secretos locales (roles.env, root:root 0600) ----------
ROLES_ENV="$ETC_DIR/roles.env"
gen_pw() { openssl rand -hex 24; }
gen_secret() { openssl rand -base64 32; }

ensure_roles_env() {
  local k
  if [ "$DRY" = 1 ]; then
    if [ -f "$ROLES_ENV" ]; then act "reutilizaria $ROLES_ENV (ya existe; no se toca)"; else act "generaria $ROLES_ENV (0600 root:root) con 7 contrasenas de roles y 5 secretos aleatorios"; fi
    return
  fi
  mkdir -p "$ETC_DIR"
  if [ -z "$RENDER_ONLY" ]; then chown root:root "$ETC_DIR"; chmod 0750 "$ETC_DIR"; fi
  [ -f "$ROLES_ENV" ] || { : > "$ROLES_ENV"; chmod 0600 "$ROLES_ENV"; say "creado $ROLES_ENV"; }
  for k in $ROLE_KEYS; do
    grep -q "^CNS_PW_${k}=" "$ROLES_ENV" || echo "CNS_PW_${k}=$(gen_pw)" >> "$ROLES_ENV"
  done
  for k in $SECRET_KEYS; do
    grep -q "^CNS_GEN_SECRET_${k}=" "$ROLES_ENV" || echo "CNS_GEN_SECRET_${k}=$(gen_secret)" >> "$ROLES_ENV"
  done
  chmod 0600 "$ROLES_ENV"
  [ -z "$RENDER_ONLY" ] && chown root:root "$ROLES_ENV"
  return 0
}

role_value() { grep "^$1=" "$ROLES_ENV" | head -1 | cut -d= -f2-; }

# ---------- 3. Render de /etc/consent/<proceso>.env desde .env.example ----------
render_block() { # $1 = proceso -> stdout con marcadores sustituidos
  local block="$1" line key val
  awk -v b="$block" '/^#@ block: /{cur=$3; next} cur==b && $0 !~ /^[[:space:]]*#/ && NF {print}' "$EXAMPLE" | while IFS= read -r line; do
    for key in $ROLE_KEYS; do
      case "$line" in *"%%PW_${key}%%"*) val="$(role_value "CNS_PW_${key}")"; line="${line//"%%PW_${key}%%"/$val}" ;; esac
    done
    for key in $SECRET_KEYS; do
      case "$line" in *"%%SECRET_${key}%%"*) val="$(role_value "CNS_GEN_SECRET_${key}")"; line="${line//"%%SECRET_${key}%%"/$val}" ;; esac
    done
    line="${line//"%%DB_HOST%%"/$DB_HOST}"; line="${line//"%%DB_PORT%%"/$DB_PORT}"; line="${line//"%%DB_NAME%%"/$DB_NAME}"
    line="${line//"%%ORIGIN%%"/$ORIGIN}"
    printf '%s\n' "$line"
  done
}

validate_env_file() { # $1 = archivo
  local f="$1"
  if grep -nE '%%|<[A-Za-z]' "$f" >/dev/null 2>&1; then die "$f contiene marcadores sin reemplazar (%%...%% o <...>)."; fi
  grep -q '^CNS_DATABASE_URL=' "$f" || die "$f no define CNS_DATABASE_URL (obligatoria)."
  grep -q '^CNS_ENVIRONMENT=LOCAL$' "$f" || die "$f: CNS_ENVIRONMENT debe ser LOCAL (modo sintetico)."
  if [ "$(basename "$f")" = web.env ]; then
    local v
    for v in CNS_ALLOWED_ORIGIN CNS_SESSION_SECRET CNS_OTP_SECRET CONSENT_STORE; do grep -q "^${v}=." "$f" || die "web.env: falta la variable obligatoria $v."; done
  fi
}

write_envs() {
  local p f
  for p in $ENV_PROCESSES; do
    f="$ETC_DIR/$p.env"
    if [ "$DRY" = 1 ]; then
      if [ -f "$f" ] && [ "$REGEN" = 0 ]; then act "conservaria $f (existe)"; else act "escribiria $f (0600 root:root) desde .env.example [bloque $p]"; fi
      continue
    fi
    if [ -f "$f" ] && [ "$REGEN" = 0 ]; then say "conservo $f (existe; --regenerate-env lo reescribe)"; validate_env_file "$f"; continue; fi
    render_block "$p" > "$f.tmp"
    chmod 0600 "$f.tmp"
    validate_env_file "$f.tmp"
    mv "$f.tmp" "$f"
    [ -z "$RENDER_ONLY" ] && chown root:root "$f"
    say "escrito $f"
  done
}

# ---------- 4. Usuarios de SO, permisos, units ----------
install_os() {
  local u
  for u in $OS_USERS; do
    if id -u "$u" >/dev/null 2>&1; then say "usuario $u ya existe"; else
      act "crearia el usuario de sistema $u (sin shell, sin home)"
      [ "$DRY" = 1 ] || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$u"
    fi
  done
  act "dejaria $PREFIX como root:root, solo lectura para los procesos (go-w)"
  if [ "$DRY" = 0 ]; then chown -R root:root "$PREFIX"; chmod -R go-w,a+rX "$PREFIX"; fi

  local f name
  for f in "$PREFIX"/infra/systemd/*.service "$PREFIX"/infra/systemd/*.timer; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    act "instalaria $UNIT_DIR/$name (ExecStart con node=$NODE_BIN)"
    if [ "$DRY" = 0 ]; then
      sed "s#/usr/bin/node #${NODE_BIN} #" "$f" > "$UNIT_DIR/$name.tmp"
      chmod 0644 "$UNIT_DIR/$name.tmp"; mv "$UNIT_DIR/$name.tmp" "$UNIT_DIR/$name"
    fi
  done
  act "systemctl daemon-reload"
  [ "$DRY" = 1 ] || systemctl daemon-reload
  for name in $ENABLE_UNITS; do
    act "systemctl enable $name (sin arrancar: primero migrate.sh)"
    [ "$DRY" = 1 ] || systemctl enable "$name" >/dev/null 2>&1
  done
  say "NO habilitadas a proposito: consent-platform (sin IdP no tiene login) y consent-verifier (parametros PENDING). Ver README-DEPLOY.md."
}

# ---------- Ejecucion ----------
say "prefijo=$PREFIX etc=$ETC_DIR origen=$ORIGIN db=$DB_HOST:$DB_PORT/$DB_NAME"
ensure_roles_env
write_envs
if [ -z "$RENDER_ONLY" ]; then install_os; fi
if [ "$DRY" = 1 ]; then say "[dry-run] fin del plan. No se escribio nada ni se imprimio ningun secreto."; else say "listo. Siguiente paso: tools/deploy/migrate.sh --phase all (README-DEPLOY.md, paso 7)."; fi
