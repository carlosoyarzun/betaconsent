#!/usr/bin/env bash
# Gobierna: orden de Carlos 2026-10-18 (PR-F, paquete de instalacion manual, modo sintetico).
# Genera consent-app-deploy.zip a partir del arbol git (SOLO archivos versionados + dist/ recien construido). Reproducible: el mismo commit produce el mismo
# contenido (salvo VERSION, que lleva la fecha). No toca nada fuera de <salida> ni del repo (npm ci / dist/ ya estan en .gitignore).
#   tools/deploy/build-package.sh [directorio-de-salida]        (default: ./build/, ignorado por git)
# Se ejecuta desde cualquier directorio; trabaja sobre la raiz del repo. Requiere: node 24, npm, git, zip, shasum|sha256sum.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"
OUT="${1:-$ROOT/build}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
ZIP="$OUT/consent-app-deploy.zip"

die() { echo "build-package: ERROR: $*" >&2; exit 1; }
for c in node npm git zip; do command -v "$c" >/dev/null 2>&1 || die "falta '$c'"; done
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; elif command -v shasum >/dev/null 2>&1; then SHA="shasum -a 256"; else die "falta sha256sum/shasum"; fi
case "$("$(command -v node)" -p 'process.versions.node')" in 24.*) ;; *) die "se requiere Node 24" ;; esac

echo "== 1/6 npm ci --ignore-scripts (con devDependencies, solo para construir el frontend)"
npm ci --ignore-scripts >/dev/null
echo "== 2/6 npm run build:frontend"
npm run build:frontend >/dev/null
[ -f dist/index.html ] || die "dist/index.html no se genero"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/consent-deploy-stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

echo "== 3/6 copia de archivos versionados"
copy_tracked() { # $@ = pathspecs de git; copia preservando la ruta relativa
  git ls-files -z -- "$@" | while IFS= read -r -d '' f; do
    mkdir -p "$STAGE/$(dirname "$f")"; cp -p "$f" "$STAGE/$f"
  done
}
copy_tracked package.json package-lock.json
# src/ sin tests (si algun dia hay *.test.ts dentro de src/, no viajan). Node ejecuta los .ts directamente (type-stripping).
git ls-files -z -- src | while IFS= read -r -d '' f; do
  case "$f" in *.test.ts|*.spec.ts) continue ;; esac
  mkdir -p "$STAGE/$(dirname "$f")"; cp -p "$f" "$STAGE/$f"
done
# Migraciones (todas: el runner exige el conjunto completo). db/ceremonies/ NO viaja: son ceremonias de break-glass posteriores a 0086 (DDL del ledger,
# alta de principals); una instalacion nueva no las necesita (db/ceremonies/README.md; el deploy solo exige que no haya una ceremonia abierta).
copy_tracked db/migrations
# Semillas SINTETICAS del perfil LOCAL (catalogo de colegio de prueba y principals PLATFORM sinteticos). Opcionales; migrate.ts --phase fixtures.
copy_tracked db/fixtures/local
# Lo unico que el servidor lee en runtime fuera de src/ y dist/: el CSS del design system (static-assets.ts) y nada de contracts/, specs/ ni docs/.
copy_tracked design-system/index.css design-system/css/tokens.css design-system/css/layouts.css design-system/css/components.css design-system/css/patterns.css
copy_tracked infra/systemd infra/nginx
# Herramientas de despliegue (menos este script: se corre en el repo, no en el servidor).
git ls-files -z -- tools/deploy | while IFS= read -r -d '' f; do
  case "$f" in tools/deploy/build-package.sh|tools/deploy/README-DEPLOY.md) continue ;; esac
  mkdir -p "$STAGE/$(dirname "$f")"; cp -p "$f" "$STAGE/$f"
done
cp -p tools/deploy/.env.example "$STAGE/.env.example"
cp -p tools/deploy/README-DEPLOY.md "$STAGE/README-DEPLOY.md"
# dist/ (build de Vite; sin el directorio oculto .vite/manifest.json)
mkdir -p "$STAGE/dist"
(cd dist && find . -type f ! -path './.vite/*' -print0 | while IFS= read -r -d '' f; do mkdir -p "$STAGE/dist/$(dirname "$f")"; cp -p "$f" "$STAGE/dist/$f"; done)

echo "== 4/6 VERSION y CHECKSUMS"
COMMIT="$(git rev-parse --short=12 HEAD)"
DIRTY=""; [ -z "$(git status --porcelain --untracked-files=no)" ] || DIRTY="-dirty"
{
  echo "commit=${COMMIT}${DIRTY}"
  echo "branch=$(git rev-parse --abbrev-ref HEAD)"
  echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "mode=synthetic (CNS_ENVIRONMENT=LOCAL, CNS_DB_ROLE_MODE=IT0B_SYNTHETIC, solo datos sinteticos)"
  echo "node_required=$(node -p "require('./package.json').engines.node")"
  echo "ui_modes=spa,ssr"
} > "$STAGE/VERSION"
chmod +x "$STAGE"/tools/deploy/*.sh
# Bloqueos de contenido ANTES de firmar: nada de entornos reales, secretos, temporales ni dependencias.
BAD="$(cd "$STAGE" && find . \( -name '.env' -o -name '.env.*' -o -name 'node_modules' -o -name '.git' -o -name '.DS_Store' -o -name '*.log' -o -name '*.pem' -o -name '*.key' -o -name 'evidence' -o -name 'tests' -o -name 'e2e' -o -name 'frontend' -o -name '.claude' -o -name 'stitch' -o -name 'docs' -o -name '.github' \) ! -name '.env.example' -print)"
[ -z "$BAD" ] || die "el paquete contiene rutas prohibidas: $BAD"
(cd "$STAGE" && find . -type f ! -name CHECKSUMS.sha256 -print0 | LC_ALL=C sort -z | xargs -0 $SHA | sed 's#  \./#  #') > "$STAGE/CHECKSUMS.sha256"

echo "== 5/6 zip"
rm -f "$ZIP"
(cd "$STAGE" && find . -type f -print | sed 's#^\./##' | LC_ALL=C sort | zip -X -q "$ZIP" -@)

echo "== 6/6 verificacion del zip"
LIST="$(unzip -Z1 "$ZIP")"
for must in package.json package-lock.json VERSION CHECKSUMS.sha256 .env.example README-DEPLOY.md dist/index.html db/migrations/0000_roles.sql src/server/entrypoints/web/main.ts tools/deploy/install.sh tools/deploy/migrate.ts tools/deploy/verify.sh infra/systemd/consent-web.service infra/nginx/consent.lectorpro.cl.conf.example design-system/index.css; do
  echo "$LIST" | grep -qx "$must" || die "falta $must en el zip"
done
echo "$LIST" | grep -E '(^|/)(node_modules|tests|evidence|frontend|docs|\.git|\.claude)/|\.test\.ts$|(^|/)\.env($|\.)' | grep -v '^\.env\.example$' && die "el zip contiene rutas prohibidas (arriba)"
echo "OK  $ZIP  ($(echo "$LIST" | wc -l | tr -d ' ') archivos, $(du -h "$ZIP" | cut -f1)) commit=${COMMIT}${DIRTY}"
