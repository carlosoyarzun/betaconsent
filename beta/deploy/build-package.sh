#!/usr/bin/env bash
# Gobierna: plan v2 H1-12. Uso (desde la raíz del repo): beta/deploy/build-package.sh  -> build/consent-beta-deploy.zip
# Solo escribe en build/ (ignorado por git), salvo node_modules/ y dist/ de beta/ (también ignorados). Reproducible: orden y mtimes fijos.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
OUT="$ROOT/build"; STAGE="$OUT/stage"; ZIP="$OUT/consent-beta-deploy.zip"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

(cd beta && npm ci --ignore-scripts && npm run build:frontend)
test -f beta/dist/.vite/manifest.json || { echo "falta beta/dist/.vite/manifest.json" >&2; exit 1; }

rm -rf "$STAGE" "$ZIP"; mkdir -p "$STAGE/beta"
for f in package.json package-lock.json README.md; do cp "beta/$f" "$STAGE/beta/$f"; done
for d in src db dist deploy examples; do
  if [ -d "beta/$d" ]; then cp -R "beta/$d" "$STAGE/beta/$d"; else echo "AVISO: beta/$d no existe; se omite" >&2; fi
done
(cd "$STAGE/beta" && npm ci --omit=dev --ignore-scripts)

COMMIT="$(git rev-parse HEAD)"; DIRTY=""; [ -z "$(git status --porcelain -- beta)" ] || DIRTY="-dirty"
CDATE="$(git show -s --format=%cI HEAD)"
printf 'commit=%s%s\ncommit_date=%s\nmode=SYNTHETIC (CNS_ENVIRONMENT=LOCAL; solo datos sinteticos, H1)\nnode=24.21.0\n' "$COMMIT" "$DIRTY" "$CDATE" > "$STAGE/VERSION"

# mtimes fijos (reproducibilidad) y checksums en orden estable
find "$STAGE" -exec touch -t 202001010000 {} +
(cd "$STAGE" && find . -type f ! -name CHECKSUMS.sha256 | LC_ALL=C sort | while read -r f; do sha "$f"; done > CHECKSUMS.sha256)
touch -t 202001010000 "$STAGE/CHECKSUMS.sha256"
(cd "$STAGE" && { echo VERSION; echo CHECKSUMS.sha256; find beta | LC_ALL=C sort; } | zip -X -q "$ZIP" -@)

# Verificación del zip
LIST="$(unzip -Z1 "$ZIP")"
for need in VERSION CHECKSUMS.sha256 beta/dist/.vite/manifest.json beta/dist/index.html beta/src/server/main.ts beta/db/bootstrap-roles.sql \
  beta/deploy/install.sh beta/deploy/verify.sh beta/deploy/consent-beta.service beta/deploy/Caddyfile beta/deploy/env.example node_modules; do
  case "$need" in node_modules) echo "$LIST" | grep -q '^beta/node_modules/pg/' || { echo "falta beta/node_modules/pg" >&2; exit 1; } ;;
    *) echo "$LIST" | grep -qx "$need" || { echo "falta en el zip: $need" >&2; exit 1; } ;; esac
done
echo "$LIST" | grep -qE '(^|/)\.env$|\.git/' && { echo "el zip contiene .env o .git" >&2; exit 1; }
echo "$LIST" | grep -v '^beta/node_modules/' | grep -v '^beta/dist/assets/' | sed 's/^/  /'
echo "OK: $ZIP ($(echo "$LIST" | wc -l | tr -d ' ') entradas); sha256 del zip:"; sha "$ZIP"
