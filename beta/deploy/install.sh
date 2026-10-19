#!/usr/bin/env bash
# Gobierna: plan v2 H1-12. Lo ejecuta Carlos COMO ROOT en el VPS, desde el paquete descomprimido:
#   unzip -q consent-beta-deploy.zip -d /root/pkg && /root/pkg/beta/deploy/install.sh
# Idempotente: se puede repetir (actualiza código, conserva /etc/consent-beta/consent.env).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "ejecutar como root" >&2; exit 1; }
PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP=/opt/consent-beta; ETC=/etc/consent-beta; ENVF="$ETC/consent.env"
[ -f "$PKG/CHECKSUMS.sha256" ] && (cd "$PKG" && sha256sum --quiet -c CHECKSUMS.sha256) || { echo "paquete sin CHECKSUMS válidos" >&2; exit 1; }
[ -x /usr/local/bin/node ] || { echo "falta /usr/local/bin/node (Node 24.21.0)" >&2; exit 1; }
command -v caddy >/dev/null || { echo "falta caddy" >&2; exit 1; }

id consent >/dev/null 2>&1 || useradd --system --home-dir "$APP" --shell /usr/sbin/nologin consent
install -d -m 0755 -o root -g root "$APP"
install -d -m 0750 -o root -g consent "$ETC"
# Código propiedad de root (solo lectura para el servicio)
rm -rf "$APP/beta.new"; cp -a "$PKG/beta" "$APP/beta.new"
rm -rf "$APP/beta.old"; [ ! -d "$APP/beta" ] || mv "$APP/beta" "$APP/beta.old"
mv "$APP/beta.new" "$APP/beta"; rm -rf "$APP/beta.old"
cp "$PKG/VERSION" "$APP/VERSION"; chown -R root:root "$APP"; chmod -R go-w "$APP"

NEWENV=0
if [ ! -e "$ENVF" ]; then install -m 0640 -o root -g consent "$PKG/beta/deploy/env.example" "$ENVF"; NEWENV=1; fi

install -m 0644 "$PKG/beta/deploy/consent-beta.service" /etc/systemd/system/consent-beta.service
CF=/etc/caddy/Caddyfile
if ! grep -q 'consent.lectorpro.cl' "$CF" 2>/dev/null; then
  [ ! -e "$CF" ] || cp -a "$CF" "$CF.bak-$(date +%Y%m%d%H%M%S)"
  install -m 0644 "$PKG/beta/deploy/Caddyfile" "$CF"
fi
install -d -o caddy -g caddy /var/log/caddy 2>/dev/null || true
caddy validate --config "$CF" --adapter caddyfile
systemctl daemon-reload
systemctl enable caddy consent-beta >/dev/null 2>&1 || true
systemctl reload caddy 2>/dev/null || systemctl restart caddy

if [ "$NEWENV" -eq 1 ] || grep -q 'CHANGE_ME' "$ENVF"; then
  echo "AVISO: $ENVF tiene valores CHANGE_ME. Edítalo (README-DEPLOY-BETA.md paso 7), corre las migraciones (paso 6) y luego:"
  echo "  systemctl restart consent-beta && $APP/beta/deploy/verify.sh"
  exit 0
fi
systemctl enable consent-beta >/dev/null
systemctl restart consent-beta
echo "Instalado $(head -1 "$APP/VERSION"). Ejecuta: $APP/beta/deploy/verify.sh"
