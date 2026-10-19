#!/usr/bin/env bash
# Gobierna: plan v2 H1-12. Verifica unidad activa, /healthz local y por HTTPS, y que el arranque pasó los gates.
# assertPoolRoles no escribe su propia línea: main.ts registra "servidor escuchando" DESPUÉS de assertEnvironment + assertPoolRoles; su presencia
# tras el último arranque prueba que pasó (si falla, el journal tiene "ARRANQUE ABORTADO").
set -uo pipefail
HOST="${1:-consent.lectorpro.cl}"; PORT="${PORT:-3000}"; fail=0
ok() { echo "OK   $*"; }; ko() { echo "FALLA $*"; fail=1; }
systemctl is-active --quiet consent-beta && ok "unidad consent-beta activa" || ko "unidad consent-beta no activa"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz")" = 200 ] && ok "healthz local 200" || ko "healthz local"
[ "$(curl -s -o /dev/null -w '%{http_code}' "https://$HOST/healthz")" = 200 ] && ok "healthz https://$HOST 200" || ko "healthz HTTPS (DNS/Caddy/certificado)"
SINCE="$(systemctl show -p ActiveEnterTimestamp --value consent-beta)"
J="$(journalctl -u consent-beta --since "${SINCE:-1 hour ago}" --no-pager 2>/dev/null)"
echo "$J" | grep -q 'ARRANQUE ABORTADO' && ko "journal: ARRANQUE ABORTADO (roles/entorno/config)"
echo "$J" | grep -q 'servidor escuchando' && ok "journal: 'servidor escuchando' (assertEnvironment y assertPoolRoles pasaron)" || ko "journal: sin 'servidor escuchando'"
exit $fail
