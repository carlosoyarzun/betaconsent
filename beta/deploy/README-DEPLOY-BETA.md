# Despliegue de consent-beta en un VPS (H1-12)

> **SOLO DATOS SINTÉTICOS Y DESTINATARIOS DE PRUEBA.** El único modo soportado en H1 es `CNS_ENVIRONMENT=LOCAL` con catálogo `SYNTHETIC`
> (la allowlist `CNS_MAIL_ALLOWLIST` limita los envíos). El paso a REAL es H2-08. Sin nftables ni backups (H2). Gobierna: DEC "Reconstrucción mínima" (2026-10-19), decisión 3.

Ubuntu 24.04 LTS, 1 vCPU / 2 GB. Todo como root salvo donde se indica. `PKG` = zip generado con `beta/deploy/build-package.sh` (en tu máquina: `build/consent-beta-deploy.zip`).

1. **DNS** (en tu proveedor): registro A `consent.lectorpro.cl` -> IP pública del VPS. Abre 22, 80 y 443 en el firewall del proveedor. Comprueba: `dig +short consent.lectorpro.cl`.
2. **Paquetes base**: `apt-get update && apt-get install -y unzip curl gnupg openssl debian-keyring debian-archive-keyring apt-transport-https ca-certificates`.
3. **Node 24.21.0** (binario oficial en `/usr/local`):
   `curl -fsSLO https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-x64.tar.xz && tar -xJf node-v24.21.0-linux-x64.tar.xz -C /usr/local --strip-components=1 --no-same-owner && node -v` (debe decir v24.21.0; en ARM usa `linux-arm64`). Alternativa: NodeSource fijando esa versión, con `node` en `/usr/local/bin` (enlace simbólico).
4. **PostgreSQL 16 (PGDG)**: `install -d /usr/share/postgresql-common/pgdg && curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main" > /etc/apt/sources.list.d/pgdg.list && apt-get update && apt-get install -y postgresql-16`
   Verifica UTF8: `sudo -u postgres psql -Atc "SHOW server_encoding"` (debe decir UTF8).
5. **Caddy (repositorio oficial)**: `curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list && apt-get update && apt-get install -y caddy`
6. **Subir y desempaquetar el paquete** (desde tu máquina: `scp build/consent-beta-deploy.zip root@IP:/root/`): `unzip -q /root/consent-beta-deploy.zip -d /root/pkg`. Comprueba: `cat /root/pkg/VERSION`.
7. **Instalar** (crea usuario `consent`, `/opt/consent-beta`, `/etc/consent-beta`, unidad y Caddyfile; no pisa un `consent.env` existente): `/root/pkg/beta/deploy/install.sh`. La primera vez avisa de los `CHANGE_ME` y no arranca el servicio.
8. **Roles y base** (contraseñas generadas; se guardan solo en `consent.env`):
   `for r in MIG APP MAIL; do export ${r}_PW="$(openssl rand -base64 32 | tr -d '/+=\n')"; done` (sin símbolos para no codificar las URL).
   `cd /opt/consent-beta/beta && sudo -u postgres psql -v dbname=consent -v migrator_password="$MIG_PW" -v app_password="$APP_PW" -v mailer_password="$MAIL_PW" -f db/bootstrap-roles.sql`
9. **`.env`**: `nano /etc/consent-beta/consent.env` (root:consent 0640; comentarios por variable en `env.example`). Pon las 3 contraseñas del paso 8 (`echo $MIG_PW $APP_PW $MAIL_PW`), `CNS_SESSION_SECRET` y la clave en `CNS_API_KEYS` con `openssl rand -base64 32`, tu `CNS_SMTP_URL`/`CNS_SMTP_FROM` y `CNS_MAIL_ALLOWLIST` con tus buzones de prueba. Deja `CNS_ENVIRONMENT=LOCAL`, `PORT=3000`, `BIND=127.0.0.1`.
10. **Migraciones**: `set -a; . /etc/consent-beta/consent.env; set +a; cd /opt/consent-beta/beta && node src/db/migrate-cli.ts` (usa `CNS_MIGRATOR_DATABASE_URL`; imprime `aplicadas: N`). Repetible.
11. **Arrancar**: `systemctl restart consent-beta`. Caddy obtiene el certificado Let's Encrypt solo (necesita DNS del paso 1 y puertos 80/443): `systemctl status caddy --no-pager`.
12. **Verificar**: `/opt/consent-beta/beta/deploy/verify.sh` y `curl -i https://consent.lectorpro.cl/healthz` (200). `verify.sh` comprueba unidad activa, `/healthz` local y HTTPS, y la línea `servidor escuchando` del journal (se escribe después de `assertEnvironment` y `assertPoolRoles`; si fallan aparece `ARRANQUE ABORTADO`).
13. **Prueba con el CSV de ejemplo** (`/opt/consent-beta/beta/examples/`, si el paquete lo trae) y tu allowlist: importa por la API con una de tus claves (`CNS_API_KEYS`, forma `keyId:secreto`; el contrato de la API y del CLI de importación está en `beta/README.md`/`beta/examples/`) usando solo filas sintéticas cuyo correo de apoderado esté en `CNS_MAIL_ALLOWLIST`; abre el correo recibido y recorre el enlace `/i/<token>` por HTTPS.
14. **Logs**: app `journalctl -u consent-beta -f` (JSON, rutas normalizadas, sin query ni PII); Caddy `journalctl -u caddy -f` y `/var/log/caddy/consent-access.log` (sin URI, cookies ni Authorization; las rutas `/i/* /m/* /r/*` llevan secretos y no se registran).

**Actualizar**: genera un zip nuevo, repite los pasos 6 y 7 y, si hay migraciones nuevas, el 10; `install.sh` conserva `consent.env`.
**Notas**: la unidad no lleva `IPAddressDeny` (necesita SMTP saliente; el cierre de egress es H2). `systemd-analyze verify` no se pudo ejecutar al preparar el paquete (macOS): corre `systemd-analyze verify /etc/systemd/system/consent-beta.service` en el VPS.
Rollback simple: `systemctl stop consent-beta`; el esquema no se revierte (migraciones hacia adelante).
