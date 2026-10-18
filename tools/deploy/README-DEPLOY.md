# Consent App - instalación manual (modo sintético)

> **AVISO.** Requiere un VPS/servidor propio con **Node 24, PostgreSQL >= 16 (UTF8), nginx y systemd**, con acceso root.
> **No sirve para hosting compartido** (cPanel, etc.). Solo **datos sintéticos**: no cargue datos personales reales.

## 1. Requisitos
- Linux con systemd (probado en diseño para Debian/Ubuntu), acceso root, dominio `consent.lectorpro.cl` apuntando al servidor (DNS lo hace Carlos).
- Node **24.21.0** en `/usr/bin` o `/usr/local/bin` (las units usan `ProtectHome`; no sirve Node bajo `/home`). `npm`, `openssl`, `curl`, `unzip`.
- PostgreSQL >= 16 en el mismo servidor, cluster con codificación UTF8, superusuario `postgres` accesible por socket Unix (`sudo -u postgres psql`).
- nginx y certbot (`apt install nginx certbot`).

## 2. Subir y descomprimir en /opt/consent-app
```
sudo mkdir -p /opt/consent-app && sudo unzip consent-app-deploy.zip -d /opt/consent-app
cd /opt/consent-app && sha256sum -c CHECKSUMS.sha256 --quiet && cat VERSION
```
Debe quedar en `/opt/consent-app` (las units systemd usan esa ruta).

## 3. Dependencias de producción
```
cd /opt/consent-app && sudo npm ci --omit=dev --ignore-scripts
```
No hay paso de build: Node ejecuta los `.ts` directamente y `dist/` (interfaz React) viene precompilado.

## 4. install.sh
```
sudo tools/deploy/install.sh --dry-run        # muestra el plan; no escribe nada
sudo tools/deploy/install.sh                  # opciones: --origin https://consent.lectorpro.cl --ui-mode spa|ssr --db-name consent
```
Crea: un usuario de sistema por proceso (`consent-web`, `consent-worker`, ...), `/etc/consent/roles.env` (contraseñas de los 7 roles de Postgres y 5 secretos
aleatorios), `/etc/consent/{web,worker,platform,reconciler,chain-verifier}.env` desde `.env.example`, las units/timers en `/etc/systemd/system` y los habilita
sin arrancarlos. Los secretos quedan **solo** en `/etc/consent/*.env` (root:root, 0600) y **nunca se imprimen**. Reejecutarlo no sobrescribe nada
(`--regenerate-env` reescribe los env; ojo: invalida sesiones y OTP). `consent-platform` y `consent-verifier` no se habilitan (ver sección 12).

## 5. Migraciones
```
sudo tools/deploy/migrate.sh --phase all --dry-run
sudo tools/deploy/migrate.sh --phase all
```
`migrate.sh` carga `roles.env`, usa el usuario `postgres` y ejecuta `node tools/deploy/migrate.ts --phase ...`. `all` = `cluster` (roles) -> `database` (0000..0086) ->
`cluster-post` -> `local-grants`. La fase **`local-grants`** concede `EXECUTE` de las siembras `seed_local_*` a `app_rw` y **solo vale en modo sintético**: se niega con error si
`ops.db_catalog` no es exactamente una fila LOCAL/SYNTHETIC. Es idempotente; se puede repetir.

## 6. Seeds sintéticos (opcional)
```
sudo tools/deploy/migrate.sh --phase fixtures
```
Carga el catálogo de colegio de prueba y principals PLATFORM sintéticos (`db/fixtures/local`). Solo perfil LOCAL.

## 7. nginx + TLS (certbot)
```
sudo cp infra/nginx/consent-proxy.conf.example /etc/nginx/snippets/consent-proxy.conf     # ajuste la ruta del include si cambia
sudo cp infra/nginx/consent.lectorpro.cl.conf.example /etc/nginx/sites-available/consent.lectorpro.cl.conf
sudo ln -s ../sites-available/consent.lectorpro.cl.conf /etc/nginx/sites-enabled/
```
Siga los 4 pasos de certbot del encabezado del archivo (primero solo el bloque :80, luego `certbot certonly --webroot`, luego el bloque :443) y `nginx -t && systemctl reload nginx`.
`CNS_ALLOWED_ORIGIN` ya queda en `https://consent.lectorpro.cl` (sin barra final) en `/etc/consent/web.env`; debe coincidir con el dominio público (cookies `__Host-*` Secure).
`/platform/` y `/__dev/*` no se publican.

## 8. Arranque
```
sudo systemctl start consent-web consent-worker
sudo systemctl start consent-reconciler.timer consent-chain-verifier.timer consent-breakglass-watch.timer
```
`CNS_UI_MODE=spa` (por defecto) sirve `dist/`; `ssr` (HTML del servidor) es la alternativa: edite `/etc/consent/web.env` y `systemctl restart consent-web`.

## 9. verify.sh
```
sudo tools/deploy/verify.sh --public https://consent.lectorpro.cl
```
Comprueba services/timers, `/healthz`, migraciones, catálogo LOCAL/SYNTHETIC, modo 0600 de los env y secretos presentes. `--no-systemd` omite systemd. Sale 0 si todo OK.

## 10. Logs
`journalctl -u consent-web -n 100 -f` (también `consent-worker`, `consent-reconciler`, `consent-chain-verifier`, `consent-breakglass-watch`). nginx: `/var/log/nginx/`.
Las alertas de los timers van a `logger` (syslog). No se registra PII.

## 11. Actualizar y desinstalar
- **Actualizar:** descomprima el zip nuevo sobre `/opt/consent-app` (o en un directorio nuevo y reemplace), `npm ci --omit=dev --ignore-scripts`, `install.sh` (conserva env),
  `migrate.sh --phase all`, `systemctl restart consent-web consent-worker`, `verify.sh`. Las migraciones aplicadas nunca se editan; solo se añaden nuevas.
- **Desinstalar:** `systemctl disable --now` de las units/timers y borrar `/etc/systemd/system/consent-*`, `systemctl daemon-reload`; borrar `/opt/consent-app` y `/etc/consent`;
  `userdel consent-*`; borrar base y roles (`DROP DATABASE consent;` y los roles del cluster) con `psql` como `postgres`. Quite el sitio de nginx.

## 12. Modo sintético: qué significa y qué falta para datos reales
- Perfil `CNS_ENVIRONMENT=LOCAL`, catálogo LOCAL/SYNTHETIC: es el **único modo soportado**; la app aborta con otro perfil. No hay producción ni datos reales (DEC-BR-014).
- Falta el **IdP real** (APR-IDP, parámetros PENDING): hoy el verifier usa un IdP sintético y `consent-platform`/`consent-verifier` no se habilitan.
- Falta el **correo saliente**: OTP y enlaces salen por sinks en memoria (SMTP externo prohibido sin nueva decisión de Carlos).
- Falta el perfil **IT0B/REAL**: STAGING/producción, egress proxy (P-45), SecretStore, PIA y enmienda de DEC-BR-014.
- Falta terminar la **migración de la UI** a React (algunas páginas siguen en HTML de servidor; `CNS_UI_MODE=ssr` como alternativa).
- Faltan las **decisiones legales** (DEC-BR-003, copy legal, LEGAL DECISION pendientes) antes de cualquier dato personal real.
