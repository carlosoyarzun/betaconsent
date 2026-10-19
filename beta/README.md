# consent-beta (reconstrucción mínima, 1 colegio)

Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19) y el plan v2
(H1-01 esqueleto, H1-02 esquema + roles). Carpeta autocontenida: no importa nada de `src/`, `db/` ni `frontend/`;
lo reutilizado se copió con cabecera `// origen: <ruta>@9345b78`. Solo datos sintéticos hasta el Hito 2.

Node 24 con type-stripping (`node src/...ts`, sin build). Dependencias de producción: `pg` y `nodemailer` (solo en `src/mail/smtp-mailer.ts`).

## Correr en local (Postgres temporal, fuera del repo)
```
cd beta && npm ci
eval "$(scripts/pg-temp.sh start)"    # clúster efímero + TEST_DATABASE_URL y PSQL (nunca el Postgres de uso diario)
npm run ci                            # typecheck + unit + integration
scripts/pg-temp.sh stop "$PG_TEMP_DIR"
```
Para una base propia: un superusuario ejecuta una vez
`psql "$SUPER_URL" -v dbname=consent -v migrator_password=... -v app_password=... -f db/bootstrap-roles.sql`
y luego `CNS_MIGRATOR_DATABASE_URL=postgresql://consent_migrator:...@host/consent npm run migrate`.

## Roles
`consent_owner` (NOLOGIN, dueño de todo) · `consent_migrator` (SET ROLE en migraciones) · `consent_app` (proceso web y CLI; sin UPDATE/DELETE/TRUNCATE
sobre el ledger ni sobre OTP/decisión; las transiciones serán funciones SECURITY DEFINER, H1-03).

## Variables (`loadConfig`, todas obligatorias; si falta una el proceso aborta)
`CNS_ENVIRONMENT` (LOCAL|REAL; debe coincidir con `ops.db_catalog`), `CNS_DATABASE_URL`, `CNS_SESSION_SECRET`, `CNS_OTP_SECRET`
(base64 >= 32 bytes, distintos), `CNS_PUBLIC_ORIGIN`, `CNS_SMTP_URL`, `CNS_SMTP_FROM`, `CNS_MAIL_ALLOWLIST` (correos o @dominios),
`CNS_API_KEYS` (`keyId:secretoBase64[,keyId2:...]`), `PORT`, `BIND`. Migraciones: `CNS_MIGRATOR_DATABASE_URL`. Tests: `TEST_DATABASE_URL`.

## Correo (H1-06)
Puerto `Mailer` (`src/mail/mailer.port.ts`) con `SmtpMailer` (nodemailer; TLS obligatorio: `smtps://`/465 => `secure`, otro puerto => `requireTLS`; nunca `rejectUnauthorized:false`;
SMTP sin TLS solo a loopback y solo con `CNS_ENVIRONMENT=LOCAL`) y `MemoryMailer` (tests). Con `ops.db_catalog.data_class = SYNTHETIC` solo se envía a `CNS_MAIL_ALLOWLIST`;
el resto no se envía (`email_outbox` queda `FAILED` + `last_error_code='SUPPRESSED_ALLOWLIST'` hasta que H1-03 admita el estado `SUPPRESSED`). Con REAL la allowlist se ignora.
Outbox en proceso (`startOutboxWorker`, `setInterval`): claim con `FOR UPDATE SKIP LOCKED`, 3 intentos con backoff 30 s / 120 s y luego `FAILED`; SENT solo tras la respuesta del proveedor.
Garantía al-menos-una-vez: si el proceso muere entre el envío y la marca SENT, la fila queda `SENDING` y se reenvía al vencer el lease (5 min); ese duplicado se acepta.
El OTP va por `sendOtpNow` (síncrono, sin outbox, sin persistencia ni log). Todo el copy de `src/mail/templates/` es BORRADOR (copy legal = LEGAL DECISION de Carlos).
Test con Mailpit: `docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit` y `MAILPIT_SMTP_URL=smtp://localhost:1025 MAILPIT_API_URL=http://localhost:8025 npm run test:integration` (sin esas variables se salta).
