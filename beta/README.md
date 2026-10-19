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
`psql "$SUPER_URL" -v dbname=consent -v migrator_password=... -v app_password=... -v mailer_password=... -f db/bootstrap-roles.sql`
y luego `CNS_MIGRATOR_DATABASE_URL=postgresql://consent_migrator:...@host/consent npm run migrate`.

## Roles (4)
- `consent_owner` (NOLOGIN): dueño de la base y de todos los objetos y funciones SECURITY DEFINER.
- `consent_migrator` (LOGIN, NOINHERIT): hace `SET ROLE consent_owner` en cada migración; no hereda privilegios.
- `consent_app` (LOGIN, pool HTTP de 10 conexiones, `CNS_DATABASE_URL`): atiende las peticiones. EXECUTE de `import_invitation`, `open_invitation`, `verify_otp`, `record_decision`,
  `revoke_decision`, `authorization_status`, y (0004) `open_manage_link`, `cancel_invitation`, `enqueue_invitation_email`. SELECT por columnas **sin** `token_hash`, `code_hash` ni `decision_maker_ref`;
  **sin INSERT ni UPDATE del outbox** (0004; antes podía insertar y forzar rotaciones/reenvíos con `payload.reissueReason`) y sin acceso a `app.manage_link`. **No puede emitir secretos.**
- `consent_mailer` (LOGIN, NOBYPASSRLS, sin DDL, sin membresías; pool de 2 conexiones, `CNS_MAILER_DATABASE_URL`): ÚNICO con EXECUTE de `issue_otp`, `arm_invitation_token` y (0004) `issue_manage_link`
  y `request_invitation_resend` (reenvío de operador con motivo); lee `invitation(invitation_ref, student_first_name, guardian_email)` y el outbox (SELECT + UPDATE de las marcas). Nada de
  `verify_otp`/`record_decision`/`revoke_decision`/`open_manage_link`/`cancel_invitation`, ni `token_hash`/`code_hash`, ni `consent_decision`.

## Arranque (`src/server/main.ts`, un proceso, dos pools)
`createPools({appUrl, mailerUrl})` -> `assertEnvironment` + `assertPoolRoles` (aborta antes de escuchar si algún pool no conecta con su rol) -> `createPgPorts(new PgUnitOfWork(app), {mailerUow: new PgUnitOfWork(mailer)})`
-> `startOutboxWorker({db: pools.mailer})`. OTP: `issue` por el puerto (pool mailer) -> `readGuardianEmail(pools.mailer, invitationRef)` -> `sendOtpNow`. Para OTP de gestión/revocación el handler obtiene el
`invitationRef` de la decisión; el seudónimo del canal (`deriveDecisionMakerRef`) se calcula en el servidor y se pasa a `verify` (consent_app no lee `decision_maker_ref`).

## Enlace de gestión con estado (0004)
`/m/<token>` ya no es un token firmado sin estado: es un secreto en `app.manage_link` (solo `sha256`, 7 días P-10, `UNIQUE(token_hash)`, RLS). `record_decision` (GRANTED) encola en la MISMA transacción una fila
`RECOVERY_LINK` sin token; el worker (pool mailer) llama `issue_manage_link(consent_id)` (devuelve el token una vez; invalida los anteriores vigentes; ledger `MANAGE_LINK_ISSUED` sin token) y envía `/m/<token>`.
`GET /m/<token>` es un 303 uniforme sin leer la base (F-RB-02); `/manage` y `/manage/page-state` canjean contra `open_manage_link(hash)` (no consume). `revoke_decision` marca `consumed_at`; el enlace consumido
solo sigue resolviendo para mostrar "ya revocado". Reemitir invalida el enlace anterior (también para una sesión ya abierta: se revalida al pedir/confirmar la revocación).
`POST /decision/subject-mismatch` -> `cancel_invitation(ref, 'SUBJECT_MISMATCH_REPORTED')` (OPENED|VERIFIED -> CANCELLED, `INVITATION_CANCELLED` con `reasonCode`, sin texto libre; libera la invitación viva del estudiante).
Desviación: no se liga con el `decisionMakerRef` de la sesión (GRD-IV-10 del contrato) porque consent_app no lo lee; la sesión HTTP sí exige OTP verificado.

## Outbox sin escritura de la app (0004, P2 de la verificación PR #121)
Recibos y enlace de gestión se encolan dentro de `record_decision`/`revoke_decision` (payload completo: versión, fecha, finalidades, `receiptRef`; consent_mailer no lee `consent_decision`);
la primera invitación con `enqueue_invitation_email(ref, version)` (consent_app, una fila por invitación, sin motivo); el reenvío de operador con `request_invitation_resend(ref, motivo)` (pool mailer, H1-09).
El worker solo rota un token de invitación vigente por `OUTBOX_RETRY` o por un motivo escrito por esas funciones: ya no hay ruta SQL de consent_app que lo fuerce.

Por qué dos roles de runtime en el mismo proceso Node (SEC-CNS-024-V1, P0): `issue_otp` devuelve el código en claro; si lo ejecutara el mismo rol que ejecuta `verify_otp` y `record_decision`, una SOLA
sentencia SQL inyectada en el pool de la app (`issue_otp -> verify_otp -> record_decision`) fabricaría un GRANTED (o un REVOKED) sin acceso al correo del apoderado. Con la separación, una SQLi en el
pool de la app ya no obtiene el código ni el token. Mitiga RES-OTP-WEB-PRB frente a SQLi en el pool de la app; residual: RCE del proceso único (tiene las dos credenciales), F-RB-03, aceptado por Carlos.
Ambos roles se verifican al arrancar por pool (`assertPoolRoles`: `assertRuntimeRole(db, expectedRole)`). `createPgPorts(uow, { mailerUow })` enruta `OtpRepo.issue/resend` y `InvitationRepo.armToken` al pool del mailer.
`arm_invitation_token` acota la vigencia a 7 días (P-10) y solo rota un token vigente con un motivo explícito (`INVITATION_LINK_REISSUED` en el ledger).

## Variables (`loadConfig`, todas obligatorias; si falta una el proceso aborta)
`CNS_ENVIRONMENT` (LOCAL|REAL; debe coincidir con `ops.db_catalog`), `CNS_DATABASE_URL`, `CNS_MAILER_DATABASE_URL` (otro rol), `CNS_SESSION_SECRET`
(base64 >= 32 bytes), `CNS_PUBLIC_ORIGIN`, `CNS_SMTP_URL`, `CNS_SMTP_FROM`, `CNS_MAIL_ALLOWLIST` (correos o @dominios),
`CNS_API_KEYS` (`keyId:secretoBase64[,keyId2:...]`), `PORT`, `BIND`. Migraciones: `CNS_MIGRATOR_DATABASE_URL`. Tests: `TEST_DATABASE_URL`.

## Correo (H1-06)
Puerto `Mailer` (`src/mail/mailer.port.ts`) con `SmtpMailer` (nodemailer; TLS obligatorio: `smtps://`/465 => `secure`, otro puerto => `requireTLS`; nunca `rejectUnauthorized:false`;
SMTP sin TLS solo a loopback y solo con `CNS_ENVIRONMENT=LOCAL`) y `MemoryMailer` (tests). Con `ops.db_catalog.data_class = SYNTHETIC` solo se envía a `CNS_MAIL_ALLOWLIST`;
el resto no se envía (`email_outbox` queda `SUPPRESSED` + `last_error_code='SUPPRESSED_ALLOWLIST'`). Con REAL la allowlist se ignora.
Outbox en proceso (`startOutboxWorker`, `setInterval`): claim con `FOR UPDATE SKIP LOCKED`, 3 intentos con backoff 30 s / 120 s y luego `FAILED`; SENT solo tras la respuesta del proveedor.
Garantía al-menos-una-vez: si el proceso muere entre el envío y la marca SENT, la fila queda `SENDING` y se reenvía al vencer el lease (5 min); ese duplicado se acepta.
La invitación NO guarda el token en el outbox (ni el enlace de gestión): al reclamar la fila el worker genera el token, llama a `arm_invitation_token(hash)` y envía `/i/<token>` (si ya no es armable, la fila queda `FAILED` con `INVITATION_NOT_ARMABLE`).
El OTP lo genera `issue_otp` en la base con el pool del mailer (se devuelve en claro una sola vez) y va por `sendOtpNow`; el destinatario se lee con `readGuardianEmail` sobre ese mismo pool. El worker del outbox (`deps.db`) usa el pool del mailer (síncrono, sin outbox, sin persistencia ni log). Todo el copy de `src/mail/templates/` es BORRADOR (copy legal = LEGAL DECISION de Carlos).
Test con Mailpit: `docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit` y `MAILPIT_SMTP_URL=smtp://localhost:1025 MAILPIT_API_URL=http://localhost:8025 npm run test:integration` (sin esas variables se salta).

## Seguridad del esquema (SEC-CNS-024, PROPUESTO)
El código OTP se genera (pgcrypto) y se verifica DENTRO de la base; no existe `CNS_OTP_SECRET` ni HMAC en Node. Mitiga RES-OTP-WEB-PRB; residual F-RB-03 aceptado por Carlos (proceso único):
el código viaja al proceso Node (pool del mailer) para ir al correo. `verify_otp` corre siempre en su propia transacción (`OtpRepo.verify` no admite unidad de trabajo externa). Ventana verificación -> decisión: 10 min.
Arranque: `assertEnvironment` (entorno vs catálogo) y `assertRuntimeRole` (rechaza superusuario, BYPASSRLS, `session_user != current_user`, membresías). `pg_dump -Fc` + `pg_restore` restaura el ledger (CHECK con `now()` van NOT VALID).
Requiere la extensión `pgcrypto` (incluida en postgres:16; la crea el dueño en el esquema `ext`, sin USAGE para `consent_app`).

## Operación (consent-admin)
CLI por SSH (`npm run admin -- <comando> [--json]`, o `node src/cli/main.ts`). Entorno: `CNS_ENVIRONMENT`, `CNS_DATABASE_URL` (consent_app), `CNS_MAILER_DATABASE_URL` (consent_mailer); con `--run-worker-once`, además la config SMTP/allowlist. Aborta si algún pool no conecta con su rol. Salida sin PII (correos como `a***@dominio`); código de salida ≠0 ante error.
- `import-csv <archivo> --batch <ref> [--dry-run|--apply]`: `--dry-run` por defecto. Todo o nada (una fila inválida rechaza el lote). Idempotente (reimportar = 0 nuevas). Resumen `total/nuevas/existentes/inválidas`.
- `send-invitations --batch <ref> [--limit n] [--run-worker-once]`: encola la primera invitación de cada READY. El envío lo hace el worker del proceso web; sin web, use `--run-worker-once`.
- `resend <invitation_ref> --reason <CODE> [--run-worker-once]`: reenvío de operador (rota el token; motivo `^[A-Z][A-Z0-9_]{2,39}$` queda en el ledger). Solo pool mailer.
- `status [--batch <ref>] [--student <ref>]`: conteos por estado de invitación, decisión y outbox; con `--student`, `authorization_status`.
- `verify-ledger`: recomputa la cadena con el verificador TS; imprime OK/FALLA, cabeza (`chain_seq`, `event_hash`) y conteo; exit 0/1. Usa el pool app (tiene SELECT del ledger).
- `cancel`: NO disponible (exit 3). `cancel_invitation` solo admite `SUBJECT_MISMATCH_REPORTED` sobre OPENED/VERIFIED; cancelar READY/SENT por operador (`OPERATOR_CANCELLED`) requiere una función nueva en H2.

CSV UTF-8, cabecera exacta `student_ref,student_first_name,guardian_email` (ver `examples/invitations.example.csv`):
`student_ref` opaco `[A-Za-z0-9_-]{8,64}` (no RUT), nombre de pila 1-40 caracteres (sin apellidos), correo válido (se guarda en minúsculas); `--batch` con la misma forma que `student_ref`. Máx. 10.000 filas.

## Criterios de aceptación H1 (E2E)

Gobierna: DEC "Reconstrucción mínima" (2026-10-19) y plan v2 H1-11. `tests/e2e/acceptance.test.ts` (`npm run test:e2e`; job `beta-e2e`) arranca el proceso real `src/server/main.ts`, la CLI real `src/cli/main.ts` y un buzón SMTP: Mailpit si `MAILPIT_SMTP_URL` y `MAILPIT_API_URL` están definidas (CI); si no, un receptor SMTP mínimo del propio test (el proceso real envía igualmente con `SmtpMailer`). Los tests dependen unos de otros y corren en orden. Solo datos sintéticos.

| Criterio de la DEC | Test (`acceptance.test.ts`) |
|---|---|
| Importar invitación (N nuevas; reimport 0) | `paso 1` |
| Correo real al apoderado; el token no queda en outbox, logs ni ledger | `paso 2` |
| Verificar apoderado (escáner x2, open, OTP del correo) | `paso 3` |
| Registrar autorización con la versión/hash servidos; recibo; `status` = AUTHORIZED | `paso 4` |
| Consultar desde LectorPro (HMAC, replay de nonce -> 401 -> false) | `paso 5` |
| Revocar con el enlace de gestión del correo y OTP; recibo; `confirm` repetido y x10 en paralelo = una revocación | `paso 6` |
| LectorPro ya no permite lecturas nuevas (primera consulta tras el commit) | `paso 6b` |
| Servidor apagado => fail-closed | `paso 7` |
| Evidencias auditables y restauración (`verify-ledger`, `pg_dump`/`pg_restore`, copia alterada => exit 1) | `paso 8` |
| Consistencia ante duplicados y concurrencia (20 `submit` paralelos = 1 decisión y 1 evento) | `extra: 20 POST /decision/submit` |
| Segundo apoderado DECLINED => no se puede leer | `extra: segundo apoderado DECLINED` |
| Subject-mismatch cancela la invitación | `extra: subject-mismatch` |

## Despliegue en VPS (H1-12)
Paquete en `beta/deploy/` (Caddy + una unidad systemd + `.env`, Ubuntu 24.04; sin nftables ni backups, eso es H2). Genera el zip desde la raíz del repo con `beta/deploy/build-package.sh`
(`build/consent-beta-deploy.zip`) y sigue `beta/deploy/README-DEPLOY-BETA.md`. Solo datos sintéticos y destinatarios de prueba; `CNS_ENVIRONMENT=LOCAL` es el único modo soportado en H1 (REAL = H2-08).
