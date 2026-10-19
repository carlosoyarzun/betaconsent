# consent-beta (reconstrucción mínima, 1 colegio)

Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19) y el plan v2
(H1-01 esqueleto, H1-02 esquema + roles). Carpeta autocontenida: no importa nada de `src/`, `db/` ni `frontend/`;
lo reutilizado se copió con cabecera `// origen: <ruta>@9345b78`. Solo datos sintéticos hasta el Hito 2.

Node 24 con type-stripping (`node src/...ts`, sin build). Única dependencia de producción: `pg`.

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
