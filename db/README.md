# db/

Esquemas y migraciones de base de datos.

Gobierna: `RULE-CNS-###`, `SEC-CNS-###` (tenancy, integridad).

- `migrations/`: SQL versionado e inmutable una vez mergeado (runner: `src/infra/adapters/postgres/migrate.ts`).
- `fixtures/local/`: paso LOCAL-ONLY / SYNTHETIC DATA ONLY, separado de las migraciones (SEC-CNS-017 c). Lo corre
  `applyLocalFixtures` como `consent_migrator` (nunca superusuario, nunca desde el proceso web); se niega si
  `CNS_ENVIRONMENT != LOCAL` o `ops.db_catalog` no es LOCAL/SYNTHETIC. CLI:
  `CNS_ENVIRONMENT=LOCAL CNS_MIGRATOR_DATABASE_URL=... node src/infra/adapters/postgres/local-fixtures-cli.ts`.

## Ownership del ledger (CA-143; tras PR #60, X8 decisión 3 de Carlos, 2026-10-06, F-X8-11)

Gobierna: DEC-BR-014 §6 (owner NOLOGIN distinto del migrador), ADR-002 §2, INV-CM-01 (append-only). Las citas son
`archivo:línea` sobre `main` (34a52de); si una migración cambia, hay que actualizarlas.

### Roles y qué puede cada uno

| Rol | Atributos / membresía | `integrity.audit_event` (ledger) | `ops.security_event` |
|---|---|---|---|
| `app_rw` (runtime) | LOGIN, NOSUPERUSER, NOBYPASSRLS, no miembro de ningún owner (`0000_roles.sql:15-17`, `:30-35`, `:48-49`) | SELECT + INSERT solo por columnas, filtrado por RLS de tenant (`0002_ledger.sql:75-77`; columnas de cadena y `occurred_at/environment` añadidas en `0013_ledger_chain.sql:77,84`). Sin UPDATE/DELETE/TRUNCATE | Solo INSERT por columnas y policy de INSERT por tenant y por familia de evento (`security_event_app_rw_insert`, `0029_security_event_otp_family.sql`); sin SELECT (`0025_ops_security_event.sql:73-78`) |
| `worker`, `platform_rw` | LOGIN, mismos atributos que `app_rw` (`0000_roles.sql:30-35`) | Nada (`0002_ledger.sql:13`) | Ningún grant (solo `app_rw`); `platform_rw` recibirá los tipos STAFF/CASE en ADR-010 PR-5, `worker` solo `EXECUTE ops.purge_p34` en SEC-CNS-021 PR-3 |
| `consent_migrator` | LOGIN, miembro de `consent_owner` con INHERIT TRUE, SET TRUE (`0000_roles.sql:41`) | Ver `consent_owner` (hereda) | Ver `consent_owner` |
| `consent_owner` (rol del migrador) | NOLOGIN, NOSUPERUSER (`0000_roles.sql:11`, `:27`); el runner corre cada migración de base como este rol (`0000_roles.sql:39-40`). Es dueño de la base (`0027_ledger_integrity_owner.sql:10`) | Sin ningún privilegio ni CREATE tras `0027` (aserciones en `0027_ledger_integrity_owner.sql:81-86`). Puede `SET ROLE integrity_owner` (ver residual) | Dueño del **esquema** `ops` (`AUTHORIZATION consent_owner`, `0001_schemas_catalog.sql:15`), por lo que puede DROP de tablas de `ops` (R-21-1 / F-2, P2, aceptado IT0b). Desde `0029` ya NO es dueño ni tiene privilegios sobre `ops.security_event` (SELECT/INSERT/UPDATE/DELETE/TRUNCATE/TRIGGER: 42501); puede `SET ROLE security_event_owner` (membresía transitoria, F-7). Lo protegen triggers `ENABLE ALWAYS` y FORCE RLS (`0025_ops_security_event.sql:60-72`) |
| `integrity_owner` | NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOBYPASSRLS; `consent_owner` es miembro con INHERIT FALSE, SET TRUE (`0026_integrity_owner_role.sql:20-29`); ningún rol de runtime es miembro (`0026:31-44`; `startup-checks.ts:87-95`) | Dueño de la tabla, de `integrity.audit_event_immutable()` y del esquema `integrity` (`0027_ledger_integrity_owner.sql:24-28`). Sin USAGE/EXECUTE sobre `app`/`ops` (`0027:8-9`) | Ninguno |
| `security_event_owner` (SEC-CNS-021 PR-1, CA-146 / P-34) | NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOBYPASSRLS; `consent_owner` es miembro con INHERIT FALSE, SET TRUE (`0028_security_event_owner_role.sql`); ningún rol de runtime es miembro (`startup-checks.ts`, `catalog.test.ts`) | Ninguno | Dueño de la tabla y de `ops.security_event_immutable()` (`0029_security_event_otp_family.sql`); USAGE en `ops` sin CREATE. Dueño futuro de `ops.retention_policy`, `ops.purge_run`, `ops.otp_budget` y `ops.purge_p34` (PR-3/PR-4). Todo DDL futuro sobre esos objetos declara `SET LOCAL ROLE security_event_owner` (allowlist en `tools/spec-checks/integrity-owner-checker.ts`, TEST-CNS-1325) y pasa por CODEOWNERS |
| `staff_roster_owner` / `staff_roster_reader` | NOLOGIN (`0018_staff_roster_roles.sql:20-24`); `consent_owner` puede SET sin heredar (`:30`); `app_rw` puede SET `staff_roster_reader` sin heredar (`:32`) | Ninguno: la vista del roster no hace JOIN a ledger (`0019_staff_roster_projection.sql:20-21`) | Ninguno |
| `tenant_resolve_owner`, `outbox_claimer` | Fuera del alcance de este modelo (`0000_roles.sql:12`, `0004_outbox_claimer_role.sql:9`) | Ninguno | Ninguno |

Dueño del ledger: `integrity_owner` es dueño de `integrity.audit_event` (arrastra índices, triggers y policies),
de `integrity.audit_event_immutable()` y del esquema `integrity` (`0027_ledger_integrity_owner.sql:5-7`). Los objetos
se transfieren antes que el esquema porque al revés `consent_owner` pierde USAGE (`0027:15`). El CREATE temporal
sobre la base se concede y revoca dentro de la misma migración (`0027:16-21`, `:31-35`), y los privilegios por
defecto de `integrity_owner` no dan EXECUTE a PUBLIC (`0027:37-40`). Todo DDL futuro sobre `integrity.*` debe
declarar `SET LOCAL ROLE integrity_owner` y pasar por CODEOWNERS (`0026_integrity_owner_role.sql:10-11`;
`/db/migrations/` está en `.github/CODEOWNERS`). `0027` aborta si algo no queda como se declara
(`0027:42-87`: dueños, triggers `ENABLE ALWAYS`, FORCE RLS, sin privilegios de `consent_owner`).

`0030` (SEC-CNS-021 PR-2) redefine la lista blanca del ledger sin los tipos OTP_*/RECOVERY_TOKEN_ISSUED/MANAGEMENT_TOKEN_ROTATED
(ahora en `ops.security_event`). **Aborta si encuentra filas OTP_*/RECOVERY históricas en `integrity.audit_event`: recrear la base**
(el CHECK se crea validado, sin `NOT VALID`, decisión de Carlos 2026-10-09; la validación recorre todas las filas y la migración revierte con
23514). En una base recreada (IT0, datos sintéticos) pasa sin costo. Esas filas dejarían la cadena inverificable (`verifyChainRows` →
`EVENT_TYPE_NOT_ALLOWED`) y un challenge en curso con `OTP_ISSUED` en sequence 1 daría conflicto en V3 (`expectedSequence` 0).

### Qué protege

- Append-only: sin grant de UPDATE/DELETE/TRUNCATE al runtime y triggers `ENABLE ALWAYS`, que bloquean incluso al
  dueño y con `session_replication_role=replica` (`0002_ledger.sql:7-8`, `:62-64`); `ops.security_event`
  igual (`0025_ops_security_event.sql:60-67`). Tras `0027`, el migrador (directo o con `SET ROLE consent_owner`)
  recibe 42501 al intentar DROP, ALTER, DISABLE TRIGGER, OWNER TO, GRANT, SELECT, INSERT, DELETE o TRUNCATE
  sobre el ledger.
- Cadena SHA-256 por tenant (`payload_hash`, `previous_event_hash`, `event_hash`; sin bifurcaciones por
  `UNIQUE (tenant_id, previous_event_hash)`; CHECK que rechaza INSERT sin eslabón), recomputable con
  `verifyLedgerChain` (`0013_ledger_chain.sql:3-4`, `:12-16`, `:22-24`;
  `src/server/modules/common/ledger-chain.ts:174`).
- No protege: la cadena no tiene HMAC ni ancla externa (`0013_ledger_chain.sql:3-4`; R-04 en
  `registers/risk-register-IT0.md:15`: solo NON-EVIDENTIARY, rechazado para datos reales).

### Residual P1 (aceptado solo para IT0 sintético)

Aceptado por Carlos el 2026-10-06 solo para IT0 sintético (texto en `0026_integrity_owner_role.sql:14-18`,
`tests/integration/postgres/ledger-chain.test.ts:169-174`). Caduca antes de datos reales / G6.

1. El migrador puede `SET ROLE integrity_owner` explícito (migrador -> `consent_owner` -> `integrity_owner`) y
   entonces tiene control total del ledger: DISABLE TRIGGER, CREATE OR REPLACE de la función, DROP. Como la cadena no
   tiene ancla externa, no detectaría una reescritura con los hashes recalculados.
2. `consent_owner` es dueño de la base (datdba) y puede `DROP DATABASE`.

Cierre: CA-144 (ADR-010 break-glass, dueño de la base distinto y ancla externa). Esta migración solo logra que el
DDL del ledger deba declararse y revisarse (`0026:18`).

### Cómo se verifica

- TEST-CNS-1230 (matriz de 42501 del migrador y membresía de `integrity_owner` = `consent_owner` INHERIT FALSE,
  SET TRUE) y TEST-CNS-1231 (dueños, sin CREATE temporal, triggers `ENABLE ALWAYS`, append e idempotencia de
  `app_rw`): `tests/integration/postgres/ledger-integrity-owner.test.ts:12`, `:42`;
  `traceability/test-matrix.csv:621-622`.
- TEST-CNS-915 documenta el residual (`ledger-chain.test.ts:159-190`); también `catalog.test.ts:13`,
  `ledger-outbox-schema.test.ts:39-40`.
- En arranque: `startup-checks.ts:87-95` falla si la conexión es miembro de `integrity_owner`.
- CA-142 (spec-check `SET LOCAL ROLE integrity_owner` en `tools/spec-checks/`): en curso, no forma parte de este doc.
  Estas pruebas requieren Postgres real (`npm run test:integration`).

## Retención y purga P-34 (0031, SEC-CNS-021 PR-3)

- `ops.retention_policy` (solo-agregar, sembrada con 30 días: **PLACEHOLDER**, LD-15 abierta) y `ops.purge_run` (evidencia por corrida) son de `security_event_owner`, con FORCE RLS y sin grants de runtime.
- La purga solo ocurre vía `ops.purge_p34(store, esperado)` (SECURITY DEFINER; EXECUTE solo `worker`). Stores: `security_event`, `otp_verification`, `purge_run` (`otp_budget` llega en PR-4). El trigger `ops.security_event_guard()` rechaza UPDATE siempre y DELETE salvo dentro de la función y solo de filas vencidas; TRUNCATE sigue prohibido.
- `ops.retention_status()` (app_rw, worker) y `ops.purge_run_summary(run_id)` (worker) exponen solo estado/conteos. CLI: `src/infra/adapters/postgres/retention-purge-cli.ts` (rol `worker`); config `CNS_RETENTION_{SECURITY_EVENT,OTP_VERIFICATION,PURGE_RUN}_DAYS` (obligatorias en STAGING; LOCAL/DEV sin ellas = `DISABLED_LOCAL`, exit 3).
- Residual R-21-2 (aceptado SOLO para IT0b sintético; pasa a P1 antes de datos reales; se cierra con ADR-010 PR-7: event trigger, membresía SET fuera de la ceremonia, auditoría de sesiones): quien pueda `SET ROLE security_event_owner` puede borrar sin dejar rastro (DISABLE TRIGGER, NO FORCE RLS, DROP POLICY/TABLE; bajar la retención y borrar OTP activos, incluido el estado de lockout; borrar `otp_verification` vencidas sin `purge_run`). Pueden hacer ese SET ROLE `consent_owner` y, por transitividad, `consent_migrator` y los superusuarios; ningún rol de runtime puede.
