# db/ceremonies/ — ceremonias de break-glass (ADR-010 rev. 6, PR-7e)

Gobierna: ADR-010 rev. 6 §10 fila PR-7 (7d/7e), §4.5.3, §4.5.4, Q13, Q-20 (c), F-PR7-03/07/08, F-PR7B-10; decisiones de Carlos del 2026-10-16 (C-1, C-4, C-5, C-9). Solo datos **sintéticos** (IT0 LOCAL / IT0b): nada de este runbook autoriza datos reales.

## Qué es y cuándo se usa

Desde el revoke de `integrity_owner` a `consent_owner` (0086, **ambos modos**, C-1) el migrador ya no puede cambiar el ledger. Toda DDL sobre `integrity.*`, y toda DDL con otro owner gobernado después de 0086, va por una **ceremonia**: el único rol que asume los 17 owners es `ddl_breakglass` (NOLOGIN fuera de ceremonia, `CONNECTION LIMIT 1`, `log_statement = 'ddl'`, sin parámetros en el log). `db/migrations/` posteriores a 0086 no pueden hacer `SET ROLE` a un owner (checker CA-142, `checkPostRevokeMigrations`, TEST-CNS-1860).

Casos: DDL del ledger (capa 2, EN1, I9…), esquemas nuevos en REAL_DATA (F-PR7-04), bootstrap/re-bootstrap de principals PLATFORM (Q10, `bootstrap-principal.sql`; el alta rutinaria será PR-7g, C-8), recuperación de incidentes.

## Quién participa (C-4)

- **IT0b sintético**: Carlos solo (opera como superusuario del host y aprueba).
- **Antes de datos reales**: dos personas (operador del host ≠ aprobador) y ≥ 3 PLATFORM (Q10). Pendiente: no hay datos reales autorizados.
- Registro: `breakglass.ceremony` (sin personas: referencia opaca, ventana, motivo, ticket Jira CA) + log de sesión + acta en Jira CA (sin PII). La evidencia **primaria** (ancla firmada antes/después, Q13) llega con PR-7f (F-R6-1, C-7 pendiente de Carlos): hasta entonces la evidencia del ensayo es **secundaria** (`evidence/it0b/PR7-ceremony-rehearsal/`).

## Procedimiento

1. **Preparar** (revisado por PR, solo DDL): el script de DDL de la ceremonia (`db/ceremonies/<ticket>-ddl.sql`) con `BEGIN; SET LOCAL ROLE <owner>; …; COMMIT;`. Prohibido DML con literales de datos. Sin `log_statement='all'`: el log de la sesión es `ddl` y sin parámetros (F-PR7-07).
2. **Verificador SCRAM en el cliente** (la contraseña en texto plano nunca llega al servidor ni a sus logs):
   `VERIFIER=$(node tools/ceremony/scram-verifier.ts)` — el verificador va a stdout; la contraseña aleatoria de 24 bytes va a **stderr**, se muestra una sola vez y se entrega fuera de banda a quien abrirá la sesión.
3. **Abrir** (superusuario, conectado a la **base de la aplicación**):
   `CNS_CEREMONY_VERIFIER="$VERIFIER" psql "$SUPERUSER_URL" -v ON_ERROR_STOP=1 -v ceremony_ref=CER-AAAAMMDD-NN -v reason_code=DDL_LEDGER -v ticket_ref=CA-nnn -v valid_minutes=30 -f db/ceremonies/open.sql`
   El verificador entra por el **entorno** (`\getenv`, psql 15+), nunca por argv (`ps`, historial del shell); la sesión fija `pg_stat_statements.track_utility = off` (F-PR7D-10).
   Inserta la fila, habilita `LOGIN` con `VALID UNTIL` (≤ 60 min, P-46; CHECK de la tabla) y rechaza una segunda ceremonia abierta. La sesión de superusuario usa `log_statement = 'none'` para no escribir el verificador.
4. **Ejecutar la DDL** como `ddl_breakglass` (`psql "postgresql://ddl_breakglass@host/db" -f <script>`). Una sola sesión a la vez.
5. **Cerrar** (siempre, aunque falle la DDL): `psql "$SUPERUSER_URL" -v ON_ERROR_STOP=1 -v ceremony_ref=… -f db/ceremonies/close.sql`. `NOLOGIN`, contraseña descartada, `VALID UNTIL` vencido y `closed_at` en una transacción; DESPUÉS del COMMIT termina las sesiones de `ddl_breakglass` y verifica que quedan 0 (falla si no).
6. **Después**: verificar con `chain-verifier` (corrida manual) y, si hubo DDL de `integrity.*`, actualizar el spec/inventario; registrar el acta en Jira CA. Un **deploy con una ceremonia abierta falla cerrado** (aserción posterior al deploy, INV-DBR-09): cierre primero.

## Vigilancia (T-8, F-PR7-03, C-9)

Quien vigila el break-glass es el **chain-verifier** (no el verifier): `consent-breakglass-watch.timer` (cada 1 min) → `main.ts breakglass-watch` → alerta (`OnFailure` → `consent-breakglass-watch-alert.service`, journal local) si `ddl_breakglass` tiene `LOGIN` o una sesión sin ceremonia abierta y vigente, o si una ceremonia sigue abierta pasada su ventana. Mismo rol (`integrity_chain_verifier`, `USAGE` de `breakglass` y `SELECT` por columnas de `breakglass.ceremony`), sin egress ni credencial nueva. **Quién lee el journal del host: IT0b (D-3), pendiente.** Los logs de ceremonia (log de sesión del servidor, `infra/postgres/postgresql.breakglass.conf.example`) se conservan como el ledger, minimizados y solo DDL: **LEGAL DECISION C-5 de Carlos**; el valor de P-34/LD-15 y el destino fuera del host (canal pull, C-7) siguen pendientes y bloquean REAL_DATA, no IT0b sintético.

## Qué NO protege esto (residual declarado)

El superusuario del cluster / root del host puede deshabilitar triggers, reescribir `breakglass.ceremony` o abrir `LOGIN` sin ceremonia: residual root/superusuario (R-03/R-16), detectado por la vigilancia y, cuando exista, por el ancla externa de PR-7f (F-R6-1, C-7). El modo REAL_DATA de la aserción es **verificable, no una autorización de datos reales** (F-PR7-12): sigue bloqueado por F-PR7-01 y el catálogo exige `data_class = SYNTHETIC`.

## Runbook de casos especiales (F-PR7B-10)

El chain-verifier guarda cabezas por tenant en `integrity.chain_checkpoint` y una copia local en su `StateDirectory` (`/var/lib/consent-chain-verifier`, 0600). Dos situaciones legítimas lo hacen fallar con exit 2 de forma **permanente** hasta una decisión humana:

- **Restaurar PITR / copia local adelantada**: tras restaurar la base a un instante anterior, la copia local queda **adelantada** a la base (`CHECKPOINT_STATE_MISMATCH`). Procedimiento: (1) confirmar con Carlos que la restauración fue intencional (ticket CA); (2) detener `consent-chain-verifier.timer`; (3) conservar la copia local anterior como evidencia (`mv`, no borrar) y dejar que el proceso la regenere desde la base restaurada **solo después** de que una corrida manual revise que la cadena restaurada es íntegra y que cada cabeza restaurada es prefijo de la anterior; (4) abrir una ceremonia (`reason_code=INCIDENT_RECOVERY`) si hay que ajustar `chain_checkpoint` (append-only: solo por ceremonia); (5) reactivar el timer y registrar el acta. Nunca se reescribe la copia local sin ceremonia: sanar el hallazgo sin intervención lo borraría.
- **Purga o baja de un tenant (colegio)** → `TENANT_MISSING` permanente: el tenant tiene checkpoints pero ya no eventos. La retención del ledger frente a checkpoints append-only es **LEGAL DECISION LD-15/P-34 (Carlos)**; mientras no exista, la baja de un tenant exige ceremonia `INCIDENT_RECOVERY` que registre (con ticket) la baja y el nuevo conjunto esperado de tenants; no hay vía automática. Ver `db/README.md`.

## Archivos

- `open.sql`, `close.sql`: abrir/cerrar (superusuario; metacomandos psql).
- `bootstrap-principal.sql`: alta del vínculo `principal_ref ↔ sub_hmac` atestado fuera de banda (Q10; F-A10-17 parte bootstrap), dentro de una ceremonia, con la sesión de `ddl_breakglass`.
- `rehearsal-ddl.sql`: DDL mínimo del ensayo automatizado (TEST-CNS-1858: abrir → DDL → cerrar, con evidencia).
- Herramienta: `tools/ceremony/scram-verifier.ts` (RFC 5802/7677, `node:crypto`, vector de prueba en TEST-CNS-1851).
