# evidence/

Evidencia de runtime, append-only, sobre consentimiento, revocación y decisiones
críticas.

Gobierna: `SEC-CNS-###`, `PRIV-CNS-###`.

Estado: vacía de evidencia de dominio (pre-build; el ledger de integridad de
consentimiento/revocación llega con ADR-002 y el código de `src/`).

## Evidencia de test runs (CA-118/H03)

`tools/testing/run-tests.ts` escribe, por cada corrida de una capa (`unit`,
`integration`, `contract`), un archivo JSON Lines en `evidence/test-runs/`
(`<layer>-<runId>.jsonl`), formato `test-evidence/v1`: ver `specs/test-framework.spec.yaml`
(`evidenceFormat`) para el esquema completo. Cero PII: solo IDs de test, ruta relativa
del archivo, resultado, duración y, si falla, código de error + mensaje truncado.

**`evidence/test-runs/` NO se commitea** (está en `.gitignore`). Decisión y
justificación completas en `specs/test-framework.spec.yaml` (`evidenceFormat.storageDecision`);
en resumen: es evidencia de una corrida de CI/desarrollo, no la evidencia de runtime de
consentimiento/revocación que este directorio gobierna para producción, y commitear un
archivo por corrida de cada PR no aporta valor de auditoría a largo plazo frente al
riesgo de historial de git. En CI, cada job sube su archivo como artefacto de GitHub
Actions con retención de 30 días (`retention-days: 30` en `.github/workflows/tests.yml`,
no la retención por defecto del repositorio); en LOCAL queda en disco para depuración y
puede borrarse. Revisable por Carlos/lampone-security si G-IT0-EXIT necesita evidencia
commiteada: ver la sección siguiente (Carlos, 2026-10-01, evidencia (a)).

## Manifiestos de evidencia IT0 (X3 / X5 / X6)

Decisión: Carlos, 2026-10-01, evidencia (a). Las condiciones de cierre de IT0 (G-IT0-EXIT, DEC-BR-014
rev. 8 §3: X3 controles synthetic-only verificados con evidencia en `evidence/`, X5, X6) se respaldan con un
**resumen por corrida y condición** commiteado en `evidence/it0/<condición>/<YYYY-MM-DD>-<commit corto>.json`
(`-nopg` antes de `.json` cuando la corrida no tuvo Postgres: los casos pg figuran `skip`).

- **Se commitea**: solo estos manifiestos. Formato: `{ condition, commit, branch, runAt (UTC),
  environment: "LOCAL"|"CI", postgres: { imageDigest|null }, tests: [{ id, title, file, status:
  "pass"|"fail"|"skip" }], summary: { pass, fail, skip }, exitCode }`. Solo IDs `TEST-CNS-###`, títulos de
  `traceability/test-matrix.csv`, rutas y estados; sin stdout/stderr, valores, emails ni tokens.
- **No se commitea**: `evidence/test-runs/` (JSONL crudos) sigue en `.gitignore` y como artefacto de CI de
  30 días. El generador rechaza (y no escribe nada) si algún manifiesto contiene patrones de email, JWT,
  token largo, `Bearer`, asignación de secreto o credenciales en URL.
- **Asignación test -> condición**: tokens `X3`/`X5`/`X6` en `governed_by` o `test_name` de filas ACTIVE de la
  matriz. Estado por ID de test en los JSONL; `pass` solo si todos los casos del ID pasaron (un skip parcial
  da `skip`). Las filas "paraguas" (`TEST-CNS-100/101/102`) agregan los IDs citados en su título.
  `X3` y `X6` están marcadas en la matriz como **parciales** (cierre pendiente de D8/D6 de Carlos): el
  manifiesto es evidencia de los casos, no declaración de que la condición esté cerrada (eso lo decide Carlos).
- **Regenerar** (sobre un árbol limpio; borrar antes `evidence/test-runs/` para no mezclar corridas):
  `npm run ci` (con `TEST_DATABASE_URL`, `TEST_APP_DB_PASSWORD`, `TEST_MIGRATOR_DB_PASSWORD` para la corrida
  completa) y luego
  `node scripts/evidence/manifest.ts --environment LOCAL --postgres-digest sha256:<digest de .github/workflows/tests.yml>`
  (o `--postgres-digest none` sin Postgres; `--environment CI` en CI). Test del generador: TEST-CNS-990.
- **X6**: la implementación completa de X6 está en `main` (PR #43, CA-128); manifiesto en
  `evidence/it0/X6/2026-10-01-89ed842.json`.
