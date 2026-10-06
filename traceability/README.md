# traceability/

Matrices de trazabilidad requisito → spec → contrato → código → test.

Gobierna: `REQ-CNS-###`, `TEST-CNS-###`.

Estado: `test-matrix.csv` (CA-118/H03, `specs/test-framework.spec.yaml`) registra test ↔
ID gobernante. Columnas: `test_id,layer,file,test_name,governed_by,status`. El rango
`TEST-CNS-900..999` está reservado para tests del propio marco de tests (framework) y para
tests de checkers de gobierno de specs (p. ej. `TEST-CNS-906`, checker H01 de máquinas de
estado, `tools/spec-checks/h01-sm-check.ts`; decisión de Carlos, 2026-09-27), no
de dominio, y se retira cuando se retiran esos tests de ejemplo. Los `TEST-CNS-###` de
dominio (numeración fuera de 900-999) los asigna `lampone-qa` junto con la spec/ADR que
gobierna cada test real (existen desde IT0; ver `test-matrix.csv`).

X8 (DEC-BR-014 rev. 8 §3; decisión 4 de Carlos, 2026-10-06):
- `state-machine-matrix.csv` y `state-machine-transition-guards.csv`: `test_id` apunta solo a TEST-CNS reales de
  `test-matrix.csv` o vale `UNCOVERED` con `uncovered_reason` (el mapeo es por cita textual del ID del
  guard/error/invariante/transición/evento en el título del test o en `governed_by`; una fila UNCOVERED significa
  "cobertura no demostrable por cita", no "sin test").
- `requirements-trace-matrix.csv`: REQ/RULE/UX/SEC/API → spec → contrato → módulo de código → TEST-CNS → evidencia,
  según citas reales (columna `status`: BUILT_IT0, TESTED_NO_CODE_CITE, CODE_NO_TEST, SPEC_ONLY).
- `x8-exceptions.csv`: huecos GRD/INV/ERR/API/REQ/RULE sin test; `accepted_by`/`accepted_on` los firma Carlos.
- Checker: `tools/spec-checks/traceability-checker.ts`, ejecutado en CI por `tests/unit/spec-checks/traceability-check.test.ts`.
