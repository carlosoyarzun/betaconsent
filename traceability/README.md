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
gobierna cada test real; siguen sin existir (pre-build de dominio).
