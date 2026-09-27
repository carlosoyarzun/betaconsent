# tests/

Tests unitarios, de integración, de contrato y E2E, incluyendo privacidad, seguridad y
accesibilidad.

Gobierna: `TEST-CNS-###`.

Estado: marco de tests montado (CA-118/H03, `specs/test-framework.spec.yaml`); sin tests
de dominio (pre-build de dominio, `src/` vacío).

## Capas y convención

| Capa | Ubicación | Qué prueba | Script |
|---|---|---|---|
| unit | `tests/unit/**/*.test.ts` | Funciones/módulos puros o casi puros, sin I/O real | `npm run test:unit` |
| integration | `tests/integration/**/*.test.ts` | I/O real contra un servicio externo (hoy: solo PostgreSQL). Nunca contra STAGING ni datos reales | `npm run test:integration` |
| contract | `tests/contract/**/*.test.ts` | Una suite por puerto (ADR-001 §11) que corre contra cada adaptador del puerto | `npm run test:contract` |
| guardrails | `tests/guardrails/**/*.test.ts` | Tests de la propia herramienta de guardrail (p. ej. Ports & Adapters, CA-136); no es una de las tres capas de arriba, se mantiene aparte con su script `npm test` | `npm test` |

Cada capa corre con `node --test` nativo (sin frameworks de test adicionales, ADR-001
§5) a través de `tools/testing/run-tests.ts <layer> <rootDir>`, que descubre los
archivos `*.test.ts` recorriendo el árbol (no glob de shell), corre `node --test` con
el reporter `spec` en stdout y el reporter de evidencia
(`tools/testing/evidence-reporter.ts`) hacia `evidence/test-runs/`, y termina con éxito
si la capa no tiene archivos SOLO fuera de CI (no bloquea desarrollo local mientras una
capa esté vacía). En CI (`CI`/`GITHUB_ACTIONS="true"`) una capa sin archivos falla
(fail-closed, SEC-CNS-011 P1-02): un check requerido no puede quedar verde si sus tests
se retiraron o movieron por error.

Convención de nombre de test: el primer argumento de `test()` empieza con el ID
gobernante exacto (`TEST-CNS-###`, o `TEST-CNS-9NN` para tests del propio marco, ver
`traceability/README.md`) seguido de una descripción breve; el reporter de evidencia
extrae esos IDs por regex para el campo `governedBy`.

Contrato por puerto (ADR-001 §11 regla 4): ver `tests/contract/ports/example-port.*`
para el patrón (`<puerto>.ts` interfaz, `<puerto>.contract.ts` casos reutilizables,
`<puerto>.test.ts` que los registra contra cada adaptador). El puerto de ejemplo
(`ExampleCounterPort`) es ficticio, no un puerto real de ADR-001 §11; sirve de plantilla
hasta que exista el primer puerto real en `src/server/ports/**`.

Integración con PostgreSQL: `tests/integration/postgres-smoke.test.ts` se omite (skip,
no falla) si `TEST_DATABASE_URL` no está definida FUERA de CI. En CI, el job
`integration` siempre define la variable contra un service container efímero; si
llegara a faltar (`CI`/`GITHUB_ACTIONS="true"` sin `TEST_DATABASE_URL`), el test FALLA
en vez de omitirse (fail-closed, SEC-CNS-011 P1-01). En LOCAL, con Docker disponible,
exportar `TEST_DATABASE_URL` antes de `npm run test:integration`; ver
`specs/test-framework.spec.yaml` (`integrationHarness`) para el detalle y el openItem
sobre la versión/digest de PostgreSQL (ADR-002 no la fija de forma exacta).

Detalle completo, decisiones y openItems: `specs/test-framework.spec.yaml`.
