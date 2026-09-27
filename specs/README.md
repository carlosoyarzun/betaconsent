# specs/

Specs ejecutables (YAML) derivadas de requisitos y reglas aprobados en Notion.

Gobierna: `REQ-CNS-###`, `RULE-CNS-###`.

## Estructura

- `state-machines/`: specs genéricas de las máquinas de estado IT0 (H01 / CA-116). No fijan
  valores concretos de producto (contextRef, productRef, finalidades): esos valores se resuelven
  desde `adapters/` (F-012, Notion Executable Specs Index).
- `adapters/`: specs de configuración de producto/contexto que parametrizan las specs genéricas
  de `state-machines/`.
  - `lectorpro-beta.spec.yaml` — LectorPro Estudio Beta (contextRef `BETA_2026_01`, productRef
    `LECTORPRO`); adapter de `state-machines/consent-decision.spec.yaml`.

Estado: subconjunto IT0 (CA-116) en `state-machines/` y `adapters/lectorpro-beta.spec.yaml`,
`status: PROPOSED` (human gate pendiente: Carlos).
