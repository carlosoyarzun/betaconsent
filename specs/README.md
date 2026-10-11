# specs/

Specs ejecutables (YAML) derivadas de requisitos y reglas aprobados en Notion.

Gobierna: `REQ-CNS-###`, `RULE-CNS-###`.

## Estructura

- `state-machines/`: specs genéricas de las máquinas de estado IT0 (H01 / CA-116). No fijan
  valores concretos de producto (contextRef, productRef, finalidades): esos valores se resuelven
  desde `adapters/` (F-012, Notion Executable Specs Index).
- `db-roles.spec.yaml` (SPEC-CNS-DB-ROLES, rev. 0.2.0, `status: PROPOSED`): roles de PostgreSQL, membresías por modo, privilegios y chequeos de ADR-010 rev. 4 (PR-1; Q-17…Q-20 de Carlos, 2026-10-11). Solo especificación: sin código ni migraciones (implementación en ADR-010 PR-2…PR-7).
- `state-machines/revocation.spec.yaml` (0.4.5) y `rights-case.spec.yaml` (0.4.7) incorporan el bloque `dbEnforcement` (rev. 4i): funciones SECURITY DEFINER por transición (dueño `transition_owner`, Q-18), trigger y revokes a `app_rw`. Sin cambio de guards, actores, estados, eventos ni semántica de consentimiento/revocación/elegibilidad.
- `adapters/`: specs de configuración de producto/contexto que parametrizan las specs genéricas
  de `state-machines/`.
  - `lectorpro-beta.spec.yaml` — LectorPro Estudio Beta (contextRef `BETA_2026_01`, productRef
    `LECTORPRO`); adapter de `state-machines/consent-decision.spec.yaml`.

Estado: subconjunto IT0 (CA-116) en `state-machines/` y `adapters/lectorpro-beta.spec.yaml`,
`status: PROPOSED` (human gate pendiente: Carlos).
