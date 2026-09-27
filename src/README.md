# src/

Código de producto de la Consent App.

Gobierna: `REQ-CNS-###`, `API-CNS-###`, `RULE-CNS-###`.

Estado: primeros slices verticales de dominio IT0 (CA-116), sin HTTP ni Postgres reales —
solo puertos e implementaciones in-memory (ADR-003 rev. 7: sin infraestructura hasta la
historia correspondiente). Capas: `server/modules` (dominio), `server/ports` (interfaces),
`infra/adapters` (in-memory IT0), siguiendo el guardrail de `tools/guardrails/ports-adapters/`.
