# src/

Código de producto de la Consent App.

Gobierna: `REQ-CNS-###`, `API-CNS-###`, `RULE-CNS-###`.

Estado: primeros slices verticales de dominio IT0 (CA-116), sin HTTP ni Postgres reales —
solo puertos e implementaciones in-memory (ADR-003 rev. 7: sin infraestructura hasta la
historia correspondiente). Capas: `server/modules` (dominio), `server/ports` (interfaces),
`infra/adapters` (in-memory IT0), siguiendo el guardrail de `tools/guardrails/ports-adapters/`.

## Servidor de desarrollo (LOCAL)

`CNS_ENVIRONMENT=LOCAL node src/server/entrypoints/dev.ts` (PORT opcional, default 3000; aborta
fuera de LOCAL, GRD-CM-13). Imprime la invitación sintética y cómo leer el OTP. Solo en LOCAL
expone `GET /__dev/otp-sink` (sink en memoria, cero PII, dominios `example.invalid`).
