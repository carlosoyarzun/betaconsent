# contracts/

Contratos OpenAPI/AsyncAPI y JSON Schemas de las interfaces del sistema. Gobierna: `API-CNS-###`.

**Estado: DRAFT (IT0, solo datos sintéticos).** Derivado de `specs/state-machines/*.spec.yaml` rev. 4c–4e (common 0.4.3, consent-decision 0.4.2, invitation 0.4.2, revocation 0.4.3, rights-case 0.4.4, tenant-context 0.4.3) y de `specs/adapters/lectorpro-beta.spec.yaml` 0.1.0 (CA-116; base `origin/fix/CA-116-f011-f012` @ dfd6e5e, PR #6, que incluye rev. 4b/4c de main 738ed98, F-011, F-012 y SEC-CNS-013). Ningún contrato está aprobado; cierre = human gate de Carlos.

## Índice (JSON Schema 2020-12, `schemas/`)

- `common.schema.json` (API-CNS-180): tipos comunes, códigos de error, respuestas uniformes. `ProductRef`, `ContextRef` y `Purpose` son códigos de catálogo con `x-resolved-from` al adapter (F-012); `ErrorCode.x-uniform-on-bearer-routes` (ERR-CM-01/02/10 → 404 uniforme). Gobierno: common.spec.yaml, adapter LectorPro Beta, DEC-BR-001, DEC-BR-015 §1, DEC-BR-017 §6, ADR-002, ADR-006 §1.
- `api-payloads.schema.json` (API-CNS-181): bodies de request/response de las transiciones con `httpPost: true` (incluye `CosignCaseConfirmationRequest` de RH3). Gobierno: specs de las 6 máquinas, SM-CNS-001 v6/v7.
- `ledger-envelope.schema.json` (API-CNS-182): sobre de `integrity.audit_event`; FIXTURE solo en LOCAL y solo en los eventTypes de la lista blanca (GRD-CM-13, GRD-CM-14). Gobierno: common.spec ledgerEnvelope, INV-CM-04, ADR-002 §2/§8.
- `ledger-event-payloads.schema.json` (API-CNS-183): lista blanca de payloads por eventType (INV-CM-05); `REVOCATION_CONFIRMED` con `recordedByRef` + `cosignedByRef` (INV-RV-11). Gobierno: events stream LEDGER de las specs, DEC-BR-017 §6.
- `security-event-payloads.schema.json` (API-CNS-184): security stream (OTP_*, RECOVERY_TOKEN_ISSUED, MANAGEMENT_TOKEN_ROTATED). Gobierno: otp-challenge.spec, revocation.spec.
- `outbox-events.schema.json` (API-CNS-185): consent.granted / consent.revoked. Gobierno: consent-decision.spec, revocation.spec R5, DEC-BR-017 §7. Sin AsyncAPI (las specs no lo exigen).
- `invitation.schema.json` (API-CNS-186), `decision-maker-verification.schema.json` (API-CNS-187), `consent-decision.schema.json` (API-CNS-188), `revocation.schema.json` (API-CNS-189; `verifiedAuthPath`/`verifiedRecoveryMethod`, GRD-RV-29), `rights-case.schema.json` (API-CNS-190; `revokedDecisionRef`, GRD-RC-02), `tenant-context.schema.json` (API-CNS-191; `actorBySource` en TN/SP): proyecciones con `x-states` y `x-transitions` (transición → operación HTTP, worker o fuente sin HTTP).

API-CNS-001 queda reservado (AuthorizationCheck del consumidor, citado por las specs). El rango 100–199 es propuesto y debe reconciliarse con el registro de Notion (OPEN-CT-04).

## Índice (OpenAPI 3.1, `openapi/`)

- `consent-it0.openapi.yaml` (API-CNS-100, `info.x-status: DRAFT`): 34 paths / 34 operaciones (API-CNS-101…149), bodies por `$ref` a `../schemas/*.schema.json#/$defs/...`. Servidor solo `http://localhost` (LOCAL/CI). Cada operación con transición lleva `x-governed-by`, `x-state-transition`, `x-route-class`, `x-eligibility`, `x-actor`, `x-guards`, `x-idempotency` y `x-pending`; las de varias fuentes, `x-actor.bySource` + `x-guards-by-source` (convención guardsBySource; `x-guards` = comunes ∪ fuente HTTP); las sincronizadas con F-011/SEC-CNS-013, `x-errors`. Transiciones sin superficie HTTP (worker, fuentes SYSTEM/FIXTURE, deshabilitadas) en `x-not-exposed` con motivo y guards.
  - Canje GET sin transición (INV-CM-08): `/i/` (con GRD-IV-13), `/m/`, `/r/` (101–103).
  - tenant-context: EN0, EN1 fuente STAFF (staff), CX2 (platform) (105–107).
  - invitation: I1, I2, I3, I3r, I9 por INVITER (staff), I4 (portador) (110–115).
  - otp-challenge: V1, V2/V3, V2r (120–122).
  - consent-decision: C1, C2, C3/C5, I9 SUBJECT_MISMATCH_REPORTED (125–128).
  - revocation: R1, R2, R3, R8, RV0 fuente BEARER, `/recovery/revoke` (R1r/R2r/R3r/R10/R11), RH2/RH2v (propose + approval), RH3 (record + cosign) (130–139).
  - rights-case: RC0 (staff), RC1 fuente BEARER, RC3/RC3a, close (RC4/RC5/RC6), **RC2u `POST /rights-case/resume` (149, nueva, F-011)** (145–149).
- Verificación local (sin validador OpenAPI instalado; no se instaló nada): YAML parsea; los 243 `$ref` del OpenAPI y los 304 `$ref` internos de los 12 schemas resuelven; los 12 schemas pasan `check_schema` Draft 2020-12 (jsonschema 4.25); sin nombres PII en paths ni parámetros; sin query params; ningún parámetro ni body acepta `tenantRef`/`organization*`; todo POST exige `X-CSRF-Token`; ningún GET transiciona; `x-api-id` únicos; bodies con `additionalProperties: false`; código OTP y `StepUpAssertion` `writeOnly`; `x-guards` cruzados contra las specs (solo difieren por diseño V1, por scope, y RC3/RC3a, unión con el lado Revocation).

## Pendiente (no hecho en este borrador)

- Validación con un validador OpenAPI 3.1 formal (no disponible localmente) y lint de PII en URLs como test automatizado.
- Tests de contrato (validación de ejemplos sintéticos).
- Códigos HTTP exactos por error (OPEN-CT-08), `x-errors` en el resto de operaciones y nombres de cookie/cabecera CSRF (P-26).

## FINDINGS y x-pending

Cerrados en esta sincronización: **F-011** / **F-CT-01** / **OPEN-CT-01** (RC2u = `POST /rights-case/resume` con CSRF; el GET de /m/ no transiciona), **F-012** (ProductRef/ContextRef/finalidades resueltos desde el adapter), **F-CT-06** (co-firma RH3 en la lista blanca: `cosignedByRef`, INV-RV-11), **F-CT-09** (guards GRD-CM-01/06/07 de SEC-CNS-013 en las transiciones RIGHTS), OPEN-CT-09 parcial (cosign RH3 con schema propio).

Abiertos, nuevos: **F-CT-10** (P1, security↔architecture: RC2u es un POST web con actor SYSTEM_GUARD, contra GRD-CM-15/TEST-CNS-445 "el ledger nunca registra SYSTEM_GUARD desde el entrypoint web"; depende de F-005/DEC-BR-018), **F-CT-11** (P2: RC4–RC6 listan ERR-CM-01 en errors sin GRD-CM-01 en guards).

Abiertos, heredados: F-002, F-003, F-004, F-005, F-006, F-007 (auditoría, no gobernantes); F-CT-04 (consent.revoked sin subjectRef), F-CT-05 (expiresAt en I2 vs SENT + P-10), F-CT-07 (TENANT_STATUS_CHANGED sin estado destino), OPEN-CT-02 (firma/transporte outbox, ACK y erasure.confirmed), OPEN-CT-03 (enum bindingResult), OPEN-CT-04, OPEN-CT-08, OPEN-CT-09 (clientRequestId de I1 como Idempotency-Key).

x-pending de specs y decisiones: DEC-BR-003/EXT-A/LD-01 (P0 del enlace), DEC-BR-004/EXT-C, EXT-B/DEC-BR-002/LD-21/F-014, LD-20/DEC-BR-005, LD-02, LD-03, LD-06, LD-15, APR-IDP, ADR-011/DEC-BR-009, P-26, P-v7-5, OPEN-OT-02, OPEN-CM-02, OPEN-CM-08, OPEN-TC-01/03/04/05/06, **OPEN-TC-07** (cascada por job, PENDING-CARLOS), **OPEN-RV-10** (step-up RH3), **OPEN-RV-11** (cosignedByRef en DEC-BR-017 §6, PENDING-CARLOS), **OPEN-RV-12** (errors ⊇ onFail), **OPEN-RV-13** (R1r/R10/R11 sin GRD-CM-07; R2/R3 sin GRD-CM-01), F-005/DEC-BR-018 (actor de RC2u), DECISION CARLOS (actorType de "migración revisada" en TN/SP).

Diferencias entre la propuesta SEC-CNS-013 (propuesta-4c.md) y la spec final; el contrato sigue la spec: (1) RC2u conserva actor SYSTEM_GUARD (`actorPending`), la propuesta pedía UNVERIFIED_BEARER; (2) TN/SP usan `bySource {FIXTURE: {actorType: FIXTURE}, MIGRATION: deshabilitada}`, sin actorRole en la fuente FIXTURE (propuesta.md lo daba con PLATFORM_ADMIN/CONTEXT_OWNER); (3) RC4–RC6 agregan ERR-CM-01 a errors sin GRD-CM-01 en guards (F-CT-11).
