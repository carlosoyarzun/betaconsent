# contracts/

Contratos OpenAPI/AsyncAPI y JSON Schemas de las interfaces del sistema. Gobierna: `API-CNS-###`.

**Estado: DRAFT (IT0, solo datos sintéticos).** Derivado de `specs/state-machines/*.spec.yaml` rev. 4 (CA-116, main e1908ed). Ningún contrato está aprobado; cierre = human gate de Carlos.

## Índice (JSON Schema 2020-12, `schemas/`)

- `common.schema.json` (API-CNS-180): tipos comunes, códigos de error, respuestas uniformes. Gobierno: common.spec.yaml, DEC-BR-001, DEC-BR-015 §1, DEC-BR-017 §6, ADR-002, ADR-006 §1.
- `api-payloads.schema.json` (API-CNS-181): bodies de request/response de las transiciones con `httpPost: true`. Gobierno: specs de las 6 máquinas, SM-CNS-001 v6/v7.
- `ledger-envelope.schema.json` (API-CNS-182): sobre de `integrity.audit_event`. Gobierno: common.spec ledgerEnvelope, INV-CM-04, GRD-CM-13, ADR-002 §2/§8.
- `ledger-event-payloads.schema.json` (API-CNS-183): lista blanca de payloads por eventType (INV-CM-05). Gobierno: events stream LEDGER de las specs, DEC-BR-017 §6.
- `security-event-payloads.schema.json` (API-CNS-184): security stream (OTP_*, RECOVERY_TOKEN_ISSUED, MANAGEMENT_TOKEN_ROTATED). Gobierno: otp-challenge.spec, revocation.spec.
- `outbox-events.schema.json` (API-CNS-185): consent.granted / consent.revoked. Gobierno: consent-decision.spec, revocation.spec R5, DEC-BR-017 §7. Sin AsyncAPI (las specs no lo exigen).
- `invitation.schema.json` (API-CNS-186), `decision-maker-verification.schema.json` (API-CNS-187), `consent-decision.schema.json` (API-CNS-188), `revocation.schema.json` (API-CNS-189), `rights-case.schema.json` (API-CNS-190), `tenant-context.schema.json` (API-CNS-191): proyecciones con `x-states` y `x-transitions` (trazabilidad transición a operación HTTP o worker).

API-CNS-001 queda reservado (AuthorizationCheck del consumidor, citado por las specs). El rango 100–199 es propuesto y debe reconciliarse con el registro de Notion (OPEN-CT-04).

## Pendiente (no hecho en este borrador)

- `openapi/consent-it0.openapi.yaml` (API-CNS-100; operaciones API-CNS-101…160): NO escrito. Diseño previsto: canje GET /i/, /m/, /r/ (x-pending DEC-BR-003); staff (I1, I2, I3, I3r, I9, EN0, EN1, RC0); portador (I4, V1, V2/V3, V2r, C1, C2, C3/C5, I9 subject-mismatch, R1, R2, R3, R8, RV0, R1r/R10/R11, RC1, RC3/RC3a); plataforma (RH2/RH2v, RH3 + cosign, RC4/RC5/RC6, CX2). Cada operación con `x-governed-by`, `x-state-transition`, `x-route-class` y `x-eligibility` (eligibility_to_participate vs eligibility_to_revoke).
- Tests de contrato (validación de ejemplos sintéticos) y lint de PII en URLs.

## x-pending y FINDINGS

x-pending usados: DEC-BR-003/EXT-A/LD-01, DEC-BR-004/EXT-C, EXT-B/DEC-BR-002/LD-21/F-014, LD-20/DEC-BR-005, LD-02, LD-03, LD-06, APR-IDP, ADR-011/DEC-BR-009, OPEN-OT-02, OPEN-TC-01/03/05/06, OPEN-RV-10, OPEN-CM-02, LD-15, P-v7-5; FINDINGS de auditoría (no gobernantes): F-002, F-003, F-004, F-005, F-006, F-007, F-011, F-012; propios: F-CT-01 (RC2u sin superficie HTTP; = F-011), F-CT-04 (consent.revoked sin subjectRef), F-CT-05 (expiresAt en I2 vs SENT + P-10), F-CT-06 (co-firma RH3 fuera de la lista blanca), F-CT-07 (TENANT_STATUS_CHANGED sin estado destino), OPEN-CT-02 (firma/transporte outbox, ACK y erasure.confirmed), OPEN-CT-03 (enum bindingResult).
