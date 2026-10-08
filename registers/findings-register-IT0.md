# Registro de FINDINGs — Iteración 0 (IT0)

Gobierna: ADR-001 rev. 7 (ACCEPTED IT0 LOCAL+CI; enmienda rev. 8 ACEPTADA para IT0 (Carlos, 2026-10-06): AD-1..AD-4; pendientes CSP, lints §6.1 y SBOM/SAST) · ADR-002/006 r6 · SEC-CNS-005 rev. 5 · DEC-BR-014 (Iteración 0) · Master Plan §36 (Contradiction Protocol). Origen: retrospectiva X8 (lampone-architect, 2026-10-06); decisiones 2, 3 y 5 confirmadas por Carlos el 2026-10-06.
Estado: registrado por decisión de Carlos del 2026-10-06 ("registrar desvíos y step-up interino como FINDING en registers/"); el estado de cada hallazgo está en la columna Estado. Los desvíos AD-1…AD-4 y los DEFER DF-1…DF-13 se detallan en la enmienda ADR-001 rev. 8 (Notion).

Cero PII en este documento.

## F-X8-01 … F-X8-15

| ID | Sev. | Hallazgo (fuente A vs B) | Estado | Owner | Respaldo | Cierre |
|---|---|---|---|---|---|---|
| F-X8-01 | P2 | ADR-001 §1 F1 SPA vs HTML SSR (AD-1) | ACCEPTED-IT0 (rev. 8 aceptada, Carlos 2026-10-06) | lampone-architect | Carlos 2026-10-06 dec. 2 | ADR-001 rev. 8 cerrada; reapertura antes de G5 |
| F-X8-02 | P2 | ADR-001 B1 Fastify (Q-23) vs `node:http` + validador propio (AD-2) | ACCEPTED-IT0 (rev. 8 aceptada) | lampone-architect / lampone-security | ídem | Rev. 8 cerrada + revisión de seguridad de límites y validación antes de G5 |
| F-X8-03 | P1 | ADR-001 §1/ADR-006 §3 (servicios separados, stub sin DB) vs un proceso con stub in-process (AD-3). R-12 se debilita. LEGAL DECISION: evidencia de borrado | ACCEPTED-IT0 solo sintético (rev. 8 aceptada) | lampone-architect | ídem | ADR-010 aprobado e implementado antes de datos reales |
| F-X8-04 | P2 | ADR-001 §1 `platform/` vs estructura real (AD-4) | ACCEPTED-IT0 (rev. 8 aceptada) | lampone-architect | ídem | Rev. 8 cerrada |
| F-X8-05 | P2 | ADR-001 §3 CSP única vs 5 cabeceras distintas, una con `unsafe-inline` (PD-1) | OPEN | lampone-dev / lampone-security | ninguno | Política única + test exacto en CI |
| F-X8-06 | P2 | ADR-001 §6.1 lints vs ninguno (PD-2) | OPEN | lampone-dev | ninguno | Herramienta decidida por Carlos y regla en CI |
| F-X8-07 | P1 | ADR-001 §5 SBOM/SAST/secret/dependency scanning vs ausentes en CI (PD-3) | OPEN | lampone-security | ninguno | Jobs en CI en verde; bloquea datos reales/G5 |
| F-X8-08 | P2 | ADR-001 §5 allowlist con owner humano vs 2 deps `pending-human-review` (PD-4) | CLOSED (Carlos 2026-10-06; en PR docs/x8-registers-readmes) | Carlos | ninguno | Status `approved` firmado por un humano |
| F-X8-09 | P2 | ADR-001 §11 puertos ObjectStorage/KeyManagement/SecretStore/Clock vs ausentes; claves HMAC en config | OPEN | lampone-architect | ninguno | Puertos creados o diferidos por DEC antes de G5 |
| F-X8-10 | P1 | **Contradicción**: risk-register R-10 dice "verificador + step-up (aplicado)", pero no hay verificador ni doble control por DB (DF-4/7/8) y el step-up es presencia | OPEN | lampone-security → Carlos | ninguno | Texto de R-10 corregido; R-10 rechazado sin ADR-010 se mantiene |
| F-X8-11 | P1 | DEC-BR-014 §6 (owner NOLOGIN ≠ migrador) vs ledger de consent_owner (0000/0001/0002); residual: el migrador puede `SET ROLE integrity_owner` con control total y `consent_owner` (datdba) puede `DROP DATABASE` | Parte del owner: RESUELTO por PR #60 (0026/0027 + TEST-CNS-1230/1231). Residual: ACEPTADO solo IT0 sintético (Carlos, 2026-10-06, opción a); caduca antes de datos reales/G6 | lampone-dev | Carlos 2026-10-06 dec. 3 | CA-144 (ADR-010 break-glass, owner de BD separado, ancla externa); ver R-22 |
| F-X8-12 | P2 | ADR-002/006: esquemas pii/suppression/platform, roles y tablas DF-1…DF-13 ausentes | DEFERRED (a ADR-010 / IT0b) | lampone-architect | Carlos 2026-10-06 dec. 3 | Reapertura según tabla B; bloquea datos reales |
| F-X8-13 | P1 | SEC-CNS-006 V6/V6a (`ops.otp_budget`) vs sin presupuesto por clave (DF-10) | DEFERRED-IT0 | lampone-security | dec. 3 (DEFER) | Implementado antes de cualquier envío real de OTP |
| F-X8-14 | P2 | risk-register R-02 "con DLP … y CHECK de case_contact" vs DLP DEFERRED (R11-B6) y sin case_contact (DF-9) | OPEN | lampone-security | R11-B6 (DLP) | Texto de R-02 actualizado |
| F-X8-15 | P1 | Step-up RH2 interino: la presencia de `stepUpAssertion` cuenta como ATTESTED sin verificación criptográfica (`case-confirmation.handler.ts:295-297`; API-CNS-136/137/140). RH3 (API-CNS-138/139) **no tiene step-up** (OPEN-RV-10 OPEN) | ACCEPTED-IT0 LOCAL | lampone-security → Carlos | Carlos 2026-09-28 opción (ii) (solo RH2) | APR-IDP aprobado y aserción verificada; OPEN-RV-10 decidido; autoridad RH3 = **LEGAL DECISION** LD-03 |

Total: 15 FINDINGs (P1: 5, P2: 10, P0: 0). Ningún P0.

## Hallazgos añadidos

| ID | Sev. | Hallazgo (fuente A vs B) | Estado | Owner | Respaldo | Cierre |
|---|---|---|---|---|---|---|
| F-X8-16 | P2 | `.github/CODEOWNERS` tiene un único code owner humano; el segundo code owner de seguridad (ADR-001 §5/§11, allowlist de dependencias, guardrails) no está designado | DEFERRED-IT0b (2º code owner de seguridad para IT0b) | Carlos | Carlos 2026-10-06 (no se cambia CODEOWNERS en IT0) | Segundo code owner designado en `.github/CODEOWNERS` (PR con revisión de Carlos); antes de IT0b |

## Notas

- F-X8-10 (P1) es contradicción registro↔implementación; se corrige el texto de R-10 en `risk-register-IT0.md` (esta PR). El rechazo de R-10 para datos reales sin ADR-010 se mantiene.
- F-X8-14: se corrige el texto de R-02 en `risk-register-IT0.md` (esta PR); el FINDING sigue OPEN hasta que lo acuse el owner.
- F-X8-11: la remediación (migraciones 0026/0027, owner `integrity_owner` del ledger) quedó resuelta por la PR #60. Residual P1 (el migrador puede asumir `integrity_owner` con `SET ROLE` explícito y tener control total; `consent_owner` datdba puede `DROP DATABASE`): aceptado por Carlos el 2026-10-06 (opción a) solo para IT0 sintético; caduca antes de datos reales/G6 y se cierra en CA-144. Riesgo asociado: R-22.
- F-X8-08: las dos dependencias (`typescript` 6.0.3, `@types/node` 24.13.4) quedan `approved` en `tools/guardrails/dependency-allowlist.json` por Carlos el 2026-10-06 (revisor humano).
- F-X8-15: la decisión del 2026-09-28 cubre solo RH2; RH3 no tiene step-up (OPEN-RV-10). La autoridad de RH3 es LEGAL DECISION (LD-03).

## Nota de versión

- 2026-10-08 (lampone-dev): estados alineados a las decisiones de Carlos del 2026-10-06 (rev. 8 de ADR-001 aceptada para IT0; DEFER de ADR-002/006 a ADR-010/IT0b; 2º code owner a IT0b). F-X8-05/06/07 siguen OPEN (CSP, lints §6.1 y SBOM/SAST pendientes).
- 2026-10-06 (lampone-dev): creación del registro con los FINDINGs F-X8-01…F-X8-15 de la retrospectiva X8 (lampone-architect) y F-X8-16 (segundo code owner pendiente, decisión de Carlos 2026-10-06).
