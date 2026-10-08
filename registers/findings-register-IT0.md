# Registro de FINDINGs — Iteración 0 (IT0)

Gobierna: ADR-001 rev. 7 (ACCEPTED IT0 LOCAL+CI; enmienda rev. 8 ACEPTADA para IT0 (Carlos, 2026-10-06): AD-1..AD-4; pendientes CSP, lints §6.1 y SBOM/SAST) · ADR-002/006 r6 · SEC-CNS-005 rev. 5 · DEC-BR-014 (Iteración 0) · Master Plan §36 (Contradiction Protocol). Origen: retrospectiva X8 (lampone-architect, 2026-10-06); decisiones 2, 3 y 5 confirmadas por Carlos el 2026-10-06.
Estado: registrado por decisión de Carlos del 2026-10-06 ("registrar desvíos y step-up interino como FINDING en registers/"); el estado de cada hallazgo está en la columna Estado. Los desvíos AD-1…AD-4 se detallan en la enmienda ADR-001 rev. 8 (Notion). DF-1…DF-13 (DEFER de ADR-002/006, no de ADR-001): detalle en la sección «DF-1…DF-13» más abajo; origen DEC-BR-019 (Notion).

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
| F-X8-09 | P2 | ADR-001 §11 puertos ObjectStorage/KeyManagement/SecretStore/Clock vs ausentes; claves HMAC en config | DEFERRED-IT0b (Carlos, 2026-10-08) | lampone-architect | Carlos 2026-10-08 (no afectan IT0 sintético) | Puertos creados o diferidos por DEC antes de G5 |
| F-X8-10 | P1 | **Contradicción**: risk-register R-10 dice "verificador + step-up (aplicado)", pero no hay verificador ni doble control por DB (DF-4/7/8) y el step-up es presencia | DEFERRED-IT0b (Carlos, 2026-10-08) | lampone-security → Carlos | Carlos 2026-10-08 (no afectan IT0 sintético) | Texto de R-10 corregido; R-10 rechazado sin ADR-010 se mantiene |
| F-X8-11 | P1 | DEC-BR-014 §6 (owner NOLOGIN ≠ migrador) vs ledger de consent_owner (0000/0001/0002); residual: el migrador puede `SET ROLE integrity_owner` con control total y `consent_owner` (datdba) puede `DROP DATABASE` | Parte del owner: RESUELTO por PR #60 (0026/0027 + TEST-CNS-1230/1231). Residual: ACEPTADO solo IT0 sintético (Carlos, 2026-10-06, opción a); caduca antes de datos reales/G6 | lampone-dev | Carlos 2026-10-06 dec. 3 | CA-144 (ADR-010 break-glass, owner de BD separado, ancla externa); ver R-22 |
| F-X8-12 | P2 | ADR-002/006: esquemas pii/suppression/platform, roles y tablas DF-1…DF-13 ausentes | DEFERRED (a ADR-010 / IT0b) | lampone-architect | Carlos 2026-10-06 dec. 3 | Reapertura según tabla B; bloquea datos reales |
| F-X8-13 | P1 | SEC-CNS-006 V6/V6a (`ops.otp_budget`) vs sin presupuesto por clave (DF-10) | DEFERRED-IT0b (Carlos, 2026-10-08) | lampone-security | dec. 3 (DEFER) | Implementado antes de cualquier envío real de OTP. CA-146 |
| F-X8-14 | P2 | risk-register R-02 "con DLP … y CHECK de case_contact" vs DLP DEFERRED (R11-B6) y sin case_contact (DF-9) | DEFERRED-IT0b (Carlos, 2026-10-08) | lampone-security | R11-B6 (DLP); Carlos 2026-10-08 (no afectan IT0 sintético) | Texto de R-02 actualizado |
| F-X8-15 | P1 | Step-up RH2 interino: la presencia de `stepUpAssertion` cuenta como ATTESTED sin verificación criptográfica (`case-confirmation.handler.ts:295-297`; API-CNS-136/137/140). RH3 (API-CNS-138/139) **no tiene step-up** (OPEN-RV-10 OPEN) | ACCEPTED-IT0 LOCAL | lampone-security → Carlos | Carlos 2026-09-28 opción (ii) (solo RH2) | APR-IDP aprobado y aserción verificada; OPEN-RV-10 decidido; autoridad RH3 = **LEGAL DECISION** LD-03 |

Total: 15 FINDINGs (P1: 5, P2: 10, P0: 0). Ningún P0.

## DF-1…DF-13 (DEFER de ADR-002/006 hacia ADR-010 y IT0b)

Fuentes: S1 = DEC-BR-019 (https://app.notion.com/p/3edee09a7fbc8197aed6c9748aa87124), sección "2026-10-06 — Cierre X7/X8", subsección "DEFER de ADR-002/006 hacia ADR-010 y IT0b". S2 = borrador x8-adr-findings.md §B (lampone-architect, 2026-10-06, base fee70d4; ya no existe como archivo). Severidad = la del FINDING que cubre cada DF. Ningún DF tiene ticket CA propio. Notion (DEC-BR-019, verificada en vivo 2026-10-08, última edición 2026-10-06T19:31Z) solo registra Ítem, Depende de y Se reabre en; Severidad y Estado vienen de este registro (F-X8-10/12/13/14; decisiones de Carlos 2026-10-06 dec. 3 y 2026-10-08, PR #71) y la descripción del borrador S2. El enlace de DEC-BR-019 a x8-adr-findings.md está roto; esta sección lo sustituye.

| ID | Título | Descripción | Fuente | Severidad | Estado | Ticket |
|---|---|---|---|---|---|---|
| DF-1 | Esquema `pii` (canal, channel_hmac, network_signal) | Objetos (borrador S2): `v_case_contact`. Datos de contacto aislados, a futuro en instancia aparte. IT0 usa email reservado en `app.invitation` (EXT-B (i)). Depende de: LD-03, EXT-B, instancia pii (LD-15 según borrador S2) | S1; S2 §B | P2 (F-X8-12) | DEFERRED (dec. 3). Reabre: antes de datos reales; historia IT1 | — |
| DF-2 | Esquema `suppression` (lista de no contacto) | Objetos (borrador S2): `suppression_owner`, tombstone. Supresión y no contacto. IT0 sin proceso de supresión; BD se recrea. Depende de LD-13/14 y ADR-009 | S1; S2 §B | P2 (F-X8-12) | DEFERRED (dec. 3). Reabre en G5 / ADR-009 | — |
| DF-3 | Esquema `platform` (asignación de roles) | Objetos (borrador S2): `platform_role_assignment`. Roles de plataforma impuestos por BD. IT0 usa roster fixture (0018/0019) y un solo proceso (AD-3). Depende de APR-IDP y ADR-010 | S1; S2 §B | P2 (F-X8-12) | DEFERRED (dec. 3). Reabre en ADR-010; IT0b si hay IdP | — |
| DF-4 | Rol `integrity_verifier` • servicio verificador | Atestar aserciones del IdP (INV-13) y verificación independiente de la cadena. Hoy solo CLI como `app_rw` (`src/infra/adapters/postgres/ledger-verify-cli.ts`). Depende de: APR-IDP, ADR-010, ADR-011 | S1; S2 §B; risk-register R-10 | P1 (F-X8-10) | DEFERRED-IT0b (Carlos 2026-10-08). Reabre en ADR-010, antes de datos reales | — |
| DF-5 | Rol de DB `rights_operator` | Operador de derechos con grants propios. Hoy en dominio con sesión CASE + roster. Depende de DF-7 y ADR-010 | S1; S2 §B | P2 (F-X8-12) | DEFERRED (dec. 3). Reabre en ADR-010 | — |
| DF-6 | Rol `diagnostic_reader` y grants | Objetos (borrador S2): `diagnostic_grant`. Lectura de diagnóstico acotada con grant. Sin soporte/diagnóstico en IT0. Depende de ADR-010 y LD-03 | S1; S2 §B | P2 (F-X8-12) | DEFERRED (dec. 3). Reabre en IT1 / G5 | — |
| DF-7 | Tablas de grant y aserción | Objetos (borrador S2): `grant_request`, `rights_case_grant`, `grant_assertion`, `case_verification`, `resolve_case_grants`. Grants por caso y aserciones IdP como hash. RH2 vive en `app.revocation`/`rights_case` (0016) con step-up interino | S1; S2 §B; risk-register R-10 | P1 (F-X8-10) | DEFERRED-IT0b (Carlos 2026-10-08). Reabre en ADR-010 | — |
| DF-8 | Doble control impuesto por DB | Frente a web/worker. Ningún proceso fabrica RH2 o un grant solo. Hoy RH2 (3 humanos) se impone en un solo proceso (AD-3). Depende de: DF-3, DF-4, DF-7, procesos separados | S1; S2 §B; risk-register R-10 | P1 (F-X8-10) | DEFERRED-IT0b. **Condición antes de datos reales** (R-10 rechazado sin ADR-010) | CA-145 |
| DF-9 | `pii.case_contact` | Contacto opcional si canal inalcanzable (GRD-RC-05). Rama CHANNEL_UNREACHABLE fuera del slice (`src/server/modules/rights-case/rights-case.ts:7`) | S1; S2 §B | P2 (F-X8-14) | DEFERRED-IT0b (Carlos 2026-10-08). Reabre en historia rights-case completa (IT1) | — |
| DF-10 | `ops.otp_budget` (presupuesto OTP) | Presupuesto OTP por clave (V6/V6a de SEC-CNS-006). Hoy solo intentos por challenge (`src/server/modules/otp-challenge/otp-challenge.ts:6`) | S1; S2 §B | P1 (F-X8-13) | DEFERRED-IT0b (F-X8-13; Carlos 2026-10-08). **Antes de datos reales**; IT0b si hay envío real | CA-146 |
| DF-11 | `authorization_check` | Registro/decisión de autorización por acción. Hoy guardas en dominio, registro en `access_log`/`security_event` | S1; S2 §B | P2 (F-X8-12) | DEFERRED (dec. 3). Reabre en ADR-010 | — |
| DF-12 | `tenant_membership` / pertenencia staff↔tenant | Objetos (borrador S2): `resolve_tenant_memberships`, `list_tenants_for`. Pertenencia staff↔tenant impuesta por BD. Hoy roster fixture + sesión STAFF ligada a tenant. Depende de APR-IDP y DF-3 | S1; S2 §B | P2 (F-X8-12) | DEFERRED (dec. 3). Reabre en IT0b (IdP) / ADR-010 | — |
| DF-13 | Roles `grant_owner`, `tenant_resolver` | Dueños/resolutores de DF-7/DF-12; no existen porque sus tablas no existen | S1; S2 §B | P2 (F-X8-12) | DEFERRED (dec. 3). Reabre en ADR-010 | — |

Vocabulario de estado (Carlos, 2026-10-08): DEFERRED-IT0b para los que se retoman en IT0b; los que reabren en ADR-010, G5 o IT1 conservan 'DEFERRED (dec. 3)' con su destino. Tickets: CA-145 (DF-8), CA-146 (DF-10), ambos relacionados con CA-144.

## Hallazgos añadidos

| ID | Sev. | Hallazgo (fuente A vs B) | Estado | Owner | Respaldo | Cierre |
|---|---|---|---|---|---|---|
| F-X8-16 | P2 | `.github/CODEOWNERS` tiene un único code owner humano; el segundo code owner de seguridad (ADR-001 §5/§11, allowlist de dependencias, guardrails) no está designado | DEFERRED-IT0b (2º code owner de seguridad para IT0b) | Carlos | Carlos 2026-10-06 (no se cambia CODEOWNERS en IT0) | Segundo code owner designado en `.github/CODEOWNERS` (PR con revisión de Carlos); antes de IT0b |

## Notas

- F-X8-10 (P1) es contradicción registro↔implementación; se corrige el texto de R-10 en `risk-register-IT0.md` (esta PR). El rechazo de R-10 para datos reales sin ADR-010 se mantiene.
- F-X8-14: se corrige el texto de R-02 en `risk-register-IT0.md` (esta PR); el FINDING quedó DEFERRED-IT0b (Carlos, 2026-10-08; no afecta IT0 sintético).
- F-X8-11: la remediación (migraciones 0026/0027, owner `integrity_owner` del ledger) quedó resuelta por la PR #60. Residual P1 (el migrador puede asumir `integrity_owner` con `SET ROLE` explícito y tener control total; `consent_owner` datdba puede `DROP DATABASE`): aceptado por Carlos el 2026-10-06 (opción a) solo para IT0 sintético; caduca antes de datos reales/G6 y se cierra en CA-144. Riesgo asociado: R-22.
- F-X8-08: las dos dependencias (`typescript` 6.0.3, `@types/node` 24.13.4) quedan `approved` en `tools/guardrails/dependency-allowlist.json` por Carlos el 2026-10-06 (revisor humano).
- F-X8-15: la decisión del 2026-09-28 cubre solo RH2; RH3 no tiene step-up (OPEN-RV-10). La autoridad de RH3 es LEGAL DECISION (LD-03).

## Nota de versión

- 2026-10-08 (lampone-dev, Carlos): F-X8-09, F-X8-10 y F-X8-14 pasan de OPEN a DEFERRED-IT0b por decisión de Carlos (no afectan IT0 sintético). R-10 y R-02 del risk-register no cambian de estado.
- 2026-10-08 (lampone-dev): estados alineados a las decisiones de Carlos del 2026-10-06 (rev. 8 de ADR-001 aceptada para IT0; DEFER de ADR-002/006 a ADR-010/IT0b; 2º code owner a IT0b). F-X8-05/06/07 siguen OPEN (CSP, lints §6.1 y SBOM/SAST pendientes).
- 2026-10-06 (lampone-dev): creación del registro con los FINDINGs F-X8-01…F-X8-15 de la retrospectiva X8 (lampone-architect) y F-X8-16 (segundo code owner pendiente, decisión de Carlos 2026-10-06).
