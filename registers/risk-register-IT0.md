# Registro de riesgos — Iteración 0 (IT0)

Gobierna: SEC-CNS-005 (threat model IT0, scratchpad `SEC-threat-model-IT0.md` §5, rev. 5 ACCEPTED 2026-09-26 por Carlos, R11) · DEC-BR-014 (Iteración 0, ACCEPTED — scope IT0 sintético) · ADR-003 rev. 7 ACCEPTED 2026-09-26 (Deployment Target IT0).
Estado: ACCEPTED (Carlos, 2026-09-26). Cierre formal de SEC-CNS-005 en Notion pendiente; este registro traslada la tabla de aceptación de riesgos residuales que Carlos aprobó en chat (R6-7, R7-4, R7-6, R11-B1, R11-B4, 2026-09-25/26) para permitir G-IT0-ENTRY. No sustituye el threat model G5 completo, que sigue siendo requisito antes de cualquier dato real.

Cero PII en este documento.

## R-01 … R-15 (SEC-CNS-005 §5, literal)

| ID | Riesgo (amenaza) | Estado de aceptación para IT0 | Restricción para datos reales |
|---|---|---|---|
| R-01 | Enlace = credencial (T-06, F01) | Aceptado | **Rechazado** (LD-01) |
| R-02 | Tipeo de dato real (T-44) | Aceptado solo con congelamiento y avisos de UI. El DLP está DIFERIDO (CA-137, R11-B6) y `pii.case_contact` no existe (DF-9, fuera del slice IT0); no hay CHECK de `case_contact` (F-X8-14) | Re-evaluar en G5 |
| R-03 | Superusuario local / root del host (T-48; antes "del proveedor"; F18 = hecho) — re-alcanzado al host dedicado (R11-B1) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Con break-glass de A3 C17 y P-42 | **Rechazado** en producción; con datos reales en STAGING, reevaluar (R11-B4) Precisión (Carlos, 2026-10-08): 'datos reales' = titulares y terceros; los datos del equipo admitidos por LD-17 (a') se re-evalúan en PIA-STG-IT0b. |
| R-04 | Ledger sin HMAC ni ancla (T-37) | Solo NON-EVIDENTIARY | **Rechazado** (ADR-011) |
| R-05 | Retiro no querido por tercero con el buzón (T-21) | Aceptado | **Rechazado** (LD-04) |
| R-06 | DDoS volumétrico (T-17) | Aceptado (P-22) | Re-evaluar en G5 |
| R-07 | Cola humana sin SLA (T-24) | Aceptado con P-19/P-35 | Re-evaluar (LD-04) |
| R-08 | Dependencia maliciosa aprobada (T-05) | Aceptado | Re-evaluar en G5 |
| R-09 | RLS por GUC ante RCE (T-26) | Aceptado | **Rechazado** |
| R-10 | `platform` fabrica el doble control (T-52) | **Corregido (F-X8-10, F-X8-15):** no hay verificador ni doble control impuesto por la BD (DF-4/DF-7/DF-8 diferidos); todo corre en un solo proceso (AD-3). El step-up de RH2 es interino: cuenta la sola presencia de `stepUpAssertion`, sin verificación criptográfica (decisión de Carlos 2026-09-28, P1 hasta APR-IDP). RH3 no tiene step-up (OPEN-RV-10 abierto). Aceptado solo para IT0 sintético | **Rechazado** sin ADR-010 |
| R-11 | Un humano con dos principals (T-56) | Aceptado con `sub` único y lista atestada | Re-evaluar en G5 |
| R-12 | Stub propio no prueba borrado (T-57) | Aceptado | Re-evaluar con consumidor real |
| R-13 | Revocación HUMAN_ASSISTED inducida por portador sin buzón (T-51) | Aceptado | **Rechazado** (LD-02 + LD-04) |
| R-14 | Colusión por grant (FA-601): receptor + un aprobador completarían HUMAN_ASSISTED si el mismo aprobador aprobara RH2 | **Mitigado en IT0** (tercer humano, R7-4; acusado por Carlos) | Tercer humano es **condición**; sin él, rechazado. Re-evaluar en G5 |
| R-15 | Indisponibilidad del aprobador original (R7-5): el grant nuevo agrega otro aprobador a la exclusión de RH2 y, con 3 humanos, deja RH2 sin aprobador elegible (caso `overdue`, fail closed) | Aceptado para IT0 por Carlos (R7-6; disponibilidad, no integridad); re-evaluar antes de datos reales | Nómina con ≥4 elegibles o re-evaluar en G5 |

## R-16 … R-21 (SEC-CNS-005/008/009, rev. 5 ACCEPTED 2026-09-26)

| ID | Riesgo (amenaza) | Estado de aceptación para IT0 | Restricción para datos reales |
|---|---|---|---|
| R-16 | Administrador/root del host (dedicado, R11-B1) controla a la vez `platform`, `verifier`, DB (superusuario local), secretos, logs y sink; colapsa la separación de identidades de servicio y, con IdP co-alojado, el step-up de R6-4 (T-48, T-52) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Condiciones: IdP externo (P-36), C15/C3 y P-42 (aprobado R11-B3) | **Rechazado** sin separación de hosts/administradores o firma verificable en DB (ADR-010); reevaluar (R11-B4) Precisión (Carlos, 2026-10-08): 'datos reales' = titulares y terceros; los datos del equipo admitidos por LD-17 (a') se re-evalúan en PIA-STG-IT0b. |
| R-17 | Co-tenencia con studio.lectorpro.cl (host, red, proxy, relay SMTP o administradores comunes) | **N/A (host dedicado, R11-B1)** | N/A mientras el host sea dedicado; cualquier co-tenencia futura exige excepción formal a MP §2 (vuelve a Carlos) |
| R-18 | Backups autogestionados: pérdida (copia en el mismo host) o exposición (passphrase en el mismo host) (A3 C5) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** La DB se recrea; P-39 (aprobado R11-B3) | Re-evaluar en G5 con ADR-009; supresión en backups LD-14 Precisión (Carlos, 2026-10-08): 'datos reales' = titulares y terceros; los datos del equipo admitidos por LD-17 (a') se re-evalúan en PIA-STG-IT0b. |
| R-19 | CDN/proxy de tercero ve tokens en URL, solo si el patrón studio lo usa (T-01; A3 C11) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Con logs de ruta desactivados (P-22) | **LEGAL DECISION** (LD-16) + P1 Precisión (Carlos, 2026-10-08): 'datos reales' = titulares y terceros; los datos del equipo admitidos por LD-17 (a') se re-evalúan en PIA-STG-IT0b. |
| R-20 | Parcheo y hardening dependen del equipo (sin proveedor); logs en el host alterables por root (A3 C12, C13) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Con P-41/P-42 (aprobados R11-B3), non-evidentiary | Re-evaluar en G5; `AuditStore` fuera del host obligatorio Precisión (Carlos, 2026-10-08): 'datos reales' = titulares y terceros; los datos del equipo admitidos por LD-17 (a') se re-evalúan en PIA-STG-IT0b. |
| R-21 | RCE en `web` o `platform` → exfiltración o C2 por el túnel `CONNECT` permitido hacia el FQDN del IdP (token endpoint y JWKS del mismo FQDN); la allowlist fija el destino, no el comportamiento (domain fronting dentro del mismo SNI, canal encubierto por tamaño/tiempo, tenant propio en IdP multi-tenant); el proxy no inspecciona TLS | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Con M2 (red por cliente, identidad por red), M4 (SNI = CONNECT, ACL antes de resolver, límites de bytes/duración/concurrencia/tasa de P-45 — **P-45 no aprobado, sin valores, R11-B3**), log/alerta ante rechazo | **Rechazado** para datos reales sin re-evaluación (interceptar TLS solo en el proxy, o IdP autoalojado en la red interna); re-evaluar antes de datos reales y en G5 Precisión (Carlos, 2026-10-08): 'datos reales' = titulares y terceros; los datos del equipo admitidos por LD-17 (a') se re-evalúan en PIA-STG-IT0b. |
| R-22 | Ledger: el migrador puede `SET ROLE integrity_owner` y tiene control total (DISABLE TRIGGER, CREATE OR REPLACE de la función, DROP); `consent_owner` es datdba y puede `DROP DATABASE`; la cadena SHA-256 sin ancla externa no detecta reescritura con hashes recalculados (F-X8-11; ver R-04) | **Aceptado solo para IT0 sintético por Carlos (2026-10-06, opción a); no se hereda a STAGING con datos reales ni a producción.** Parte del owner resuelta por PR #60 | Caduca antes de datos reales/G6. Cierre: CA-144 (ADR-010 break-glass, owner de BD separado, ancla externa); sin ello, rechazado (R-04 ya rechazado para datos reales) |

## Notas de aceptación (Carlos, 2026-09-25, chat; SEC-CNS-005 §5)

- Aceptación **para IT0 sintético** de R-01…R-13 según SEC-review-5 §5 (a).
- **Rechazados para datos reales:** R-01, R-04, R-05, R-09, R-10, R-13.
- R-02, R-06, R-07, R-08, R-11 y R-12 **no quedan aceptados por extensión** para datos reales: se re-evalúan en G5.
- **R-14:** no lo cubre R6-7; acusado explícitamente por Carlos (R7-4) y mitigado en IT0 por el tercer humano (receptor del grant, aprobador del grant y aprobador de RH2, los tres distintos).
- **R-15:** aceptado para IT0 por Carlos (R7-6); es un riesgo de disponibilidad, no de integridad (el caso queda `overdue`, fail-closed); mitigación futura: nómina con ≥4 elegibles.
- **R-03** (re-alcanzado: "superusuario del proveedor gestionado" → "superusuario local / root del host"), **R-16, R-18, R-19, R-20 y R-21: aceptados solo para IT0 sintético por Carlos (R11-B4, 2026-09-26)**, con M2/M4 y demás mitigaciones documentadas en SEC-CNS-005/008/009; no se heredan a STAGING con datos reales ni a producción; el rechazo para datos reales se mantiene.
- **R-17: N/A** (host dedicado para Consent App, separado de studio; R11-B1). El rechazo para datos reales de R-01, R-04, R-05, R-09, R-10 y R-13 se mantiene sin cambios.

- **Precisión LD-17/LD-18/LD-19 (Carlos, 2026-10-08):** aplica a R-03, R-16, R-18, R-19, R-20 y R-21: Precisión (Carlos, 2026-10-08): 'datos reales' = titulares y terceros; los datos del equipo admitidos por LD-17 (a') se re-evalúan en PIA-STG-IT0b. Ref.: LD-17, LD-18, LD-19.

## Pendiente

- Cierre formal de SEC-CNS-005 y su re-emisión en Notion, con registro de este mismo estado (DEC-BR-014 §2 E1).
- Ningún riesgo de esta tabla habilita el uso de datos personales reales (SEC F01, Master Plan §54).

## Nota de versión

- 2026-09-26 (lampone-dev, R11 aprobado por Carlos): incorpora SEC-threat-model-IT0.md §5 rev. 5 ACCEPTED 2026-09-26. R-03 re-alcanzado a "superusuario local / root del host" (antes "del proveedor gestionado"); R-16, R-18, R-19, R-20 y R-21 agregados y aceptados solo para IT0 sintético (R11-B4); R-17 agregado como N/A (host dedicado, R11-B1). Se mantiene el rechazo de todos estos riesgos para datos reales/STAGING con datos reales/producción.
- 2026-10-06 (lampone-dev, Carlos): estado ACCEPTED; R-10 corregido a lo implementado (F-X8-10, F-X8-15) y R-02 alineado con DLP diferido y sin `case_contact` (F-X8-14). Ver `findings-register-IT0.md`.
