# Registro de riesgos — Iteración 0 (IT0)

Gobierna: SEC-CNS-005 (threat model IT0, scratchpad `SEC-threat-model-IT0.md` §5, rev. 5 ACCEPTED 2026-09-26 por Carlos, R11) · DEC-BR-014 (Iteración 0, ACCEPTED — scope IT0 sintético) · ADR-003 rev. 7 ACCEPTED 2026-09-26 (Deployment Target IT0).
Estado: PROPOSED. Cierre formal de SEC-CNS-005 pendiente; este registro traslada la tabla de aceptación de riesgos residuales que Carlos aprobó en chat (R6-7, R7-4, R7-6, R11-B1, R11-B4, 2026-09-25/26) para permitir G-IT0-ENTRY. No sustituye el threat model G5 completo, que sigue siendo requisito antes de cualquier dato real.

Cero PII en este documento.

## R-01 … R-15 (SEC-CNS-005 §5, literal)

| ID | Riesgo (amenaza) | Estado de aceptación para IT0 | Restricción para datos reales |
|---|---|---|---|
| R-01 | Enlace = credencial (T-06, F01) | Aceptado | **Rechazado** (LD-01) |
| R-02 | Tipeo de dato real (T-44) | Aceptado con DLP, congelamiento y CHECK de `case_contact` | Re-evaluar en G5 |
| R-03 | Superusuario local / root del host (T-48; antes "del proveedor"; F18 = hecho) — re-alcanzado al host dedicado (R11-B1) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Con break-glass de A3 C17 y P-42 | **Rechazado** en producción; con datos reales en STAGING, reevaluar (R11-B4) |
| R-04 | Ledger sin HMAC ni ancla (T-37) | Solo NON-EVIDENTIARY | **Rechazado** (ADR-011) |
| R-05 | Retiro no querido por tercero con el buzón (T-21) | Aceptado | **Rechazado** (LD-04) |
| R-06 | DDoS volumétrico (T-17) | Aceptado (P-22) | Re-evaluar en G5 |
| R-07 | Cola humana sin SLA (T-24) | Aceptado con P-19/P-35 | Re-evaluar (LD-04) |
| R-08 | Dependencia maliciosa aprobada (T-05) | Aceptado | Re-evaluar en G5 |
| R-09 | RLS por GUC ante RCE (T-26) | Aceptado | **Rechazado** |
| R-10 | `platform` fabrica el doble control (T-52) | Solo con verificador + step-up (aplicado) | **Rechazado** sin ADR-010 |
| R-11 | Un humano con dos principals (T-56) | Aceptado con `sub` único y lista atestada | Re-evaluar en G5 |
| R-12 | Stub propio no prueba borrado (T-57) | Aceptado | Re-evaluar con consumidor real |
| R-13 | Revocación HUMAN_ASSISTED inducida por portador sin buzón (T-51) | Aceptado | **Rechazado** (LD-02 + LD-04) |
| R-14 | Colusión por grant (FA-601): receptor + un aprobador completarían HUMAN_ASSISTED si el mismo aprobador aprobara RH2 | **Mitigado en IT0** (tercer humano, R7-4; acusado por Carlos) | Tercer humano es **condición**; sin él, rechazado. Re-evaluar en G5 |
| R-15 | Indisponibilidad del aprobador original (R7-5): el grant nuevo agrega otro aprobador a la exclusión de RH2 y, con 3 humanos, deja RH2 sin aprobador elegible (caso `overdue`, fail closed) | Aceptado para IT0 por Carlos (R7-6; disponibilidad, no integridad); re-evaluar antes de datos reales | Nómina con ≥4 elegibles o re-evaluar en G5 |

## R-16 … R-21 (SEC-CNS-005/008/009, rev. 5 ACCEPTED 2026-09-26)

| ID | Riesgo (amenaza) | Estado de aceptación para IT0 | Restricción para datos reales |
|---|---|---|---|
| R-16 | Administrador/root del host (dedicado, R11-B1) controla a la vez `platform`, `verifier`, DB (superusuario local), secretos, logs y sink; colapsa la separación de identidades de servicio y, con IdP co-alojado, el step-up de R6-4 (T-48, T-52) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Condiciones: IdP externo (P-36), C15/C3 y P-42 (aprobado R11-B3) | **Rechazado** sin separación de hosts/administradores o firma verificable en DB (ADR-010); reevaluar (R11-B4) |
| R-17 | Co-tenencia con studio.lectorpro.cl (host, red, proxy, relay SMTP o administradores comunes) | **N/A (host dedicado, R11-B1)** | N/A mientras el host sea dedicado; cualquier co-tenencia futura exige excepción formal a MP §2 (vuelve a Carlos) |
| R-18 | Backups autogestionados: pérdida (copia en el mismo host) o exposición (passphrase en el mismo host) (A3 C5) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** La DB se recrea; P-39 (aprobado R11-B3) | Re-evaluar en G5 con ADR-009; supresión en backups LD-14 |
| R-19 | CDN/proxy de tercero ve tokens en URL, solo si el patrón studio lo usa (T-01; A3 C11) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Con logs de ruta desactivados (P-22) | **LEGAL DECISION** (LD-16) + P1 |
| R-20 | Parcheo y hardening dependen del equipo (sin proveedor); logs en el host alterables por root (A3 C12, C13) | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Con P-41/P-42 (aprobados R11-B3), non-evidentiary | Re-evaluar en G5; `AuditStore` fuera del host obligatorio |
| R-21 | RCE en `web` o `platform` → exfiltración o C2 por el túnel `CONNECT` permitido hacia el FQDN del IdP (token endpoint y JWKS del mismo FQDN); la allowlist fija el destino, no el comportamiento (domain fronting dentro del mismo SNI, canal encubierto por tamaño/tiempo, tenant propio en IdP multi-tenant); el proxy no inspecciona TLS | **Aceptado solo para IT0 sintético por Carlos (R11-B4, 2026-09-26); no se hereda a STAGING con datos reales ni a producción.** Con M2 (red por cliente, identidad por red), M4 (SNI = CONNECT, ACL antes de resolver, límites de bytes/duración/concurrencia/tasa de P-45 — **P-45 no aprobado, sin valores, R11-B3**), log/alerta ante rechazo | **Rechazado** para datos reales sin re-evaluación (interceptar TLS solo en el proxy, o IdP autoalojado en la red interna); re-evaluar antes de datos reales y en G5 |

## Notas de aceptación (Carlos, 2026-09-25, chat; SEC-CNS-005 §5)

- Aceptación **para IT0 sintético** de R-01…R-13 según SEC-review-5 §5 (a).
- **Rechazados para datos reales:** R-01, R-04, R-05, R-09, R-10, R-13.
- R-02, R-06, R-07, R-08, R-11 y R-12 **no quedan aceptados por extensión** para datos reales: se re-evalúan en G5.
- **R-14:** no lo cubre R6-7; acusado explícitamente por Carlos (R7-4) y mitigado en IT0 por el tercer humano (receptor del grant, aprobador del grant y aprobador de RH2, los tres distintos).
- **R-15:** aceptado para IT0 por Carlos (R7-6); es un riesgo de disponibilidad, no de integridad (el caso queda `overdue`, fail-closed); mitigación futura: nómina con ≥4 elegibles.
- **R-03** (re-alcanzado: "superusuario del proveedor gestionado" → "superusuario local / root del host"), **R-16, R-18, R-19, R-20 y R-21: aceptados solo para IT0 sintético por Carlos (R11-B4, 2026-09-26)**, con M2/M4 y demás mitigaciones documentadas en SEC-CNS-005/008/009; no se heredan a STAGING con datos reales ni a producción; el rechazo para datos reales se mantiene.
- **R-17: N/A** (host dedicado para Consent App, separado de studio; R11-B1). El rechazo para datos reales de R-01, R-04, R-05, R-09, R-10 y R-13 se mantiene sin cambios.

## Pendiente

- Cierre formal de SEC-CNS-005 y su re-emisión en Notion, con registro de este mismo estado (DEC-BR-014 §2 E1).
- Ningún riesgo de esta tabla habilita el uso de datos personales reales (SEC F01, Master Plan §54).

## Nota de versión

- 2026-09-26 (lampone-dev, R11 aprobado por Carlos): incorpora SEC-threat-model-IT0.md §5 rev. 5 ACCEPTED 2026-09-26. R-03 re-alcanzado a "superusuario local / root del host" (antes "del proveedor gestionado"); R-16, R-18, R-19, R-20 y R-21 agregados y aceptados solo para IT0 sintético (R11-B4); R-17 agregado como N/A (host dedicado, R11-B1). Se mantiene el rechazo de todos estos riesgos para datos reales/STAGING con datos reales/producción.
