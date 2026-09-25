# Registro de riesgos — Iteración 0 (IT0)

Gobierna: SEC-CNS-005 (threat model IT0, scratchpad `SEC-threat-model-IT0.md` §5) · DEC-BR-014 (Iteración 0, ACCEPTED — scope IT0 sintético).
Estado: PROPOSED. Cierre formal de SEC-CNS-005 pendiente; este registro traslada la tabla de aceptación de riesgos residuales que Carlos aprobó en chat (R6-7, R7-4, R7-6, 2026-09-25) para permitir G-IT0-ENTRY. No sustituye el threat model G5 completo, que sigue siendo requisito antes de cualquier dato real.

Cero PII en este documento.

## R-01 … R-15 (SEC-CNS-005 §5, literal)

| ID | Riesgo (amenaza) | Estado de aceptación para IT0 | Restricción para datos reales |
|---|---|---|---|
| R-01 | Enlace = credencial (T-06, F01) | Aceptado | **Rechazado** (LD-01) |
| R-02 | Tipeo de dato real (T-44) | Aceptado con DLP, congelamiento y CHECK de `case_contact` | Re-evaluar en G5 |
| R-03 | Superusuario del proveedor gestionado (T-48) | Solo staging sintético (Q-27) o verificado en X5 | **Rechazado** en producción |
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

## Notas de aceptación (Carlos, 2026-09-25, chat; SEC-CNS-005 §5)

- Aceptación **para IT0 sintético** de R-01…R-13 según SEC-review-5 §5 (a).
- **Rechazados para datos reales:** R-01, R-04, R-05, R-09, R-10, R-13.
- **R-03 aceptado solo en staging sintético** (Q-27).
- R-02, R-06, R-07, R-08, R-11 y R-12 **no quedan aceptados por extensión** para datos reales: se re-evalúan en G5.
- **R-14:** no lo cubre R6-7; acusado explícitamente por Carlos (R7-4) y mitigado en IT0 por el tercer humano (receptor del grant, aprobador del grant y aprobador de RH2, los tres distintos).
- **R-15:** aceptado para IT0 por Carlos (R7-6); es un riesgo de disponibilidad, no de integridad (el caso queda `overdue`, fail-closed); mitigación futura: nómina con ≥4 elegibles.

## Pendiente

- Cierre formal de SEC-CNS-005 y su re-emisión en Notion, con registro de este mismo estado (DEC-BR-014 §2 E1).
- Ningún riesgo de esta tabla habilita el uso de datos personales reales (SEC F01, Master Plan §54).
