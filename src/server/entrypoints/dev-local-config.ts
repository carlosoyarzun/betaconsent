// Gobierna: dev.ts (único consumidor en producción de este módulo). Constantes LOCAL-only
// extraídas a un archivo sin efectos secundarios (dev.ts sí los tiene: aborta con
// process.exit(1) fuera de LOCAL y arranca un server.listen al importarse) para que
// tests/integration/consent-flow/dev-local-config.test.ts (TEST-CNS-566) pueda validar, con
// `loadOtpPolicyConfig`/`loadDecisionRelationshipConfig` reales, los MISMOS valores que usa
// dev.ts, sin tener que ejecutar dev.ts como proceso. Bug corregido (Carlos, reporte CI):
// "IT0_SYNTHETIC_GUARDIAN" no cumplía `^[A-Z_]{1,40}$` (el "0" no es ni A-Z ni "_"); ningún
// test lo detectaba porque nada importaba estos valores fuera de dev.ts mismo.
//
// D4 / GRD-CD-04 (decision-relationship.config.ts, opción b de Carlos, 2026-09-27): sin default
// de producción; estos valores son LOCAL-only y nunca se usan fuera de dev.ts/tests.

/** P-01/P-02/P-03 (otp-policy.config.ts): sin valor aprobado en SEC-CNS-006, LOCAL-only. */
export const LOCAL_ONLY_DEV_OTP_POLICY = { codeLength: 6, ttlMs: 5 * 60_000, maxAttempts: 3, maxResends: 3 };

/** GRD-CD-04: enum legal real PENDING DEC-BR-003 / EXT-A / LD-01; debe cumplir el patrón del
 * contrato `^[A-Z_]{1,40}$` (solo A-Z y "_", sin dígitos). */
export const LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

/** P-15 (recovery-token-policy.config.ts): sin valor aprobado en SEC-CNS-006, LOCAL-only
 * (CA-116 PR 2, UX-CNS-004 recovery). 15 minutos es un valor sintético de conveniencia para
 * probar el flujo a mano, no una recomendación de producto. */
export const LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY = { ttlMs: 15 * 60_000 };

/** P-18 (recovery-handle-policy.config.ts, SEC-CNS-014): ADR-006 §6.2 fija 10 minutos para el
 * handle RECOVERY de la cookie `__Host-cns-recovery` (distinto de P-15, el TTL del token
 * persistido en BD). No es LOCAL-only por conveniencia: es el valor citado por el ADR, pero se
 * declara aquí igual que el resto de este archivo para que dev.ts y los tests compartan una
 * sola fuente. */
export const LOCAL_ONLY_DEV_RECOVERY_HANDLE_POLICY = { ttlMs: 10 * 60_000 };

/** LOCAL + CI / SYNTHETIC DATA ONLY — APR-IDP PENDING (Carlos, 2026-09-28, opción (ii); CA-128,
 * API-CNS-138): lista nominal de 4 personas ficticias, sin reutilización entre roles (NF-19,
 * GRD-RC-15) — 2 RIGHTS_OPERATOR y 2 APPROVER. Sin IdP real en IT0: dev.ts inyecta este roster
 * en StaffIdentityPort (in-memory-staff-identity.adapter.ts) y lo resuelve únicamente el
 * endpoint de desarrollo /__dev/staff-login (case-confirmation.handler.ts, LOCAL-only,
 * GRD-CM-13). Cero PII: solo refs opacas sintéticas, nunca email, nombre ni RUT. LEGAL DECISION
 * LD-03 (quién tiene autoridad legal para registrar/co-firmar RH3) no se decide aquí. */
export const LOCAL_ONLY_DEV_STAFF_ROSTER = [
  { principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" as const },
  { principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR" as const },
  { principalRef: "staff-synthetic-03", role: "APPROVER" as const },
  { principalRef: "staff-synthetic-04", role: "APPROVER" as const },
];
