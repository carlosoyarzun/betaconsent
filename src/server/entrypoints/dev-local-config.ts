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
