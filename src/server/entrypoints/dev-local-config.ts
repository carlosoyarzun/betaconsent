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

import {
  APPROVED_LINK_HANDLE_TTL_MS,
  APPROVED_P10_INVITATION_EXPIRES_IN_MS,
  APPROVED_P33_IDEMPOTENCY_TTL_MS,
} from "../modules/common/approved-parameters.ts";

/** P-01/P-02/P-03 (otp-policy.config.ts): sin valor aprobado en SEC-CNS-006, LOCAL-only. */
export const LOCAL_ONLY_DEV_OTP_POLICY = { codeLength: 6, ttlMs: 5 * 60_000, maxAttempts: 3, maxResends: 3 };

/** P-33 (idempotency-policy.config.ts, GRD-CM-08): TTL de la Idempotency-Key = 24 h, APROBADO
 * (Carlos, 2026-10-01); vale en cualquier entorno (approved-parameters.ts). */
export const LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY = { ttlMs: APPROVED_P33_IDEMPOTENCY_TTL_MS };

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

/** SEC-CNS-014 patrón (Carlos, 2026-09-28), link-handle.ts/invitation-handle-policy.config.ts:
 * TTL de la cookie `__Host-cns-i-handle` que fija GET /i/{token} sin leer la BD. Solo necesita
 * sobrevivir el 303 inmediato a GET /welcome; 10 minutos es un valor sintético de conveniencia,
 * no una recomendación de producto (mismo criterio LOCAL-only que el resto de este archivo). */
export const LOCAL_ONLY_DEV_INVITATION_HANDLE_POLICY = { ttlMs: 10 * 60_000 };

/** SEC-CNS-014 patrón (Carlos, 2026-09-28), link-handle.ts/manage-handle-policy.config.ts: TTL
 * de la cookie `__Host-cns-m-handle` que fija GET /m/{token} sin leer la BD. Mismo criterio
 * LOCAL-only que arriba. TTL 10 min APROBADO (Carlos, 2026-10-01; approved-parameters.ts). Pasa como
 * override explícito porque manage-handle-policy.config.ts (modules/revocation/*) no se toca en CA-128. */
export const LOCAL_ONLY_DEV_MANAGE_HANDLE_POLICY = { ttlMs: APPROVED_LINK_HANDLE_TTL_MS };

/** Refs opacas sintéticas de dev.ts (LOCAL-only): TenantRef/Ref válidos contra common.schema.json
 * (:27, :35), porque viajan tal cual en el sobre de consent.revoked (CA-127). */
export const LOCAL_ONLY_DEV_TENANT_ID = "c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48";
export const LOCAL_ONLY_DEV_SUBJECT_REF = "e8d2b4a6-3c19-4f75-b6e0-1a9c7d5f3b82";

/** Otro colegio (tenant distinto), solo para probar el aislamiento por tenant de la consola STAFF. */
export const LOCAL_ONLY_DEV_OTHER_TENANT_ID = "5d2e8a1c-6b3f-4d97-9c04-7e1a3b5d9f20";

/** CA-125 (LOCAL-only, SYNTHETIC DATA ONLY): refs UUIDv4 del sujeto, la SchoolParticipation y el
 * canal esperado del destinatario que dev.ts siembra en el catálogo del tenant de dev (IT0 no
 * tiene todavía un flujo de alta de sujetos ni participaciones: FINDING P1). Cero PII. */
export const LOCAL_ONLY_DEV_STAFF_SUBJECT_REF = "b7c3d1e5-2a48-4f96-8d10-6e9f0a2c4b73";
export const LOCAL_ONLY_DEV_PARTICIPATION_REF = "d4f8a2c6-7b13-4e59-a8c2-0f3d5b7e9a14";
export const LOCAL_ONLY_DEV_STAFF_CHANNEL_REF = "f1a5c9e3-4d27-4b68-9e30-2c4e6a8b0d51";

/** CA-125: P-10 (vigencia de la invitación = 7 días, APROBADO, Carlos 2026-10-01) y deliveryChannel
 * (EXT-B / F-014, DEC-BR-014 §7: sigue sin aprobar; valor LOCAL-only para el sink de dev, sin salida
 * de red). EXT-B (a), Carlos 2026-10-01: IT0 permite invitaciones UNBOUND y no tiene tabla de canales. */
export const LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY = {
  expiresInMs: APPROVED_P10_INVITATION_EXPIRES_IN_MS,
  deliveryChannel: "CONSENT_APP_EMAIL" as const,
};

/** LOCAL + CI / SYNTHETIC DATA ONLY — APR-IDP PENDING (Carlos, 2026-09-28, opción (ii); CA-128,
 * API-CNS-138): lista nominal de 4 personas ficticias, sin reutilización entre roles (NF-19,
 * GRD-RC-15) — 2 RIGHTS_OPERATOR y 2 APPROVER (consola CASE), más 2 TENANT_ADMIN (consola STAFF, CA-125). Sin IdP real en IT0: dev.ts inyecta este roster
 * en StaffIdentityPort (in-memory-staff-identity.adapter.ts) y lo resuelve únicamente el
 * endpoint de desarrollo /__dev/staff-login (case-confirmation.handler.ts, LOCAL-only,
 * GRD-CM-13). Cero PII: solo refs opacas sintéticas, nunca email, nombre ni RUT. LEGAL DECISION
 * LD-03 (quién tiene autoridad legal para registrar/co-firmar RH3) no se decide aquí. */
export const LOCAL_ONLY_DEV_STAFF_ROSTER = [
  { principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" as const },
  { principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR" as const },
  { principalRef: "staff-synthetic-03", role: "APPROVER" as const },
  { principalRef: "staff-synthetic-04", role: "APPROVER" as const },
  // CA-125 (contracts/openapi /staff/*, staffSession): miembros TENANT_ADMIN de la consola STAFF,
  // cada uno con su membership de tenant (GRD-CM-01) y sin reutilizar personas entre roles
  // (GRD-RC-15). 05 = colegio de dev; 06 = OTRO colegio, para probar el aislamiento por tenant.
  { principalRef: "staff-synthetic-05", role: "TENANT_ADMIN" as const, tenantId: LOCAL_ONLY_DEV_TENANT_ID },
  { principalRef: "staff-synthetic-06", role: "TENANT_ADMIN" as const, tenantId: LOCAL_ONLY_DEV_OTHER_TENANT_ID },
];
