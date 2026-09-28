#!/usr/bin/env node
// Entrypoint de desarrollo LOCAL (GRD-CM-13, ADR-003 rev. 7: sin infraestructura real, solo
// adapters in-memory). Arranca el flujo invitación -> OTP -> decisión en 127.0.0.1 con un
// tenant, un contexto BETA_2026_01 y una invitación sintéticos (dominio example.invalid, cero
// PII). Exige environment=LOCAL: cualquier otro valor aborta antes de escuchar (fail-closed).
// Uso: `node src/server/entrypoints/dev.ts` (PORT opcional, default 3000). Documentado en
// src/README.md.

import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "./http/consent-flow-server.ts";
import { loadOtpPolicyConfig } from "../modules/otp-challenge/otp-policy.config.ts";
import { loadDecisionRelationshipConfig } from "../modules/consent-decision/decision-relationship.config.ts";
import { loadRecoveryTokenPolicyConfig } from "../modules/revocation/recovery-token-policy.config.ts";
import { loadRecoveryHandlePolicyConfig } from "../modules/revocation/recovery-handle-policy.config.ts";
import { loadInvitationHandlePolicyConfig } from "../modules/invitation/invitation-handle-policy.config.ts";
import { loadManageHandlePolicyConfig } from "../modules/revocation/manage-handle-policy.config.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../modules/invitation/invitation.ts";
import { RH3_DEV_CASE_REF, seedRh3DevCase } from "./dev-rh3-seed.ts";
import { LECTORPRO_BETA_CONFIG } from "../modules/consent-decision/lectorpro-beta.config.ts";
import {
  LOCAL_ONLY_DEV_INVITATION_HANDLE_POLICY,
  LOCAL_ONLY_DEV_MANAGE_HANDLE_POLICY,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_RECOVERY_HANDLE_POLICY,
  LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_STAFF_ROSTER,
} from "./dev-local-config.ts";
import { createInMemoryStaffIdentityAdapter } from "../../infra/adapters/in-memory-staff-identity.adapter.ts";
import type { InMemoryTenantHandleAdapter } from "../../infra/adapters/in-memory-tenant-handle.adapter.ts";

const environment = process.env.CNS_ENVIRONMENT ?? "";
if (environment !== "LOCAL") {
  // GRD-CM-13 (fixture_actor_environment): este entrypoint es de seed FIXTURE + sink de
  // depuración; solo puede correr en LOCAL. Aborta sin escuchar ningún puerto.
  console.error(
    `dev.ts requiere CNS_ENVIRONMENT=LOCAL (recibido: "${environment || "(vacío)"}"). ` +
      "Nunca corre en DEV/STAGING/PRODUCTION (GRD-CM-13). Abortando.",
  );
  process.exit(1);
}

const port = Number.parseInt(process.env.PORT ?? "3000", 10);
const allowedOrigin = process.env.CNS_ALLOWED_ORIGIN ?? `http://127.0.0.1:${port}`;

// D4: P-01/P-02/P-03 no tienen valor aprobado en specs/contracts; este override es LOCAL-only,
// nunca un default de producción (ver otp-policy.config.ts). Valor compartido con
// TEST-CNS-566 (dev-local-config.test.ts) vía dev-local-config.ts, para que CI detecte si deja
// de cumplir lo que exige el loader real.
const otpPolicy = loadOtpPolicyConfig(LOCAL_ONLY_DEV_OTP_POLICY);

// LOCAL-only sintético (GRD-CD-04, decision-relationship.config.ts, opción b de Carlos,
// 2026-09-27): el enum legal real sigue PENDING DEC-BR-003 / EXT-A / LD-01.
const relationshipConfig = loadDecisionRelationshipConfig(LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG);

const ports = createDefaultConsentFlowPorts(otpPolicy, relationshipConfig);
const sessionSecret = randomBytes(32);

const TENANT_ID = "tenant-dev";
const INVITATION_REF = "inv-dev-001";
const SUBJECT_REF = "dev-subject@example.invalid";
const CHANNEL_REF = "dev-decision-maker@example.invalid";

createInvitation(ports.invitation, TENANT_ID, "INVITER", {
  invitationRef: INVITATION_REF,
  contextRef: LECTORPRO_BETA_CONFIG.contextRef,
  productRef: LECTORPRO_BETA_CONFIG.productRef,
  subjectRef: SUBJECT_REF,
});
markInvitationReady(ports.invitation, TENANT_ID, "INVITER", INVITATION_REF, {
  consentVersion: "v1-dev",
  expiresAt: new Date(Date.now() + 24 * 60 * 60_000),
  recipientChannelRef: CHANNEL_REF,
});
const { token } = sendInvitation(ports.invitation, TENANT_ID, "INVITER", INVITATION_REF);

// CA-116 (revocación IT0, UX-CNS-004): además del enlace /i/<token>, siembra un enlace
// /m/<token> sintético sobre una decisión GRANTED ya existente (sin pasar por el flujo HTTP de
// invitación/OTP/decisión), para poder probar a mano gestión/retiro sin repetir todo el flujo
// de arriba. CA116_MGMT_TOKEN es un literal fijo (LOCAL only, cero PII, D4 mismo criterio que
// el resto de este archivo).
const MGMT_CHAIN_REF = "chain-dev-mgmt";
const MGMT_CONSENT_ID = "consent-dev-mgmt-001";
const MGMT_TOKEN = "dev-mgmt-token-001";
ports.decision.repo.save({
  consentId: MGMT_CONSENT_ID,
  tenantId: TENANT_ID,
  contextRef: LECTORPRO_BETA_CONFIG.contextRef,
  productRef: LECTORPRO_BETA_CONFIG.productRef,
  subjectRef: "dev-mgmt-subject@example.invalid",
  decisionMakerRef: "dm:dev-mgmt",
  invitationRef: "inv-dev-mgmt-seed",
  verificationRef: "ver-dev-mgmt-seed",
  chainRef: MGMT_CHAIN_REF,
  state: "GRANTED",
  purposes: LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const })),
  priorStepsComplete: true,
  stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
  receiptRef: "receipt-dev-mgmt-001",
});
// P-15 (recovery-token-policy.config.ts): mismo patrón D4 que otpPolicy, LOCAL-only, PENDING
// de valor aprobado en SEC-CNS-006 (CA-116 PR 2, UX-CNS-004 recovery).
const recoveryTokenPolicy = loadRecoveryTokenPolicyConfig(LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY);
// P-18 (recovery-handle-policy.config.ts, ADR-006 §6.2, SEC-CNS-014): TTL de la cookie
// __Host-cns-recovery que fija GET /r/{token} sin leer la BD; distinto de P-15 (arriba).
const recoveryHandlePolicy = loadRecoveryHandlePolicyConfig(LOCAL_ONLY_DEV_RECOVERY_HANDLE_POLICY);
// SEC-CNS-014 patrón (Carlos, 2026-09-28): TTL de las cookies __Host-cns-i-handle/
// __Host-cns-m-handle que fijan GET /i/{token} y GET /m/{token} sin leer la BD.
const invitationHandlePolicy = loadInvitationHandlePolicyConfig(LOCAL_ONLY_DEV_INVITATION_HANDLE_POLICY);
const manageHandlePolicy = loadManageHandlePolicyConfig(LOCAL_ONLY_DEV_MANAGE_HANDLE_POLICY);
const revocationPorts = createDefaultRevocationFlowPorts(recoveryTokenPolicy, ports.decision.ledger, ports.decision.repo);
(revocationPorts.tenantHandle as InMemoryTenantHandleAdapter).issue({
  handle: MGMT_TOKEN,
  tenantId: TENANT_ID,
  chainRef: MGMT_CHAIN_REF,
  revokedDecisionRef: MGMT_CONSENT_ID,
});

// CA-128 (API-CNS-138, RH3 paso 1): además del enlace /m/<token> de arriba, siembra un caso
// RH3 completo (RC1 abierto + RH2 ya atestado) para poder probar record_case_confirmation a
// mano sin repetir HTTP para RC1/RH2 (fuera de alcance de este slice). Cadena/decisión propias
// (RH3_*), separadas de MGMT_* de arriba, para no interferir con el flujo de gestión.
const RH3_CASE_REF = RH3_DEV_CASE_REF;
seedRh3DevCase(ports, revocationPorts, TENANT_ID);
// LOCAL + CI / SYNTHETIC DATA ONLY — APR-IDP PENDING (Carlos 2026-09-28 opción (ii)).
const staffIdentity = createInMemoryStaffIdentityAdapter(LOCAL_ONLY_DEV_STAFF_ROSTER);

const server = createConsentFlowHttpServer({
  config: { allowedOrigin },
  ports,
  revocationPorts,
  sessionSecret,
  recoveryHandlePolicy,
  invitationHandlePolicy,
  manageHandlePolicy,
  environment: "LOCAL",
  staffIdentity,
});

server.listen(port, "127.0.0.1", () => {
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  console.log(`Consent App (IT0, LOCAL) escuchando en ${baseUrl}`);
  // API-CNS-101 (P-12): el flujo empieza con el GET de canje, nunca con el token suelto (cero
  // PII/credenciales en logs fuera de esta URL sintética de LOCAL, dominio example.invalid).
  // UX-CNS-001: el canje redirige a /welcome (INV-CM-08, no transiciona ahí).
  console.log(`Abre esta URL en tu navegador para comenzar el flujo (canje de un solo uso, GET /i/{token}):`);
  console.log(`  ${baseUrl}/i/${token}`);
  console.log(`Leer el OTP emitido: GET ${baseUrl}/__dev/otp-sink (solo existe con CNS_ENVIRONMENT=LOCAL).`);
  // CA-116: enlace /m/<token> sintético sobre una decisión GRANTED ya sembrada (MGMT_CONSENT_ID),
  // para probar a mano gestión/retiro (GET /m/{token} -> /manage) sin repetir el flujo de arriba.
  console.log(`Enlace de gestión (UX-CNS-004, sobre una decisión GRANTED ya sembrada):`);
  console.log(`  ${baseUrl}/m/${MGMT_TOKEN}`);
  // CA-116 PR 2: para probar la recuperación a mano, desde el enlace de gestión de arriba pulsa
  // "Enviar enlace de recuperación" (POST /manage/recovery-link) y lee el enlace /r/<token> real
  // aquí (nunca en la respuesta HTTP ni en logs de producción: solo en LOCAL).
  console.log(`Leer el enlace de recuperación emitido: GET ${baseUrl}/__dev/recovery-sink (solo existe con CNS_ENVIRONMENT=LOCAL).`);
  // CA-127: R4 encola consent.revoked en el outbox in-memory; se lee aquí (solo LOCAL, sin entrega: R5).
  console.log(`Leer los eventos del outbox: GET ${baseUrl}/__dev/outbox-sink (solo existe con CNS_ENVIRONMENT=LOCAL).`);
  // CA-128 (API-CNS-138 + API-CNS-139, RH3 completo): caso ya abierto con RH2 atestado
  // (RH3_CASE_REF). Cuatro ojos: registra staff-synthetic-01 y co-firma otro RIGHTS_OPERATOR
  // distinto (staff-synthetic-02; un APPROVER no co-firma, revocation.spec RH3). Cada persona
  // usa su propio cookie jar.
  const staffLogin = (principalRef: string, jar: string): string =>
    `  curl -i -c ${jar} -X POST ${baseUrl}/__dev/staff-login -H 'content-type: application/json' -d '{"tenantId":"${TENANT_ID}","caseRef":"${RH3_CASE_REF}","principalRef":"${principalRef}"}'`;
  console.log(`RH3 paso 1 (API-CNS-138, sin efecto hasta co-firma): caso ${RH3_CASE_REF}. Probar con curl:`);
  console.log(staffLogin("staff-synthetic-01", "/tmp/cns-case-op1.txt"));
  console.log(`  # copia el valor de __Host-cns-case-csrf del Set-Cookie de arriba en <CSRF1>, luego:`);
  console.log(
    `  curl -i -b /tmp/cns-case-op1.txt -X POST ${baseUrl}/platform/rights-cases/${RH3_CASE_REF}/confirmation -H "origin: ${allowedOrigin}" -H "x-csrf-token: <CSRF1>" -H 'content-type: application/json' -d '{"confirmationGivenOnCasePage":true}'`,
  );
  console.log(`RH3 paso 2 (API-CNS-139, co-firma por un segundo RIGHTS_OPERATOR distinto -> CONFIRMED):`);
  console.log(staffLogin("staff-synthetic-02", "/tmp/cns-case-op2.txt"));
  console.log(`  # copia el valor de __Host-cns-case-csrf de este segundo login en <CSRF2>, luego:`);
  console.log(
    `  curl -i -b /tmp/cns-case-op2.txt -X POST ${baseUrl}/platform/rights-cases/${RH3_CASE_REF}/confirmation/cosign -H "origin: ${allowedOrigin}" -H "x-csrf-token: <CSRF2>" -H 'content-type: application/json' -d '{}'`,
  );
});
