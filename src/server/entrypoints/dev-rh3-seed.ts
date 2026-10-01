// Gobierna: CA-128 (API-CNS-138/139, RH3) y CA-127 (R4, CONSENT_REVOKED). Siembra LOCAL-only del
// caso RH3 de dev.ts, extraída a un archivo sin efectos secundarios para que un test de
// integración (TEST-CNS-687) ejecute el mismo seed que dev.ts sin arrancar el proceso.
// SYNTHETIC DATA ONLY. La Revocation pasa por el mismo camino de dominio que fija RH2
// RH2 con doble control (proposeCaseVerificationTx por el RIGHTS_OPERATOR 01 y approveCaseVerificationTx por el APPROVER 03
// del roster sintético LOCAL; verifiedAuthPath=RECOVERY, verifiedRecoveryMethod=HUMAN_ASSISTED), nunca se guarda ya
// "atestada" a mano. La aserción de step-up es un stub LOCAL-only (APR-IDP PENDING): aquí se da por ATTESTED.

import { LECTORPRO_BETA_CONFIG } from "../modules/consent-decision/lectorpro-beta.config.ts";
import { randomUUID } from "node:crypto";

import { approveCaseVerificationTx, proposeCaseVerificationTx } from "../modules/revocation/revocation.ts";
import { createInMemoryStaffIdentityAdapter } from "../../infra/adapters/in-memory-staff-identity.adapter.ts";
import { LOCAL_ONLY_DEV_STAFF_ROSTER } from "./dev-local-config.ts";
import type { ConsentFlowPorts } from "./http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "./http/revocation-flow.handler.ts";

/** Refs opacas UUIDv4 (common.schema.json Ref) para que los eventos del ledger validen. */
export const RH3_DEV_CHAIN_REF = "chain-dev-rh3";
export const RH3_DEV_CONSENT_ID = "3d9b7c1e-2a4f-4b6d-8e10-5f7a9c3b1d20";
export const RH3_DEV_CASE_REF = "4b1d7e9a-2c3f-4a68-8d5e-6f0a1b2c3d4e";
export const RH3_DEV_REVOCATION_REF = "8e2c4a6b-1d3f-4a5c-9b7e-0f2d4c6a8b10";

/** Siembra atomica (UNA tx del tenant, SEC-CNS-017 F4): o queda todo el caso o nada. Idempotente por consulta, no por
 * captura de errores: si el caso ya existe devuelve false sin escribir. Cualquier otro error propaga. */
export async function seedRh3DevCase(_ports: ConsentFlowPorts, revocationPorts: RevocationFlowPorts, tenantId: string): Promise<boolean> {
  // SEC-CNS-016/CA-124 PR-E: toda escritura de la siembra corre bajo el tenant (uow.inTenant); sirve igual
  // para CONSENT_STORE=memory y postgres. Los bolsos "fuera de tx" de Postgres rechazan el acceso suelto.
  const rv = revocationPorts.revocation;
  return rv.uow.inTenant(tenantId, async (tx) => {
    if (await tx.rightsCaseRepo.findByRef(tenantId, RH3_DEV_CASE_REF)) return false;
    await tx.consentDecisionRepo.save({
      consentId: RH3_DEV_CONSENT_ID,
      tenantId,
      contextRef: LECTORPRO_BETA_CONFIG.contextRef,
      productRef: LECTORPRO_BETA_CONFIG.productRef,
      subjectRef: "6b1f0c2a-7d3e-4a58-9b41-2c8e5f0a7d13", // Ref opaca UUIDv4: viaja en el sobre de consent.revoked (CA-127), nunca email/PII
      decisionMakerRef: "dm:dev-rh3",
      invitationRef: "inv-dev-rh3-seed",
      verificationRef: "ver-dev-rh3-seed",
      chainRef: RH3_DEV_CHAIN_REF,
      state: "GRANTED",
      purposes: LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const })),
      priorStepsComplete: true,
      stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
      receiptRef: "receipt-dev-rh3-001",
    });
    await tx.rightsCaseRepo.save({
      caseRef: RH3_DEV_CASE_REF,
      tenantId,
      chainRef: RH3_DEV_CHAIN_REF,
      revokedDecisionRef: RH3_DEV_CONSENT_ID,
      status: "OPEN",
    });
    await tx.revocationRepo.save({
      revocationRef: RH3_DEV_REVOCATION_REF,
      tenantId,
      chainRef: RH3_DEV_CHAIN_REF,
      caseRef: RH3_DEV_CASE_REF,
      revokedDecisionRef: RH3_DEV_CONSENT_ID,
      status: "REQUESTED",
    });
    const staff = createInMemoryStaffIdentityAdapter(LOCAL_ONLY_DEV_STAFF_ROSTER);
    const op1 = LOCAL_ONLY_DEV_STAFF_ROSTER[0]!.principalRef; // RIGHTS_OPERATOR (propone)
    const approver = LOCAL_ONLY_DEV_STAFF_ROSTER[2]!.principalRef; // APPROVER (aprueba, distinto de quienes confirman RH3)
    const proposalRef = randomUUID();
    await proposeCaseVerificationTx({ ...rv, ...tx }, staff, tenantId, RH3_DEV_REVOCATION_REF, RH3_DEV_CASE_REF, { principalRef: op1 }, {
      proposalRef,
      verificationScriptVersion: "dev-script-1",
    });
    await approveCaseVerificationTx({ ...rv, ...tx }, staff, tenantId, RH3_DEV_REVOCATION_REF, RH3_DEV_CASE_REF, proposalRef, { principalRef: approver }, true);
    await tx.rightsCaseRepo.save({
      caseRef: RH3_DEV_CASE_REF,
      tenantId,
      chainRef: RH3_DEV_CHAIN_REF,
      revokedDecisionRef: RH3_DEV_CONSENT_ID,
      status: "IN_VERIFICATION",
      revocationRef: RH3_DEV_REVOCATION_REF,
    });
    return true;
  });
}
