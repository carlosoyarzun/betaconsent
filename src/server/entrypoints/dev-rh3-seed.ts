// Gobierna: CA-128 (API-CNS-138/139, RH3) y CA-127 (R4, CONSENT_REVOKED). Siembra LOCAL-only del
// caso RH3 de dev.ts, extraída a un archivo sin efectos secundarios para que un test de
// integración (TEST-CNS-687) ejecute el mismo seed que dev.ts sin arrancar el proceso.
// SYNTHETIC DATA ONLY. En memoria la Revocation pasa por el mismo camino de dominio que fija RH2
// RH2 con doble control (proposeCaseVerificationTx por el RIGHTS_OPERATOR 01 y approveCaseVerificationTx por el APPROVER 03
// del roster sintético LOCAL; verifiedAuthPath=RECOVERY, verifiedRecoveryMethod=HUMAN_ASSISTED), nunca se guarda ya
// "atestada" a mano. La aserción de step-up es un stub LOCAL-only (APR-IDP PENDING): aquí se da por ATTESTED.

import type { ConsentDecisionRecord } from "../ports/consent-decision-repository.port.ts";
import { LECTORPRO_BETA_CONFIG } from "../modules/consent-decision/lectorpro-beta.config.ts";
import { createHash, randomUUID } from "node:crypto";

import { getServedConsentVersion } from "../modules/consent-decision/served-consent-version.ts";

import { approveCaseVerificationTx, proposeCaseVerificationTx } from "../modules/revocation/revocation.ts";
import { createInMemoryStaffIdentityAdapter } from "../../infra/adapters/in-memory-staff-identity.adapter.ts";
import { LOCAL_ONLY_DEV_STAFF_ROSTER } from "./dev-local-config.ts";
import type { ConsentFlowPorts } from "./http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "./http/revocation-flow.handler.ts";

/** Refs opacas UUIDv4 (common.schema.json Ref) para que los eventos del ledger validen. */
export const RH3_DEV_CHAIN_REF = "7a3e9c1b-5d2f-4e68-9a40-1b3d5f7a9c2e";
export const RH3_DEV_CONSENT_ID = "3d9b7c1e-2a4f-4b6d-8e10-5f7a9c3b1d20";
export const RH3_DEV_CASE_REF = "4b1d7e9a-2c3f-4a68-8d5e-6f0a1b2c3d4e";
export const RH3_DEV_REVOCATION_REF = "8e2c4a6b-1d3f-4a5c-9b7e-0f2d4c6a8b10";

/** Refs opacas de la siembra. Por defecto las constantes de dev; los tests de platform siembran varios casos en la misma base con refs propias (un case_ref es unico en toda la base: rights_case_of). */
export interface Rh3DevRefs {
  readonly chainRef: string;
  readonly consentId: string;
  readonly caseRef: string;
  readonly revocationRef: string;
  readonly subjectRef: string;
  readonly invitationRef: string;
  readonly verificationRef: string;
  readonly dmRef: string;
  readonly enrollmentRef: string;
  readonly participationRef: string;
  readonly receiptRef: string;
}

export const RH3_DEV_REFS: Rh3DevRefs = {
  chainRef: RH3_DEV_CHAIN_REF,
  consentId: RH3_DEV_CONSENT_ID,
  caseRef: RH3_DEV_CASE_REF,
  revocationRef: RH3_DEV_REVOCATION_REF,
  subjectRef: "6b1f0c2a-7d3e-4a58-9b41-2c8e5f0a7d13", // Ref opaca UUIDv4: viaja en el sobre de consent.revoked (CA-127), nunca email/PII
  invitationRef: "9c4d2e6a-1b3f-4c58-8e70-3a5b7c9d1e2f",
  verificationRef: "2e6a8c0b-4d1f-4b39-9c52-7d9f1b3a5c7e",
  dmRef: "5b7d9f1a-3c2e-4d46-8a60-0c2e4a6b8d1f",
  enrollmentRef: "1f3b5d7a-9c2e-4a48-8b60-2d4f6a8c0e1b",
  participationRef: "8d0f2b4c-6e1a-4c37-9d59-1a3c5e7b9d2f",
  receiptRef: "0b2d4f6a-8c1e-4a37-9d52-3e5a7c9b1d4f",
};

/** Siembra atomica (UNA tx del tenant, SEC-CNS-017 F4): o queda todo el caso o nada. Idempotente por consulta, no por
 * captura de errores: si el caso ya existe devuelve false sin escribir. Cualquier otro error propaga. */
export async function seedRh3DevCase(_ports: ConsentFlowPorts, revocationPorts: RevocationFlowPorts, tenantId: string, refs: Rh3DevRefs = RH3_DEV_REFS): Promise<boolean> {
  // SEC-CNS-016/CA-124 PR-E: toda escritura de la siembra corre bajo el tenant (uow.inTenant); sirve igual
  // para CONSENT_STORE=memory y postgres. Los bolsos "fuera de tx" de Postgres rechazan el acceso suelto.
  const rv = revocationPorts.revocation;
  return rv.uow.inTenant(tenantId, async (tx) => {
    if (await tx.rightsCaseRepo.findByRef(tenantId, refs.caseRef)) return false;
    // ADR-010 rev. 5 PR-b: la base solo admite el ciclo legal (estado inicial fijo, grafo, cruces entre filas) y deriva el ledger de las filas; la decision GRANTED sembrada recorre el MISMO
    // camino que el flujo real: invitacion DRAFT->READY->SENT->OPENED, OTP CODE_SENT->VERIFIED, invitacion VERIFIED, decision PENDING + 4 pasos + GRANTED, invitacion COMPLETED.
    const subjectRef = refs.subjectRef;
    const invitationRef = refs.invitationRef;
    const verificationRef = refs.verificationRef;
    const dmRef = refs.dmRef;
    const enrollmentRef = refs.enrollmentRef;
    const participationRef = refs.participationRef;
    const served = getServedConsentVersion();
    const channel = "dev-rh3@example.invalid";
    const invBase = {
      invitationRef, tenantId, contextRef: LECTORPRO_BETA_CONFIG.contextRef, productRef: LECTORPRO_BETA_CONFIG.productRef, subjectRef, enrollmentRef, participationRef,
    } as const;
    const expiresAt = new Date(Date.now() + 24 * 3_600_000);
    const tokenHash = createHash("sha256").update(randomUUID()).digest("hex");
    await tx.invitationRepo.save({ ...invBase, state: "DRAFT" });
    const ready = { ...invBase, state: "READY" as const, consentVersion: served.consentVersion, expiresAt, recipientBinding: "RECIPIENT_CHANNEL" as const, recipientChannelRef: channel };
    await tx.invitationRepo.save(ready);
    const sent = { ...ready, state: "SENT" as const, tokenHash, deliveryChannel: "CONSENT_APP_EMAIL" as const };
    await tx.invitationRepo.save(sent);
    const opened = { ...sent, state: "OPENED" as const };
    await tx.invitationRepo.save(opened);
    const otp = {
      verificationRef, tenantId, scope: "DECISION" as const, parentRef: invitationRef, channelRef: channel, codeHash: "0".repeat(64), attempts: 0, expiresAt,
      state: "CODE_SENT" as const, resendCount: 0,
    };
    await tx.otpRepo.save(otp);
    await tx.otpRepo.save({ ...otp, attempts: 1, state: "VERIFIED", consumedAt: new Date(), decisionMakerRef: dmRef, dmRefKeyVersion: 2 });
    const verified = { ...opened, state: "VERIFIED" as const, boundDecisionMakerRef: dmRef, verifiedByRef: verificationRef, dmRefKeyVersion: 2 };
    await tx.invitationRepo.save(verified);
    const pending = {
      consentId: refs.consentId,
      tenantId,
      contextRef: LECTORPRO_BETA_CONFIG.contextRef,
      productRef: LECTORPRO_BETA_CONFIG.productRef,
      subjectRef,
      decisionMakerRef: dmRef,
      invitationRef,
      verificationRef,
      chainRef: refs.chainRef,
      state: "PENDING" as const,
      purposes: [],
      priorStepsComplete: false,
      stepsRecorded: [] as string[],
    };
    await tx.consentDecisionRepo.save(pending);
    const stepsAll = ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"];
    let current: ConsentDecisionRecord = pending;
    for (const step of stepsAll) {
      current = {
        ...current,
        stepsRecorded: [...current.stepsRecorded, step],
        priorStepsComplete: ["CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"].every((k) => [...current.stepsRecorded, step].includes(k)),
        ...(step === "CONSENT_VERSION_VIEWED" ? { consentVersion: served.consentVersion, consentTextHash: served.consentTextHash, privacyNoticeVersion: served.privacyNoticeVersion } : {}),
        ...(step === "DECISION_MAKER_AUTHORITY_DECLARED" ? { relationshipRef: "SYNTHETIC_GUARDIAN" } : {}),
      };
      await tx.consentDecisionRepo.save(current);
    }
    await tx.consentDecisionRepo.save({
      ...current,
      state: "GRANTED",
      purposes: LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const })),
      receiptRef: refs.receiptRef,
      consentVersion: served.consentVersion,
      consentTextHash: served.consentTextHash,
      privacyNoticeVersion: served.privacyNoticeVersion,
    });
    await tx.invitationRepo.save({ ...verified, state: "COMPLETED", closedByConsentId: refs.consentId });
    if (tx.rightsCaseTransitions !== undefined && tx.revocationTransitions !== undefined) {
      // ADR-010 rev. 5 (6d parte 2): con Postgres el caso llega a IN_VERIFICATION por el CAMINO LEGAL con las funciones de la base que SI ejecuta app_rw (RC1 -> RC2u -> RC3), sin
      // siembras seed_local_* (la base las revoca a app_rw en 0070). RH2 (propuesta y aprobacion) y RH3 solo existen en el proceso `platform`, con sesion CASE/PLATFORM: aqui no se simulan.
      // La Revocation queda REQUESTED y el caso IN_VERIFICATION, listos para que un operador proponga RH2 desde platform.
      await tx.rightsCaseTransitions.open({ caseRef: refs.caseRef, chainRef: refs.chainRef, revokedDecisionRef: refs.consentId, origin: "CHANNEL_UNREACHABLE" });
      await tx.rightsCaseTransitions.confirmReturn({ caseRef: refs.caseRef, expectedSequence: 1 });
      await tx.revocationTransitions.expressRevocationIntentInCase({
        caseRef: refs.caseRef,
        chainRef: refs.chainRef,
        revokedDecisionRef: refs.consentId,
        initiatedVia: "DECISION_MAKER",
        revocationRef: refs.revocationRef,
        attach: false,
        expectedSequence: 0,
      });
      return true;
    }
    await tx.rightsCaseRepo.save({
      caseRef: refs.caseRef,
      tenantId,
      chainRef: refs.chainRef,
      revokedDecisionRef: refs.consentId,
      status: "OPEN",
    });
    await tx.revocationRepo.save({
      revocationRef: refs.revocationRef,
      tenantId,
      chainRef: refs.chainRef,
      caseRef: refs.caseRef,
      revokedDecisionRef: refs.consentId,
      status: "REQUESTED",
    });
    const staff = createInMemoryStaffIdentityAdapter(LOCAL_ONLY_DEV_STAFF_ROSTER);
    const op1 = LOCAL_ONLY_DEV_STAFF_ROSTER[0]!.principalRef; // RIGHTS_OPERATOR (propone)
    const approver = LOCAL_ONLY_DEV_STAFF_ROSTER[2]!.principalRef; // APPROVER (aprueba, distinto de quienes confirman RH3)
    const proposalRef = randomUUID();
    await proposeCaseVerificationTx({ ...rv, ...tx }, staff, tenantId, refs.revocationRef, refs.caseRef, { principalRef: op1 }, {
      proposalRef,
      verificationScriptVersion: "dev-script-1",
    });
    await approveCaseVerificationTx({ ...rv, ...tx }, staff, tenantId, refs.revocationRef, refs.caseRef, proposalRef, { principalRef: approver }, true);
    await tx.rightsCaseRepo.save({
      caseRef: refs.caseRef,
      tenantId,
      chainRef: refs.chainRef,
      revokedDecisionRef: refs.consentId,
      status: "IN_VERIFICATION",
      revocationRef: refs.revocationRef,
    });
    return true;
  });
}
