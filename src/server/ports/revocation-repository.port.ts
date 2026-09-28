// Gobierna: specs/state-machines/revocation.spec.yaml (aggregateType Revocation).
// Puerto (ADR-001 §11): proyección del ledger para el agregado Revocation. IT0: adaptador
// in-memory; el adaptador de Postgres llega con la historia de infraestructura.

import type { ChainRef, TenantId } from "../modules/common/types.ts";

export type RevocationStatus = "REQUESTED" | "VERIFIED" | "CONFIRMED" | "APPLIED" | "FAILED";

export interface AttestedVerification {
  readonly revocationRef: string;
  readonly caseRef: string;
}

export interface RevocationRecord {
  revocationRef: string;
  tenantId: TenantId;
  chainRef: ChainRef;
  caseRef?: string;
  status: RevocationStatus;
  /** GRD-RV-10: RH2/RH2v ATTESTED de esta misma (revocationRef, caseRef), o undefined. */
  attestedVerification?: AttestedVerification;
  recordedByRef?: string;
  cosignedByRef?: string;
  /** R14-C: consentId de la decisión GRANTED vigente que esta Revocation revoca, fijado en
   * servidor al crear R1 (revocation.spec.yaml attributes: revokedDecisionRef). */
  revokedDecisionRef?: string;
  /** R8 (WithdrawRevocationRequest): único reasonCode del vocabulario IT0 (DEC-BR-017 §6). */
  reasonCode?: "WITHDRAWN_BY_REQUESTER";
}

export interface RevocationRepositoryPort {
  findByRef(tenantId: TenantId, revocationRef: string): RevocationRecord | null;
  findByCase(tenantId: TenantId, caseRef: string): RevocationRecord | null;
  save(record: RevocationRecord): void;
}
