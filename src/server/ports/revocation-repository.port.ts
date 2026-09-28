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
  /** GRD-RV-04/R14-C: la Revocation no terminal (status != FAILED, incluida APPLIED: el UNIQUE
   * parcial de GRD-RV-04 es WHERE state NOT IN ('COMPLETED','FAILED')) de esta cadena, si
   * existe. CA-116 PR 2 (recovery, R1r/R10/R11): a diferencia de R1 self-service (que siempre
   * trae su propio revocationRef en la sesión MANAGE), el handle RECOVERY de /r/{token} solo
   * conoce chainRef, así que el flujo de recuperación necesita resolver por cadena en vez de
   * por revocationRef. El llamador decide el tratamiento por status (GRD-RV-27: desde APPLIED
   * respuesta uniforme, sin crear otra). */
  findOpenByChain(tenantId: TenantId, chainRef: ChainRef): RevocationRecord | null;
  save(record: RevocationRecord): void;
}
