// Gobierna: specs/state-machines/revocation.spec.yaml (aggregateType Revocation).
// Puerto (ADR-001 §11): proyección del ledger para el agregado Revocation. IT0: adaptador
// in-memory; el adaptador de Postgres llega con la historia de infraestructura.

import type { ChainRef, TenantId } from "../modules/common/types.ts";

export type RevocationStatus = "REQUESTED" | "VERIFIED" | "CONFIRMED" | "APPLIED" | "DOWNSTREAM_PENDING" | "DELIVERED" | "COMPLETED" | "FAILED";

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
  /** GRD-RV-29 (verifiedAuthPath/verifiedRecoveryMethod): vía del último REVOCATION_VERIFIED,
   * fijada por el dominio en R2/R2r/R10/RH2 (nunca del input del usuario). R4 la deriva de aquí
   * para CONSENT_REVOKED.authPath/recoveryMethod. recoveryMethod solo si authPath = RECOVERY. */
  verifiedAuthPath?: "OTP" | "RECOVERY";
  verifiedRecoveryMethod?: "CHANNEL_LINK" | "HUMAN_ASSISTED";
  /** R8 (WithdrawRevocationRequest): único reasonCode del vocabulario IT0 (DEC-BR-017 §6). */
  reasonCode?: "WITHDRAWN_BY_REQUESTER";
}

export interface RevocationRepositoryPort {
  findByRef(tenantId: TenantId, revocationRef: string): Promise<RevocationRecord | null>;
  /** Igual que `findByRef` pero toma el lock de la fila hasta el fin de la unidad de trabajo
   * (SELECT ... FOR UPDATE en Postgres; revocation.spec R4 "una tx con lock", SEC-CNS-015 P1-1).
   * Solo dentro de `UnitOfWorkPort.inTenant`: serializa R2/R3/R4/R8/RH* sobre la misma Revocation
   * y relee el estado vigente tras esperar al ganador. In-memory: equivalente a `findByRef` (la
   * unidad de trabajo ya serializa). */
  findByRefForUpdate(tenantId: TenantId, revocationRef: string): Promise<RevocationRecord | null>;
  findByCase(tenantId: TenantId, caseRef: string): Promise<RevocationRecord | null>;
  /** GRD-RV-04/R14-C: la Revocation no terminal (status != FAILED, incluida APPLIED: el UNIQUE
   * parcial de GRD-RV-04 es WHERE state NOT IN ('COMPLETED','FAILED')) de esta cadena, si
   * existe. CA-116 PR 2 (recovery, R1r/R10/R11): a diferencia de R1 self-service (que siempre
   * trae su propio revocationRef en la sesión MANAGE), el handle RECOVERY de /r/{token} solo
   * conoce chainRef, así que el flujo de recuperación necesita resolver por cadena en vez de
   * por revocationRef. El llamador decide el tratamiento por status (GRD-RV-27: desde APPLIED
   * respuesta uniforme, sin crear otra). */
  findOpenByChain(tenantId: TenantId, chainRef: ChainRef): Promise<RevocationRecord | null>;
  /** GRD-RV-04 (R14-C): la única Revocation no terminal (status NOT IN COMPLETED/FAILED) que revoca esta
   * decisión, o null. "Una crea, las demás se adjuntan": R1 con otro revocationRef sobre la misma
   * decisión devuelve esta en vez de crear (Carlos, 2026-10-01, GRD-RV-04 opción a). */
  findOpenByDecision(tenantId: TenantId, revokedDecisionRef: string): Promise<RevocationRecord | null>;
  save(record: RevocationRecord): Promise<void>;
}
