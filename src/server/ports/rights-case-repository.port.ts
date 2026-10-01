// Gobierna: specs/state-machines/rights-case.spec.yaml (aggregateType RightsCase).
// Puerto (ADR-001 §11): proyección del ledger para el agregado RightsCase. En IT0 el
// adaptadores son in-memory y Postgres (app.rights_case, CA-124 PR-D) en src/infra/adapters/**.

import type { ChainRef, TenantId } from "../modules/common/types.ts";

export type RightsCaseStatus = "OPEN" | "CONTACTING" | "IN_VERIFICATION" | "RESOLVED" | "WITHDRAWN";

/** vocabulary.origin (rights-case.spec.yaml) = escalationReason (DEC-BR-017 §6). */
export type RightsCaseOrigin =
  | "LIMIT_REACHED"
  | "CHANNEL_UNREACHABLE"
  | "REQUESTER_ASKED"
  | "SCHOOL_REPORTED"
  | "REQUEST_EXPIRED";

export interface RightsCaseRecord {
  caseRef: string;
  tenantId: TenantId;
  chainRef: ChainRef;
  revokedDecisionRef: string;
  status: RightsCaseStatus;
  revocationRef?: string;
  /** GRD-RC-07 (RC2u): origin = CHANNEL_UNREACHABLE es la única condición que habilita RC2u. */
  origin?: RightsCaseOrigin;
}

export interface RightsCaseRepositoryPort {
  /** GRD-RC-02: ≤1 caso no terminal por (tenantId, chainRef, revokedDecisionRef). */
  findOpenByChain(tenantId: TenantId, chainRef: ChainRef, revokedDecisionRef: string): Promise<RightsCaseRecord | null>;
  findByRef(tenantId: TenantId, caseRef: string): Promise<RightsCaseRecord | null>;
  /** Como `findByRef` con lock de fila hasta el fin de la unidad de trabajo (FOR UPDATE; SEC-CNS-015
   * P2-E): RC2u/RC3/RC4-6 deciden sobre el estado bloqueado. In-memory: equivalente a `findByRef`. */
  findByRefForUpdate(tenantId: TenantId, caseRef: string): Promise<RightsCaseRecord | null>;
  save(record: RightsCaseRecord): Promise<void>;
}
