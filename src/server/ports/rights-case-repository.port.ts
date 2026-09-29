// Gobierna: specs/state-machines/rights-case.spec.yaml (aggregateType RightsCase).
// Puerto (ADR-001 §11): proyección del ledger para el agregado RightsCase. En IT0 el
// adaptador es in-memory (src/infra/adapters/**); el adaptador de Postgres (app.rights_case)
// llega con la historia de infraestructura correspondiente.

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
  save(record: RightsCaseRecord): Promise<void>;
}
