// Gobierna: specs/state-machines/rights-case.spec.yaml (aggregateType RightsCase).
// Puerto (ADR-001 §11): proyección del ledger para el agregado RightsCase. En IT0 el
// adaptador es in-memory (src/infra/adapters/**); el adaptador de Postgres (app.rights_case)
// llega con la historia de infraestructura correspondiente.

import type { ChainRef, TenantId } from "../modules/common/types.ts";

export type RightsCaseStatus = "OPEN" | "CONTACTING" | "IN_VERIFICATION" | "RESOLVED" | "WITHDRAWN";

export interface RightsCaseRecord {
  caseRef: string;
  tenantId: TenantId;
  chainRef: ChainRef;
  revokedDecisionRef: string;
  status: RightsCaseStatus;
  revocationRef?: string;
}

export interface RightsCaseRepositoryPort {
  /** GRD-RC-02: ≤1 caso no terminal por (tenantId, chainRef, revokedDecisionRef). */
  findOpenByChain(tenantId: TenantId, chainRef: ChainRef, revokedDecisionRef: string): RightsCaseRecord | null;
  findByRef(tenantId: TenantId, caseRef: string): RightsCaseRecord | null;
  save(record: RightsCaseRecord): void;
}
