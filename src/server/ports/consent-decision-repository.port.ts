// Gobierna: specs/state-machines/consent-decision.spec.yaml (aggregateType ConsentDecision).
// Puerto (ADR-001 §11): proyección del ledger para el agregado. Adaptador in-memory en IT0.

import type { TenantId } from "../modules/common/types.ts";

export type ConsentDecisionState = "PENDING" | "GRANTED" | "DECLINED";

export type PurposeChoice = "GRANT" | "DECLINE";

export interface PurposeDecision {
  readonly purpose: string;
  readonly choice: PurposeChoice;
}

export interface ConsentDecisionRecord {
  readonly consentId: string;
  readonly tenantId: TenantId;
  readonly contextRef: string;
  readonly productRef: string;
  readonly subjectRef: string;
  readonly decisionMakerRef: string;
  readonly invitationRef: string;
  readonly verificationRef: string;
  /** decisionChainKey = (tenantRef, contextRef, subjectRef, decisionMakerRef); opaco. */
  readonly chainRef: string;
  readonly state: ConsentDecisionState;
  readonly purposes: readonly PurposeDecision[];
  /** GRD-CD-05 (prior_steps_complete): pasos previos registrados por C2. */
  readonly priorStepsComplete: boolean;
}

export interface ConsentDecisionRepositoryPort {
  findByConsentId(tenantId: TenantId, consentId: string): ConsentDecisionRecord | null;
  /** GRD-CD-08 (single_active_grant_per_chain): ¿hay ya GRANTED (o PARTIALLY_GRANTED, no modelado en IT0) en esta cadena? */
  findActiveGrantByChain(tenantId: TenantId, chainRef: string): ConsentDecisionRecord | null;
  save(record: ConsentDecisionRecord): void;
}
