// Gobierna: specs/state-machines/consent-decision.spec.yaml (aggregateType ConsentDecision).
// Puerto (ADR-001 §11): proyección del ledger para el agregado. Adaptador in-memory en IT0.

import type { TenantId } from "../modules/common/types.ts";

export type ConsentDecisionState = "PENDING" | "GRANTED" | "DECLINED" | "REVOKED";
// REVOKED: terminal; solo la fija C6 dentro de R4 (consent-decision.spec.yaml C6, GRD-CD-09).

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
  /** stepKind ya registrados por C2 (RecordDecisionStep), sin duplicados. Determina
   * priorStepsComplete (GRD-CD-05: CONSENT_VERSION_VIEWED, DECISION_MAKER_AUTHORITY_DECLARED,
   * SUBJECT_CONFIRMED; CONTEXT_INFORMATION_VIEWED no es requerido por ese guard). */
  readonly stepsRecorded: readonly string[];
  /** Ref opaca del recibo (contracts/api-payloads.schema.json DecisionRecorded.receiptRef, Ref
   * UUID); solo se fija al terminar en GRANTED o DECLINED (C3/C5). Ausente en PENDING. */
  readonly receiptRef?: string;
}

export interface ConsentDecisionRepositoryPort {
  findByConsentId(tenantId: TenantId, consentId: string): Promise<ConsentDecisionRecord | null>;
  /** Como `findByConsentId` con lock de fila hasta el fin de la unidad de trabajo (FOR UPDATE;
   * R4/C6, SEC-CNS-015 P1-1). In-memory: equivalente a `findByConsentId`. */
  findByConsentIdForUpdate(tenantId: TenantId, consentId: string): Promise<ConsentDecisionRecord | null>;
  /** GRD-CD-08 (single_active_grant_per_chain): ¿hay ya GRANTED (o PARTIALLY_GRANTED, no modelado en IT0) en esta cadena?
   * Una decisión REVOKED (C6) ya no cuenta como vigente (INV-1, INV-5). */
  findActiveGrantByChain(tenantId: TenantId, chainRef: string): Promise<ConsentDecisionRecord | null>;
  save(record: ConsentDecisionRecord): Promise<void>;
}
