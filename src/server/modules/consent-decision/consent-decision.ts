// Gobierna: specs/state-machines/consent-decision.spec.yaml (C1 StartDecision, C2
// RecordDecisionStep, C3/C5 SubmitDecision) y specs/adapters/lectorpro-beta.spec.yaml
// (contextRef, productRef, requiredPurposes, prohibitedPurposes, allowPartialGrant). Alcance
// IT0 de este archivo (subconjunto mínimo, TEST-CNS-490 en adelante): C1/C2/C3/C5 con las 4
// finalidades requeridas de LECTORPRO/BETA_2026_01 y allowPartialGrant=false (C4 no
// alcanzable, coherente con la spec). No implementa C6 (revocación: vive en
// revocation.ts/R4), C7/C8 (deshabilitadas en BETA_2026_01), consentTextHash sobre el texto
// servido (GRD-CD-03, requiere ConsentVersion real), GRD-CM-08/09 (idempotencia de
// Idempotency-Key e integridad de claves) ni GRD-CD-10 (expectedSequence, carrera con
// revocación). Ver reporte de la tarea para el detalle de lo diferido.

import { DomainError } from "../common/errors.ts";
import { assertActorRoleIn, assertRouteEligible, assertTenantConsistency } from "../common/guards.ts";
import type { ActorRole, TenantId } from "../common/types.ts";
import type {
  ConsentDecisionRecord,
  ConsentDecisionRepositoryPort,
  PurposeChoice,
  PurposeDecision,
} from "../../ports/consent-decision-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { InvitationPorts } from "../invitation/invitation.ts";
import { markInvitationCompleted, markInvitationDeclined } from "../invitation/invitation.ts";
import type { LectorProBetaConfig } from "./lectorpro-beta.config.ts";

export interface ConsentDecisionPorts {
  readonly repo: ConsentDecisionRepositoryPort;
  readonly ledger: LedgerPort;
  readonly invitation: InvitationPorts;
  readonly config: LectorProBetaConfig;
}

const DECISION_MAKER_ROLE: readonly ActorRole[] = ["DECISION_MAKER"];

function deriveChainRef(tenantId: TenantId, contextRef: string, subjectRef: string, decisionMakerRef: string): string {
  // decisionChainKey = (tenantRef, contextRef, subjectRef, decisionMakerRef); opaco (ADR-002 §10).
  return `chain:${tenantId}:${contextRef}:${subjectRef}:${decisionMakerRef}`;
}

function requireDecision(ports: ConsentDecisionPorts, tenantId: TenantId, consentId: string): ConsentDecisionRecord {
  const found = ports.repo.findByConsentId(tenantId, consentId);
  if (!found) {
    throw new DomainError("ERR-CM-01");
  }
  assertTenantConsistency(found.tenantId, tenantId); // GRD-CM-02
  return found;
}

export interface StartDecisionInput {
  readonly consentId: string;
  readonly invitationRef: string;
  readonly verificationRef: string;
  readonly decisionMakerRef: string;
}

/** C1: null -> PENDING. Guards: GRD-CM-02, GRD-CM-05, GRD-CM-07, GRD-CD-01, GRD-CD-02. */
export function startDecision(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  input: StartDecisionInput,
): ConsentDecisionRecord {
  assertActorRoleIn(actorRole, DECISION_MAKER_ROLE); // GRD-CM-07

  const invitation = ports.invitation.invitationRepo.findByRef(tenantId, input.invitationRef);
  if (!invitation) {
    throw new DomainError("ERR-CM-01");
  }
  assertTenantConsistency(invitation.tenantId, tenantId); // GRD-CM-02

  if (invitation.state !== "VERIFIED" || invitation.boundDecisionMakerRef !== input.decisionMakerRef) {
    // GRD-CD-01/02 (decision_session_valid, invitation_verified).
    throw new DomainError("ERR-CD-07");
  }
  assertRouteEligible(
    ports.invitation.eligibility.isEligibleForIssuance(tenantId, invitation.contextRef, invitation.productRef),
  ); // GRD-CM-05

  const record: ConsentDecisionRecord = {
    consentId: input.consentId,
    tenantId,
    contextRef: invitation.contextRef,
    productRef: invitation.productRef,
    subjectRef: invitation.subjectRef,
    decisionMakerRef: input.decisionMakerRef,
    invitationRef: input.invitationRef,
    verificationRef: input.verificationRef,
    chainRef: deriveChainRef(tenantId, invitation.contextRef, invitation.subjectRef, input.decisionMakerRef),
    state: "PENDING",
    purposes: [],
    priorStepsComplete: false,
  };
  ports.repo.save(record);
  // C1 emits: [] (SM-CNS-001 §4 C1): sin evento de ledger propio.
  return record;
}

/** C2 (subconjunto): registra los pasos previos exigidos por GRD-CD-05 en un solo lote. */
export function recordRequiredSteps(ports: ConsentDecisionPorts, tenantId: TenantId, consentId: string): ConsentDecisionRecord {
  const found = requireDecision(ports, tenantId, consentId);
  if (found.state !== "PENDING") {
    throw new DomainError("ERR-CM-06");
  }

  const events: Array<{ eventType: string; payload: Record<string, unknown> }> = [
    { eventType: "CONTEXT_INFORMATION_VIEWED", payload: { consentId } },
    { eventType: "CONSENT_VERSION_VIEWED", payload: { consentId } },
    { eventType: "DECISION_MAKER_AUTHORITY_DECLARED", payload: { consentId } },
    { eventType: "SUBJECT_CONFIRMED", payload: { consentId, subjectRef: found.subjectRef } },
  ];
  for (const event of events) {
    ports.ledger.append({
      eventType: event.eventType,
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: event.payload,
      idempotencyKey: `${consentId}:${event.eventType}`,
    });
  }

  const updated: ConsentDecisionRecord = { ...found, priorStepsComplete: true };
  ports.repo.save(updated);
  return updated;
}

function validatePurposes(config: LectorProBetaConfig, purposes: readonly PurposeDecision[]): void {
  const byPurpose = new Map<string, PurposeChoice>();
  for (const p of purposes) {
    if (byPurpose.has(p.purpose)) {
      // Elección duplicada o preseleccionada: no explícita ni única.
      throw new DomainError("ERR-CD-02");
    }
    byPurpose.set(p.purpose, p.choice);
  }
  if (config.prohibitedPurposes.some((p) => byPurpose.has(p))) {
    // GRD-CD-06/07: ninguna finalidad prohibida.
    throw new DomainError("ERR-CD-02");
  }
  for (const required of config.requiredPurposes) {
    if (!byPurpose.has(required)) {
      // GRD-CD-06/07: toda finalidad requerida necesita elección explícita.
      throw new DomainError("ERR-CD-02");
    }
  }
  for (const purpose of byPurpose.keys()) {
    if (!config.requiredPurposes.includes(purpose)) {
      // Fuera de configuración (ninguna finalidad opcional modelada en IT0).
      throw new DomainError("ERR-CD-02");
    }
  }
}

/** C3 (all_required_granted) / C5 (required_declined): PENDING -> GRANTED | DECLINED. */
export function submitDecision(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  decisionMakerRef: string,
  consentId: string,
  purposes: readonly PurposeDecision[],
): ConsentDecisionRecord {
  const found = requireDecision(ports, tenantId, consentId);
  assertActorRoleIn(actorRole, DECISION_MAKER_ROLE); // GRD-CM-10
  if (found.decisionMakerRef !== decisionMakerRef) {
    // GRD-CD-11 (actor_is_decision_maker): solo el DecisionMaker verificado de esta cadena.
    throw new DomainError("ERR-CM-10");
  }
  if (found.state !== "PENDING") {
    // GRD-CM-06 / ERR-CD-08 (DECISION_TERMINAL): no hay GRANTED<->DECLINED directo ni salida de terminal.
    throw new DomainError("ERR-CD-08");
  }
  if (!found.priorStepsComplete) {
    // GRD-CD-05 (prior_steps_complete, INV-2).
    throw new DomainError("ERR-CD-04");
  }
  assertRouteEligible(
    ports.invitation.eligibility.isEligibleForIssuance(tenantId, found.contextRef, found.productRef),
  ); // GRD-CD-12 (context_guards_at_submit, re-evaluado)

  validatePurposes(ports.config, purposes); // GRD-CD-06/07

  const allGranted = ports.config.requiredPurposes.every(
    (purpose) => purposes.find((p) => p.purpose === purpose)?.choice === "GRANT",
  );

  if (allGranted) {
    const existingGrant = ports.repo.findActiveGrantByChain(tenantId, found.chainRef);
    if (existingGrant) {
      // GRD-CD-08 (single_active_grant_per_chain, INV-1).
      throw new DomainError("ERR-CD-01");
    }
  }

  const nextState = allGranted ? "GRANTED" : "DECLINED";
  const decided: ConsentDecisionRecord = { ...found, state: nextState, purposes };
  ports.repo.save(decided);

  for (const p of purposes) {
    ports.ledger.append({
      eventType: "PURPOSE_DECISION_RECORDED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { consentId, purpose: p.purpose, choice: p.choice },
      idempotencyKey: `${consentId}:purpose:${p.purpose}`,
    });
  }

  if (allGranted) {
    ports.ledger.append({
      eventType: "CONSENT_GRANTED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { consentId, chainRef: found.chainRef },
      idempotencyKey: `${consentId}:granted`,
    });
    ports.ledger.append({
      eventType: "RECEIPT_CREATED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { receiptRef: `receipt:${consentId}` },
      idempotencyKey: `${consentId}:receipt`,
    });
    markInvitationCompleted(ports.invitation, tenantId, found.invitationRef, consentId); // I6
  } else {
    ports.ledger.append({
      eventType: "CONSENT_DECLINED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { consentId, chainRef: found.chainRef },
      idempotencyKey: `${consentId}:declined`,
    });
    ports.ledger.append({
      eventType: "RECEIPT_CREATED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { receiptRef: `receipt:${consentId}` },
      idempotencyKey: `${consentId}:receipt`,
    });
    markInvitationDeclined(ports.invitation, tenantId, found.invitationRef, consentId); // I7
  }

  return decided;
}
