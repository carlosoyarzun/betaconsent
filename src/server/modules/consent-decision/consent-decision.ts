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

import { randomUUID } from "node:crypto";

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
import type { DecisionRelationshipConfig } from "./decision-relationship.config.ts";

export interface ConsentDecisionPorts {
  readonly repo: ConsentDecisionRepositoryPort;
  readonly ledger: LedgerPort;
  readonly invitation: InvitationPorts;
  readonly config: LectorProBetaConfig;
  /** GRD-CD-04: relationshipRef, opción (b) de Carlos (decision-relationship.config.ts). */
  readonly relationships: DecisionRelationshipConfig;
}

const DECISION_MAKER_ROLE: readonly ActorRole[] = ["DECISION_MAKER"];

function deriveChainRef(tenantId: TenantId, contextRef: string, subjectRef: string, decisionMakerRef: string): string {
  // decisionChainKey = (tenantRef, contextRef, subjectRef, decisionMakerRef); opaco (ADR-002 §10).
  return `chain:${tenantId}:${contextRef}:${subjectRef}:${decisionMakerRef}`;
}

async function requireDecision(ports: ConsentDecisionPorts, tenantId: TenantId, consentId: string): Promise<ConsentDecisionRecord> {
  const found = await ports.repo.findByConsentId(tenantId, consentId);
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
export async function startDecision(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  input: StartDecisionInput,
): Promise<ConsentDecisionRecord> {
  assertActorRoleIn(actorRole, DECISION_MAKER_ROLE); // GRD-CM-07

  const invitation = await ports.invitation.invitationRepo.findByRef(tenantId, input.invitationRef);
  if (!invitation) {
    throw new DomainError("ERR-CM-01");
  }
  assertTenantConsistency(invitation.tenantId, tenantId); // GRD-CM-02

  if (invitation.state !== "VERIFIED" || invitation.boundDecisionMakerRef !== input.decisionMakerRef) {
    // GRD-CD-01/02 (decision_session_valid, invitation_verified).
    throw new DomainError("ERR-CD-07");
  }
  assertRouteEligible(
    await ports.invitation.eligibility.isEligibleForIssuance(tenantId, invitation.contextRef, invitation.productRef),
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
    stepsRecorded: [],
  };
  await ports.repo.save(record);
  // C1 emits: [] (SM-CNS-001 §4 C1): sin evento de ledger propio.
  return record;
}

/** stepKind de contracts/schemas/api-payloads.schema.json DecisionStepRequest (:413-487). */
export type DecisionStepInput =
  | { readonly stepKind: "CONTEXT_INFORMATION_VIEWED" }
  | { readonly stepKind: "CONSENT_VERSION_VIEWED" }
  | {
      readonly stepKind: "DECISION_MAKER_AUTHORITY_DECLARED";
      /** PENDING DEC-BR-003 / EXT-A / LD-01 (enum legal); aquí solo se valida contra
       * ports.relationships.allowedRelationshipRefs (opción b de Carlos, 2026-09-27). */
      readonly relationshipRef: string;
      /** Declaración explícita, sin preselección (P06; GRD-CD-04). */
      readonly authorityDeclared: true;
    }
  | { readonly stepKind: "SUBJECT_CONFIRMED"; readonly subjectConfirmed: true };

/** GRD-CD-05 (consent-decision.spec.yaml:298-303): CONTEXT_INFORMATION_VIEWED no es requerido,
 * solo aparece en `emits` de C2 (handoff §4). */
const REQUIRED_STEP_KINDS: readonly DecisionStepInput["stepKind"][] = [
  "CONSENT_VERSION_VIEWED",
  "DECISION_MAKER_AUTHORITY_DECLARED",
  "SUBJECT_CONFIRMED",
];

function isStepsComplete(stepsRecorded: readonly string[]): boolean {
  return REQUIRED_STEP_KINDS.every((kind) => stepsRecorded.includes(kind));
}

/** C2: registra un paso (PENDING -> PENDING). Guards: GRD-CM-02, GRD-CM-05, GRD-CM-10,
 * GRD-CD-01, GRD-CD-03, GRD-CD-04. Reemplaza el antiguo `recordRequiredSteps` (que marcaba los
 * 4 pasos como completos sin ninguna entrada real del usuario, violando GRD-CD-04): ahora cada
 * paso se registra uno a uno con los datos reales que exige DecisionStepRequest. */
export async function recordDecisionStep(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  decisionMakerRef: string,
  consentId: string,
  step: DecisionStepInput,
): Promise<ConsentDecisionRecord> {
  const found = await requireDecision(ports, tenantId, consentId);
  assertActorRoleIn(actorRole, DECISION_MAKER_ROLE); // GRD-CM-10
  if (found.decisionMakerRef !== decisionMakerRef) {
    // Mismo patrón que submitDecision: solo el DecisionMaker verificado de esta cadena.
    throw new DomainError("ERR-CM-10");
  }
  if (found.state !== "PENDING") {
    throw new DomainError("ERR-CM-06");
  }

  if (step.stepKind === "DECISION_MAKER_AUTHORITY_DECLARED") {
    // GRD-CD-04 (relationship_and_authority_declaration, onFail ERR-CD-04): authorityDeclared
    // explícito (P06, sin preselección: el tipo ya exige `true` literal) y relationshipRef en
    // la lista permitida por configuración (opción b, decision-relationship.config.ts).
    if (step.authorityDeclared !== true || !ports.relationships.allowedRelationshipRefs.includes(step.relationshipRef)) {
      throw new DomainError("ERR-CD-04");
    }
  }
  if (step.stepKind === "SUBJECT_CONFIRMED" && step.subjectConfirmed !== true) {
    throw new DomainError("ERR-CD-04");
  }

  const payload: Record<string, unknown> = { consentId };
  if (step.stepKind === "DECISION_MAKER_AUTHORITY_DECLARED") {
    payload.relationshipRef = step.relationshipRef;
  }
  if (step.stepKind === "SUBJECT_CONFIRMED") {
    payload.subjectRef = found.subjectRef;
  }

  await ports.ledger.append({
    eventType: step.stepKind,
    tenantId,
    aggregateType: "ConsentDecision",
    aggregateId: consentId,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload,
    idempotencyKey: `${consentId}:${step.stepKind}`,
  });

  const stepsRecorded = found.stepsRecorded.includes(step.stepKind)
    ? found.stepsRecorded
    : [...found.stepsRecorded, step.stepKind];
  const updated: ConsentDecisionRecord = {
    ...found,
    stepsRecorded,
    priorStepsComplete: isStepsComplete(stepsRecorded),
  };
  await ports.repo.save(updated);
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
export async function submitDecision(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  decisionMakerRef: string,
  consentId: string,
  purposes: readonly PurposeDecision[],
): Promise<ConsentDecisionRecord> {
  const found = await requireDecision(ports, tenantId, consentId);
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
    await ports.invitation.eligibility.isEligibleForIssuance(tenantId, found.contextRef, found.productRef),
  ); // GRD-CD-12 (context_guards_at_submit, re-evaluado)

  validatePurposes(ports.config, purposes); // GRD-CD-06/07

  const allGranted = ports.config.requiredPurposes.every(
    (purpose) => purposes.find((p) => p.purpose === purpose)?.choice === "GRANT",
  );

  if (allGranted) {
    const existingGrant = await ports.repo.findActiveGrantByChain(tenantId, found.chainRef);
    if (existingGrant) {
      // GRD-CD-08 (single_active_grant_per_chain, INV-1).
      throw new DomainError("ERR-CD-01");
    }
  }

  const nextState = allGranted ? "GRANTED" : "DECLINED";
  // receiptRef (contracts/api-payloads.schema.json DecisionRecorded, common.schema.json Ref):
  // opaco UUIDv4. El MISMO valor se usa en el evento RECEIPT_CREATED del ledger (P1: antes
  // usaba `receipt:${consentId}`, con un formato distinto del Ref que exige
  // ledger-event-payloads.schema.json:415-430 y sin relación con lo que expone la respuesta
  // HTTP).
  const receiptRef = randomUUID();
  const decided: ConsentDecisionRecord = { ...found, state: nextState, purposes, receiptRef };
  await ports.repo.save(decided);

  for (const p of purposes) {
    await ports.ledger.append({
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
    await ports.ledger.append({
      eventType: "CONSENT_GRANTED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { consentId, chainRef: found.chainRef },
      idempotencyKey: `${consentId}:granted`,
    });
    await ports.ledger.append({
      eventType: "RECEIPT_CREATED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      // managementLinkIssued: false es el valor factual de este slice IT0: el
      // management_token nunca se emite todavía (x-scope-note, consent-flow.handler.ts).
      payload: { receiptRef, managementLinkIssued: false },
      idempotencyKey: `${consentId}:receipt`,
    });
    await markInvitationCompleted(ports.invitation, tenantId, found.invitationRef, consentId); // I6
  } else {
    await ports.ledger.append({
      eventType: "CONSENT_DECLINED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { consentId, chainRef: found.chainRef },
      idempotencyKey: `${consentId}:declined`,
    });
    await ports.ledger.append({
      eventType: "RECEIPT_CREATED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      // managementLinkIssued: false es el valor factual de este slice IT0: el
      // management_token nunca se emite todavía (x-scope-note, consent-flow.handler.ts).
      payload: { receiptRef, managementLinkIssued: false },
      idempotencyKey: `${consentId}:receipt`,
    });
    await markInvitationDeclined(ports.invitation, tenantId, found.invitationRef, consentId); // I7
  }

  return decided;
}
