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
import type { UnitOfWorkPort } from "../../ports/unit-of-work.port.ts";
import type { InvitationPorts } from "../invitation/invitation.ts";
import { invitationPortsInTx, markInvitationCompletedTx, markInvitationDeclinedTx } from "../invitation/invitation.ts";
import type { LectorProBetaConfig } from "./lectorpro-beta.config.ts";
import type { DecisionRelationshipConfig } from "./decision-relationship.config.ts";
import { deriveChainRef } from "./chain-ref.ts";
import { lastLedgerSequence, sequencedAppender } from "../common/ledger-append.ts";

export interface ConsentDecisionPorts {
  readonly repo: ConsentDecisionRepositoryPort;
  readonly ledger: LedgerPort;
  readonly invitation: InvitationPorts;
  /** CA-124 (diseño §5, SEC-CNS-015 P2-E): cada transición corre en UNA unidad de trabajo del tenant
   * (decisión + ledger + Invitation I6/I7 en la misma tx). Su tenancy comparte `repo` e
   * `invitation.invitationRepo` con este bag. */
  readonly uow: UnitOfWorkPort;
  readonly config: LectorProBetaConfig;
  /** GRD-CD-04: relationshipRef, opción (b) de Carlos (decision-relationship.config.ts). */
  readonly relationships: DecisionRelationshipConfig;
  /** SEC-CNS-017 F2: clave HMAC del chainRef opaco (chain-ref.ts deriveChainRefKey), por entorno. */
  readonly chainRefKey: Buffer;
}

const DECISION_MAKER_ROLE: readonly ActorRole[] = ["DECISION_MAKER"];

/** Ejecuta `fn` en una unidad de trabajo del tenant; dentro, `repo`, `ledger` e `invitation` son los de la
 * tx (SEC-CNS-015 P2-E). No se anida `inTenant`; `fn` puede reejecutarse si la unidad se reintenta. */
function inTx<T>(ports: ConsentDecisionPorts, tenantId: TenantId, fn: (txPorts: ConsentDecisionPorts) => Promise<T>): Promise<T> {
  return ports.uow.inTenant(tenantId, (tx) =>
    fn({ ...ports, repo: tx.consentDecisionRepo, ledger: tx.ledger, invitation: invitationPortsInTx(ports.invitation, tx) }),
  );
}

/** Secuencia vigente de la decision: se lee ANTES de bloquear/leer el estado (SEC-CNS-015 P2-E). */
const decisionSequence = (ports: ConsentDecisionPorts, tenantId: TenantId, consentId: string): Promise<number> =>
  lastLedgerSequence(ports.ledger, tenantId, consentId);

/** Relee la decision CON lock de fila (SEC-CNS-015 P2-E): la transicion se decide sobre el estado bloqueado. */
async function requireDecision(ports: ConsentDecisionPorts, tenantId: TenantId, consentId: string): Promise<ConsentDecisionRecord> {
  const found = await ports.repo.findByConsentIdForUpdate(tenantId, consentId);
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
): Promise<ConsentDecisionRecord> {
  return inTx(ports, tenantId, (p) => startDecisionTx(p, tenantId, actorRole, input));
}

async function startDecisionTx(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  input: StartDecisionInput,
): Promise<ConsentDecisionRecord> {
  assertActorRoleIn(actorRole, DECISION_MAKER_ROLE); // GRD-CM-07

  const invitation = await ports.invitation.invitationRepo.findByRefForUpdate(tenantId, input.invitationRef); // lock: C1 decide sobre la Invitation (SEC-CNS-016 P2-4)
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
    chainRef: deriveChainRef(ports.chainRefKey, tenantId, invitation.contextRef, invitation.subjectRef, input.decisionMakerRef),
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
export function recordDecisionStep(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  decisionMakerRef: string,
  consentId: string,
  step: DecisionStepInput,
): Promise<ConsentDecisionRecord> {
  return inTx(ports, tenantId, (p) => recordDecisionStepTx(p, tenantId, actorRole, decisionMakerRef, consentId, step));
}

async function recordDecisionStepTx(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  decisionMakerRef: string,
  consentId: string,
  step: DecisionStepInput,
): Promise<ConsentDecisionRecord> {
  const base = await decisionSequence(ports, tenantId, consentId);
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
    expectedSequence: base,
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
export function submitDecision(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  decisionMakerRef: string,
  consentId: string,
  purposes: readonly PurposeDecision[],
): Promise<ConsentDecisionRecord> {
  return inTx(ports, tenantId, (p) => submitDecisionTx(p, tenantId, actorRole, decisionMakerRef, consentId, purposes));
}

/** C3/C5 en UNA tx con lock de fila y base previa: los k eventos de la decision declaran base + k
 * (sequencedAppender) y I6/I7 corre en la misma tx con su propio lock y base de la Invitation. */
async function submitDecisionTx(
  ports: ConsentDecisionPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  decisionMakerRef: string,
  consentId: string,
  purposes: readonly PurposeDecision[],
): Promise<ConsentDecisionRecord> {
  const base = await decisionSequence(ports, tenantId, consentId);
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

  const seq = sequencedAppender(ports.ledger, base);
  for (const p of purposes) {
    await seq.append({
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
    await seq.append({
      eventType: "CONSENT_GRANTED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { consentId, chainRef: found.chainRef },
      idempotencyKey: `${consentId}:granted`,
    });
    await seq.append({
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
    await markInvitationCompletedTx(ports.invitation, tenantId, found.invitationRef, consentId); // I6
  } else {
    await seq.append({
      eventType: "CONSENT_DECLINED",
      tenantId,
      aggregateType: "ConsentDecision",
      aggregateId: consentId,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { consentId, chainRef: found.chainRef },
      idempotencyKey: `${consentId}:declined`,
    });
    await seq.append({
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
    await markInvitationDeclinedTx(ports.invitation, tenantId, found.invitationRef, consentId); // I7
  }

  return decided;
}
