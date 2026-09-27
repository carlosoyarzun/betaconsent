// Gobierna: specs/state-machines/invitation.spec.yaml (I1 CreateInvitation, I2
// MarkInvitationReady, I3 SendInvitation, I4 OpenInvitation, I5/I6/I7 internos) y
// specs/state-machines/common.spec.yaml (GRD-CM-02, GRD-CM-05, GRD-CM-07). Alcance IT0 de
// este archivo (subconjunto mínimo, TEST-CNS-475 en adelante): llega hasta OPENED (habilita
// otp-challenge V1) y expone I5/I6/I7 para que otp-challenge y consent-decision los disparen
// en el mismo lote lógico. No implementa I3r (rotación), I7u (deshabilitada en BETA_2026_01),
// I8 (expiración por barrido) ni I9 (cancelación); tampoco GRD-IV-02 (pertenencia real de
// subjectRef/enrollmentRef al tenant, requiere tenant-context), GRD-IV-06/11 (límites de
// rotación/reemisión) ni GRD-IV-13 (cascada de cancelación pendiente, requiere
// tenant-context). Ver reporte de la tarea para el detalle de lo diferido.

import { createHash, randomBytes } from "node:crypto";

import { DomainError } from "../common/errors.ts";
import { assertActorRoleIn, assertRouteEligible, assertTenantConsistency } from "../common/guards.ts";
import type { ActorRole, TenantId } from "../common/types.ts";
import type { EligibilityPort } from "../../ports/eligibility.port.ts";
import type { InvitationRecord, InvitationRepositoryPort } from "../../ports/invitation-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";

export interface InvitationPorts {
  readonly invitationRepo: InvitationRepositoryPort;
  readonly eligibility: EligibilityPort;
  readonly ledger: LedgerPort;
}

const INVITER_ROLES: readonly ActorRole[] = ["INVITER"];

function requireInvitation(ports: InvitationPorts, tenantId: TenantId, invitationRef: string): InvitationRecord {
  const found = ports.invitationRepo.findByRef(tenantId, invitationRef);
  if (!found) {
    // GRD-CM-01: invitationRef inexistente o de otro tenant -> 404 uniforme.
    throw new DomainError("ERR-CM-01");
  }
  assertTenantConsistency(found.tenantId, tenantId); // GRD-CM-02 (Guard T)
  return found;
}

export interface CreateInvitationInput {
  readonly invitationRef: string;
  readonly contextRef: string;
  readonly productRef: string;
  readonly subjectRef: string;
}

/** I1: DRAFT. Guards cubiertos: GRD-CM-05, GRD-CM-07, GRD-IV-01. */
export function createInvitation(
  ports: InvitationPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  input: CreateInvitationInput,
): InvitationRecord {
  assertActorRoleIn(actorRole, INVITER_ROLES); // GRD-CM-07
  assertRouteEligible(ports.eligibility.isEligibleForIssuance(tenantId, input.contextRef, input.productRef)); // GRD-CM-05

  const activeExisting = ports.invitationRepo.findActiveBySubject(tenantId, input.contextRef, input.subjectRef);
  if (activeExisting) {
    // GRD-IV-01 (single_non_terminal_invitation).
    throw new DomainError("ERR-IV-02");
  }

  const record: InvitationRecord = {
    invitationRef: input.invitationRef,
    tenantId,
    contextRef: input.contextRef,
    productRef: input.productRef,
    subjectRef: input.subjectRef,
    state: "DRAFT",
  };
  ports.invitationRepo.save(record);
  ports.ledger.append({
    eventType: "INVITATION_CREATED",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: record.invitationRef,
    actorType: "HUMAN",
    actorRole: "INVITER",
    payload: { invitationRef: record.invitationRef, subjectRef: record.subjectRef },
    idempotencyKey: record.invitationRef,
  });
  return record;
}

export interface MarkInvitationReadyInput {
  readonly consentVersion: string;
  readonly expiresAt: Date;
  /** GRD-OT-02: único canal al que V1 podrá enviar el OTP de esta invitación. */
  readonly recipientChannelRef: string;
}

/** I2: DRAFT -> READY. Guards cubiertos: GRD-CM-02, GRD-CM-07, GRD-IV-03. */
export function markInvitationReady(
  ports: InvitationPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  invitationRef: string,
  input: MarkInvitationReadyInput,
): InvitationRecord {
  const found = requireInvitation(ports, tenantId, invitationRef);
  assertActorRoleIn(actorRole, INVITER_ROLES);

  if (found.state !== "DRAFT") {
    throw new DomainError("ERR-CM-06");
  }
  if (!input.consentVersion || !input.expiresAt || !input.recipientChannelRef) {
    // GRD-IV-03 (ready_fields_fixed).
    throw new DomainError("ERR-IV-03");
  }

  const ready: InvitationRecord = {
    ...found,
    state: "READY",
    consentVersion: input.consentVersion,
    expiresAt: input.expiresAt,
    recipientChannelRef: input.recipientChannelRef,
  };
  ports.invitationRepo.save(ready);
  ports.ledger.append({
    eventType: "INVITATION_READY",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: invitationRef,
    actorType: "HUMAN",
    actorRole: "INVITER",
    payload: { invitationRef, consentVersion: input.consentVersion },
    idempotencyKey: `${invitationRef}:ready`,
  });
  return ready;
}

export interface SendInvitationResult {
  readonly record: InvitationRecord;
  /** Token opaco en claro; el llamador lo entrega al sink de envío y lo descarta (GRD-IV-05: solo tokenHash persiste). */
  readonly token: string;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Expuesto para que el entrypoint HTTP resuelva el tenantId de un token de invitación antes
 * de llamar openInvitation (GRD-IV-07: igualdad exacta del hash, nunca del token en claro). */
export function hashInvitationToken(token: string): string {
  return hashToken(token);
}

/** I3: READY -> SENT. Guards cubiertos: GRD-CM-02, GRD-CM-07, GRD-IV-04 (parcial), GRD-IV-05. */
export function sendInvitation(
  ports: InvitationPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  invitationRef: string,
): SendInvitationResult {
  const found = requireInvitation(ports, tenantId, invitationRef);
  assertActorRoleIn(actorRole, INVITER_ROLES);

  if (found.state !== "READY") {
    throw new DomainError("ERR-CM-06");
  }
  if (!found.consentVersion) {
    // GRD-IV-04 (version_and_mode_guards), subconjunto: exige consentVersion fijada.
    throw new DomainError("ERR-IV-04");
  }

  const token = randomBytes(32).toString("hex"); // GRD-IV-05: CSPRNG, opaco, no JWT.
  const tokenHash = hashToken(token);
  const sent: InvitationRecord = { ...found, state: "SENT", tokenHash };
  ports.invitationRepo.save(sent);
  ports.ledger.append({
    eventType: "INVITATION_SENT",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: invitationRef,
    actorType: "HUMAN",
    actorRole: "INVITER",
    payload: { invitationRef, expiresAt: found.expiresAt?.toISOString() },
    idempotencyKey: `${invitationRef}:sent`,
  });
  return { record: sent, token };
}

/** I4: SENT -> OPENED (primer POST del portador tras el canje del token). Guards: GRD-IV-07, GRD-IV-08. */
export function openInvitation(ports: InvitationPorts, tenantId: TenantId, token: string): InvitationRecord {
  const tokenHash = hashToken(token);
  const found = ports.invitationRepo.findByTokenHash(tokenHash);
  if (!found || found.tenantId !== tenantId) {
    // GRD-IV-07: token inexistente, o de otro tenant -> 404 uniforme (ERR-IV-01).
    throw new DomainError("ERR-IV-01");
  }
  if (found.expiresAt && found.expiresAt.getTime() <= Date.now()) {
    throw new DomainError("ERR-IV-01");
  }
  if (found.state === "OPENED") {
    // GRD-IV-08 (first_post_only): un segundo POST no vuelve a transicionar ni duplica el evento.
    return found;
  }
  if (found.state !== "SENT") {
    throw new DomainError("ERR-CM-06");
  }

  const opened: InvitationRecord = { ...found, state: "OPENED" };
  ports.invitationRepo.save(opened);
  ports.ledger.append({
    eventType: "INVITATION_OPENED",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: found.invitationRef,
    actorType: "HUMAN",
    actorRole: "UNVERIFIED_BEARER",
    payload: { invitationRef: found.invitationRef },
    idempotencyKey: `${found.invitationRef}:opened`,
  });
  return opened;
}

/** I5 (interno, disparado por otp-challenge V3): OPENED -> VERIFIED. */
export function markInvitationVerified(
  ports: InvitationPorts,
  tenantId: TenantId,
  invitationRef: string,
  decisionMakerRef: string,
  verificationRef: string,
): InvitationRecord {
  const found = requireInvitation(ports, tenantId, invitationRef);
  if (found.state !== "OPENED") {
    throw new DomainError("ERR-CM-06");
  }
  const verified: InvitationRecord = { ...found, state: "VERIFIED", boundDecisionMakerRef: decisionMakerRef };
  ports.invitationRepo.save(verified);
  ports.ledger.append({
    eventType: "INVITATION_VERIFIED",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: invitationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { invitationRef, verificationRef, decisionMakerRef },
    idempotencyKey: `${invitationRef}:${verificationRef}`,
  });
  return verified;
}

/** I6 (interno, disparado por consent-decision C3): VERIFIED -> COMPLETED. */
export function markInvitationCompleted(
  ports: InvitationPorts,
  tenantId: TenantId,
  invitationRef: string,
  consentId: string,
): InvitationRecord {
  const found = requireInvitation(ports, tenantId, invitationRef);
  if (found.state !== "VERIFIED") {
    throw new DomainError("ERR-CM-06");
  }
  const completed: InvitationRecord = { ...found, state: "COMPLETED" };
  ports.invitationRepo.save(completed);
  ports.ledger.append({
    eventType: "INVITATION_COMPLETED",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: invitationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { invitationRef, consentId },
    idempotencyKey: `${invitationRef}:completed`,
  });
  return completed;
}

/** I7 (interno, disparado por consent-decision C5): VERIFIED -> DECLINED. */
export function markInvitationDeclined(
  ports: InvitationPorts,
  tenantId: TenantId,
  invitationRef: string,
  consentId: string,
): InvitationRecord {
  const found = requireInvitation(ports, tenantId, invitationRef);
  if (found.state !== "VERIFIED") {
    throw new DomainError("ERR-CM-06");
  }
  const declined: InvitationRecord = { ...found, state: "DECLINED" };
  ports.invitationRepo.save(declined);
  ports.ledger.append({
    eventType: "INVITATION_DECLINED",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: invitationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { invitationRef, consentId },
    idempotencyKey: `${invitationRef}:declined`,
  });
  return declined;
}
