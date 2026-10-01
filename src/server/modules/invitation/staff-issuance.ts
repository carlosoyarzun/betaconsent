// Gobierna: specs/state-machines/invitation.spec.yaml I1 (CreateInvitation), I2
// (MarkInvitationReady), I3 (SendInvitation) y contracts/openapi API-CNS-110/111/112
// (POST /staff/invitations, /ready, /send). CA-125. Orquesta los guards que dependen del
// contexto de tenant (Guard P GRD-CM-03, Guard E GRD-CM-04, GRD-IV-02, GRD-IV-11) y delega la
// transición en invitation.ts (GRD-CM-05, GRD-IV-01, GRD-IV-03/04/05, ledger). GRD-CM-01/10
// (sesión, CSRF) y GRD-CM-08 (idempotencia) los aplica el entrypoint HTTP.
// No implementado en este corte: I3r (reenvío/rotación), I9 por INVITER, EN1.

import { randomUUID } from "node:crypto";

import { DomainError } from "../common/errors.ts";
import { assertRouteEligible } from "../common/guards.ts";
import type { ActorRole, TenantId } from "../common/types.ts";
import type { EnrollmentRepositoryPort } from "../../ports/enrollment-repository.port.ts";
import type { InvitationLinkChannelPort } from "../../ports/invitation-link-channel.port.ts";
import type { TenantCatalogPort } from "../../ports/tenant-catalog.port.ts";
import type { TenantTxPorts } from "../../ports/unit-of-work.port.ts";
import {
  createInvitationTx,
  invitationPortsInTx,
  markInvitationReadyTx,
  sendInvitationTx,
  type InvitationPorts,
} from "./invitation.ts";
import type { InvitationIssuancePolicy } from "./invitation-issuance-policy.config.ts";
import type { InvitationRecord } from "../../ports/invitation-repository.port.ts";

export interface StaffIssuancePorts {
  readonly invitation: InvitationPorts;
  readonly enrollmentRepo: EnrollmentRepositoryPort;
  readonly tenantCatalog: TenantCatalogPort;
  readonly invitationLinkChannel: InvitationLinkChannelPort;
  /** P-10 y deliveryChannel (EXT-B). Ausente = fail-closed en I2/I3 (ERR-CM-12). */
  readonly policy?: InvitationIssuancePolicy;
}

/** CA-124 PR-E (SEC-CNS-016): puertos de la consola STAFF ligados a UNA tx abierta del tenant. `invitation`,
 * `enrollmentRepo` y `tenantCatalog` son los de la tx (lecturas bajo RLS, nunca fuera de `inTenant`). */
export function staffIssuanceInTx(ports: StaffIssuancePorts, tx: TenantTxPorts): StaffIssuancePorts {
  return { ...ports, invitation: invitationPortsInTx(ports.invitation, tx), enrollmentRepo: tx.enrollmentRepo, tenantCatalog: tx.tenantCatalog };
}

export interface StaffCreateInvitationInput {
  readonly subjectRef: string;
  readonly enrollmentRef: string;
  readonly participationRef: string;
  readonly contextRef: string;
  readonly reissueOfRef?: string;
}

export interface StaffInvitationStepResult {
  readonly record: InvitationRecord;
  /** Sequence del último evento del agregado tras la transición (>= 1). */
  readonly sequence: number;
}

async function lastSequence(ports: InvitationPorts, tenantId: TenantId, invitationRef: string): Promise<number> {
  const events = await ports.ledger.listByAggregate(tenantId, "Invitation", invitationRef);
  return events.reduce((max, e) => Math.max(max, e.sequence), 0);
}

/**
 * I1: null -> DRAFT. Guards: GRD-IV-02 (subject/enrollment/participation del tenant y coherentes
 * entre sí, ERR-CM-01), GRD-CM-03 (Guard P, ERR-CM-03), GRD-CM-04 (Guard E, ERR-CM-04),
 * GRD-IV-11 (reemisión: P-11 sin valor aprobado en el repo => límite 0 fail-closed, ERR-IV-07),
 * y los de invitation.createInvitation (GRD-CM-05, GRD-CM-07, GRD-IV-01).
 * El productRef sale de la SchoolParticipation del tenant, nunca del body.
 */
export function staffCreateInvitation(
  ports: StaffIssuancePorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  input: StaffCreateInvitationInput,
): Promise<StaffInvitationStepResult> {
  return ports.invitation.uow.inTenant(tenantId, (tx) => staffCreateInvitationTx(staffIssuanceInTx(ports, tx), tenantId, actorRole, input));
}

/** I1 dentro de una tx ya abierta (puertos de `staffIssuanceInTx`): no abre `inTenant`. */
export async function staffCreateInvitationTx(
  ports: StaffIssuancePorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  input: StaffCreateInvitationInput,
): Promise<StaffInvitationStepResult> {
  const enrollment = await ports.enrollmentRepo.findByRef(tenantId, input.enrollmentRef);
  const participation = await ports.tenantCatalog.findParticipation(tenantId, input.participationRef);
  if (
    !enrollment ||
    !participation ||
    !await ports.tenantCatalog.subjectBelongsToTenant(tenantId, input.subjectRef) ||
    enrollment.subjectRef !== input.subjectRef ||
    enrollment.participationRef !== input.participationRef
  ) {
    throw new DomainError("ERR-CM-01"); // GRD-IV-02 (subject_belongs_to_tenant): 404 uniforme
  }
  if (participation.status !== "ACTIVE" || participation.contextRef !== input.contextRef) {
    throw new DomainError("ERR-CM-03"); // GRD-CM-03 (Guard P)
  }
  if (enrollment.state !== "ACTIVE") {
    throw new DomainError("ERR-CM-04"); // GRD-CM-04 (Guard E)
  }
  if (input.reissueOfRef !== undefined) {
    // GRD-IV-11: el límite P-11 no tiene valor en el repo; sin valor, fail-closed (rechazo hasta
    // revisión humana). FINDING P2 de CA-125.
    throw new DomainError("ERR-IV-07");
  }

  const invitationRef = randomUUID(); // INV-CM-09
  const record = await createInvitationTx(ports.invitation, tenantId, actorRole, {
    invitationRef,
    contextRef: input.contextRef,
    productRef: participation.productRef,
    subjectRef: input.subjectRef,
    enrollmentRef: input.enrollmentRef,
    participationRef: input.participationRef,
  });
  return { record, sequence: await lastSequence(ports.invitation, tenantId, invitationRef) };
}

export interface StaffMarkReadyInput {
  readonly consentVersion: string;
  readonly recipientBinding: "RECIPIENT_CHANNEL" | "UNBOUND";
  readonly recipientChannelRef?: string;
}

/** I2: DRAFT -> READY. expiresAt lo fija el servidor (P-10; nunca del cliente, GRD-IV-12). */
export function staffMarkInvitationReady(
  ports: StaffIssuancePorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  invitationRef: string,
  input: StaffMarkReadyInput,
): Promise<StaffInvitationStepResult> {
  return ports.invitation.uow.inTenant(tenantId, (tx) =>
    staffMarkInvitationReadyTx(staffIssuanceInTx(ports, tx), tenantId, actorRole, invitationRef, input),
  );
}

/** I2 dentro de una tx ya abierta (puertos de `staffIssuanceInTx`). */
export async function staffMarkInvitationReadyTx(
  ports: StaffIssuancePorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  invitationRef: string,
  input: StaffMarkReadyInput,
): Promise<StaffInvitationStepResult> {
  if (!ports.policy) throw new DomainError("ERR-CM-12");
  const existing = await ports.invitation.invitationRepo.findByRef(tenantId, invitationRef);
  if (!existing) throw new DomainError("ERR-CM-01");
  assertRouteEligible(await ports.invitation.eligibility.isEligibleForIssuance(tenantId, existing.contextRef, existing.productRef)); // GRD-CM-05
  const record = await markInvitationReadyTx(ports.invitation, tenantId, actorRole, invitationRef, {
    consentVersion: input.consentVersion,
    expiresAt: new Date(Date.now() + ports.policy.expiresInMs),
    recipientBinding: input.recipientBinding,
    ...(input.recipientChannelRef !== undefined ? { recipientChannelRef: input.recipientChannelRef } : {}),
  });
  return { record, sequence: await lastSequence(ports.invitation, tenantId, invitationRef) };
}

/**
 * I3: READY -> SENT. Guards de contexto: GRD-CM-03 (Guard P) y GRD-CM-04 (Guard E) se releen
 * aquí (se evalúan por request, DEC-BR-015:42) y GRD-CM-05 se evalúa por el puerto de
 * elegibilidad (sin caché, también en I2). Entrega el enlace SOLO por el
 * puerto de canal (sink IT0); el token nunca vuelve al llamador.
 */
export async function staffSendInvitation(
  ports: StaffIssuancePorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  invitationRef: string,
): Promise<StaffInvitationStepResult> {
  const { deliver, ...result } = await ports.invitation.uow.inTenant(tenantId, (tx) =>
    staffSendInvitationTx(staffIssuanceInTx(ports, tx), tenantId, actorRole, invitationRef),
  );
  await deliver(); // efecto externo DESPUÉS de confirmar: si la tx falla no sale ningún enlace
  return result;
}

export interface StaffSendInvitationTxResult extends StaffInvitationStepResult {
  /** Entrega el enlace por el puerto de canal. El llamador la ejecuta SOLO tras el COMMIT de la tx
   * (la tx puede reejecutarse; el efecto externo no es transaccional). El token solo vive en este cierre. */
  readonly deliver: () => Promise<void>;
}

/** I3 dentro de una tx ya abierta (puertos de `staffIssuanceInTx`); no entrega el enlace (ver `deliver`). */
export async function staffSendInvitationTx(
  ports: StaffIssuancePorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  invitationRef: string,
): Promise<StaffSendInvitationTxResult> {
  if (!ports.policy) throw new DomainError("ERR-CM-12");
  const found = await ports.invitation.invitationRepo.findByRef(tenantId, invitationRef);
  if (!found) throw new DomainError("ERR-CM-01");

  assertRouteEligible(await ports.invitation.eligibility.isEligibleForIssuance(tenantId, found.contextRef, found.productRef)); // GRD-CM-05
  if (found.participationRef !== undefined && found.enrollmentRef !== undefined) {
    const participation = await ports.tenantCatalog.findParticipation(tenantId, found.participationRef);
    if (!participation || participation.status !== "ACTIVE") throw new DomainError("ERR-CM-03"); // GRD-CM-03
    const enrollment = await ports.enrollmentRepo.findByRef(tenantId, found.enrollmentRef);
    if (!enrollment || enrollment.state !== "ACTIVE") throw new DomainError("ERR-CM-04"); // GRD-CM-04
  }

  const policy = ports.policy;
  const { record, token } = await sendInvitationTx(ports.invitation, tenantId, actorRole, invitationRef, {
    deliveryChannel: policy.deliveryChannel,
    expiresAt: new Date(Date.now() + policy.expiresInMs), // GRD-IV-12: SENT + P-10
  });
  const sequence = await lastSequence(ports.invitation, tenantId, invitationRef);
  return {
    record,
    sequence,
    deliver: () =>
      ports.invitationLinkChannel.send({
        invitationRef,
        invitationPath: `/i/${token}`,
        deliveryChannel: policy.deliveryChannel,
        ...(record.recipientChannelRef !== undefined ? { recipientChannelRef: record.recipientChannelRef } : {}),
      }),
  };
}
