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
  /** CA-125: refs que el contrato exige en I1 (CreateInvitationRequest); opcionales para los
   * llamadores legacy (fixtures) que no pasan por la API de staff. */
  readonly enrollmentRef?: string;
  readonly participationRef?: string;
  readonly reissueOfRef?: string;
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
    ...(input.enrollmentRef !== undefined ? { enrollmentRef: input.enrollmentRef } : {}),
    ...(input.participationRef !== undefined ? { participationRef: input.participationRef } : {}),
    ...(input.reissueOfRef !== undefined ? { reissueOfRef: input.reissueOfRef } : {}),
  };
  ports.invitationRepo.save(record);
  ports.ledger.append({
    eventType: "INVITATION_CREATED",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: record.invitationRef,
    actorType: "HUMAN",
    actorRole: "INVITER",
    // ledger-event-payloads.schema.json#/$defs/INVITATION_CREATED exige participationRef,
    // enrollmentRef y reissueOfRef (nullable). Con la API de staff (CA-125) el payload es completo;
    // los llamadores legacy sin esas refs conservan el payload anterior (discrepancia previa,
    // documentada en tests/contract/ledger/ledger-event-payloads-contract.test.ts).
    payload:
      input.participationRef !== undefined && input.enrollmentRef !== undefined
        ? {
            invitationRef: record.invitationRef,
            participationRef: input.participationRef,
            enrollmentRef: input.enrollmentRef,
            subjectRef: record.subjectRef,
            reissueOfRef: input.reissueOfRef ?? null,
          }
        : { invitationRef: record.invitationRef, subjectRef: record.subjectRef },
    idempotencyKey: record.invitationRef,
  });
  return record;
}

export interface MarkInvitationReadyInput {
  readonly consentVersion: string;
  readonly expiresAt: Date;
  /** GRD-OT-02: único canal al que V1 podrá enviar el OTP de esta invitación. Obligatorio si y
   * solo si recipientBinding = RECIPIENT_CHANNEL (GRD-IV-03). */
  readonly recipientChannelRef?: string;
  /** CA-125: default RECIPIENT_CHANNEL (comportamiento legacy). UNBOUND: sin canal esperado. */
  readonly recipientBinding?: "RECIPIENT_CHANNEL" | "UNBOUND";
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
  const recipientBinding = input.recipientBinding ?? "RECIPIENT_CHANNEL";
  const channelOk =
    recipientBinding === "RECIPIENT_CHANNEL" ? Boolean(input.recipientChannelRef) : input.recipientChannelRef === undefined;
  if (!input.consentVersion || !input.expiresAt || !channelOk) {
    // GRD-IV-03 (ready_fields_fixed): recipientChannelRef si y solo si RECIPIENT_CHANNEL.
    throw new DomainError("ERR-IV-03");
  }

  const ready: InvitationRecord = {
    ...found,
    state: "READY",
    consentVersion: input.consentVersion,
    expiresAt: input.expiresAt,
    recipientBinding,
    ...(input.recipientChannelRef !== undefined ? { recipientChannelRef: input.recipientChannelRef } : {}),
  };
  ports.invitationRepo.save(ready);
  ports.ledger.append({
    eventType: "INVITATION_READY",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: invitationRef,
    actorType: "HUMAN",
    actorRole: "INVITER",
    // ledger-event-payloads.schema.json#/$defs/INVITATION_READY exige también expiresAt y
    // recipientBinding (P1: faltaban).
    payload: {
      invitationRef,
      consentVersion: input.consentVersion,
      expiresAt: input.expiresAt.toISOString(),
      recipientBinding,
    },
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

export interface SendInvitationOptions {
  /** CA-125: INVITATION_SENT.deliveryChannel (EXT-B, sin fijar): lo inyecta la política del
   * entrypoint. Sin él, el payload legacy (sin deliveryChannel) se conserva para fixtures. */
  readonly deliveryChannel?: "SCHOOL_CHANNEL" | "CONSENT_APP_EMAIL";
  /** CA-125 (GRD-IV-12): expiresAt = SENT + P-10, calculado por el servidor; reemplaza el de I2. */
  readonly expiresAt?: Date;
}

/** I3: READY -> SENT. Guards cubiertos: GRD-CM-02, GRD-CM-07, GRD-IV-04 (parcial), GRD-IV-05. */
export function sendInvitation(
  ports: InvitationPorts,
  tenantId: TenantId,
  actorRole: ActorRole,
  invitationRef: string,
  options: SendInvitationOptions = {},
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
  const expiresAt = options.expiresAt ?? found.expiresAt;
  const sent: InvitationRecord = { ...found, state: "SENT", tokenHash, ...(expiresAt !== undefined ? { expiresAt } : {}) };
  ports.invitationRepo.save(sent);
  ports.ledger.append({
    eventType: "INVITATION_SENT",
    tenantId,
    aggregateType: "Invitation",
    aggregateId: invitationRef,
    actorType: "HUMAN",
    actorRole: "INVITER",
    payload: {
      invitationRef,
      ...(options.deliveryChannel !== undefined ? { deliveryChannel: options.deliveryChannel } : {}),
      expiresAt: expiresAt?.toISOString(),
    },
    idempotencyKey: `${invitationRef}:sent`,
  });
  return { record: sent, token };
}

/** Efecto compartido de I4 (SENT -> OPENED), sin resolver el token: ambas vías de entrada
 * (openInvitation por token, openInvitationByRef por sesión ya resuelta en el GET de canje)
 * terminan aquí. Guards: GRD-IV-07 (expiración), GRD-IV-08 (first_post_only, idempotente). */
function transitionInvitationToOpened(ports: InvitationPorts, tenantId: TenantId, found: InvitationRecord): InvitationRecord {
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

/** I4: SENT -> OPENED, resolviendo el token en el mismo paso. Guards: GRD-IV-07, GRD-IV-08.
 * Uso: pruebas de dominio y cualquier llamador que aún tenga el token en mano. El flujo HTTP
 * (P-12, GET /i/{token} + POST /invitation/open) usa `openInvitationByRef` en su lugar, porque
 * el POST del contrato (EmptyCommand) nunca vuelve a recibir el token. */
export function openInvitation(ports: InvitationPorts, tenantId: TenantId, token: string): InvitationRecord {
  const tokenHash = hashToken(token);
  const found = ports.invitationRepo.findByTokenHash(tokenHash);
  if (!found || found.tenantId !== tenantId) {
    // GRD-IV-07: token inexistente, o de otro tenant -> 404 uniforme (ERR-IV-01).
    throw new DomainError("ERR-IV-01");
  }
  return transitionInvitationToOpened(ports, tenantId, found);
}

/** I4 vía sesión (P-12): el GET /i/{token} ya resolvió el token (GRD-IV-07), creó la sesión
 * LANDING con (tenantId, invitationRef) y descartó el token. Este POST transiciona por esa
 * referencia; nunca recibe ni vuelve a resolver el token (contracts/openapi EmptyCommand). */
export function openInvitationByRef(ports: InvitationPorts, tenantId: TenantId, invitationRef: string): InvitationRecord {
  const found = requireInvitation(ports, tenantId, invitationRef); // ERR-CM-01 si no existe o es de otro tenant
  return transitionInvitationToOpened(ports, tenantId, found);
}

/** GET /i/{token} (P-12, API-CNS-101): resuelve el token por su hash sin transicionar
 * (INV-CM-08) ni tocar el ledger. Devuelve `null` si el hash no resuelve o si la invitación ya
 * está expirada (GRD-IV-07); el llamador SIEMPRE trata `null` como 404 uniforme, sin distinguir
 * el motivo. GRD-IV-13 (cascada de cancelación pendiente) sigue diferido: requiere
 * tenant-context, fuera del alcance de este archivo (ver cabecera). */
export function resolveInvitationForRedeem(ports: InvitationPorts, token: string): InvitationRecord | null {
  return resolveInvitationForRedeemByHash(ports, hashToken(token));
}

/** GET /welcome (SEC-CNS-014 patrón, Carlos 2026-09-28): variante de resolveInvitationForRedeem
 * que resuelve DIRECTAMENTE por el hash ya fijado por GET /i/{token} (link-handle.ts), sin
 * volver a hashear un token en claro que ese GET ya no conserva (INV-CM-08 reforzado: el GET de
 * canje deja de leer la BD, consent-flow.handler.ts handleRedeemInvitationLink). Mismo
 * predicado que resolveInvitationForRedeem (GRD-IV-07: expiración), sin efectos. */
export function resolveInvitationForRedeemByHash(ports: InvitationPorts, tokenHash: string): InvitationRecord | null {
  const found = ports.invitationRepo.findByTokenHash(tokenHash);
  if (!found) return null;
  if (found.expiresAt && found.expiresAt.getTime() <= Date.now()) return null;
  return found;
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
