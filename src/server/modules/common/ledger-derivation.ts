// Gobierna: ADR-010 rev. 5 §4.2.b (capa 1; LG-1..LG-10; aceptada por Carlos el 2026-10-15 para IT0b), specs/ledger-derivation.spec.yaml (tabla OLD->NEW: UNICA fuente de la emision),
// condiciones F-PR6-22/23/28/30. specs/db-roles.spec.yaml INV-DBR-07.
//
// Funcion TS PURA que deriva los eventos del ledger de un cambio de fila (OLD -> NEW) por agregado. Misma tabla que implementan los triggers de la base (db/migrations/0047..0049, esquema
// ledger_gen, rol ledger_writer). Sirve a DOS usos y a ninguno mas:
//   1. el adaptador in-memory de la unidad de trabajo (in-memory-unit-of-work.adapter.ts) emite con ella los mismos eventos que la base (el dominio ya no llama a `ledger.append` para estos agregados);
//   2. ORACULO de los vectores dorados TS<->SQL (tests/integration/postgres/adr010-ledger-pr-b-*.test.ts): la base y esta funcion deben producir los mismos eventos, claves y payloads.
// NO decide si hubo consentimiento, si el OTP es valido ni la autorizacion del tenant: registra transiciones ya decididas por el dominio y por las guardas de la base (§32 de Master Plan).
// Las guardas (estado inicial, grafo, inmutables, cruces) viven SOLO en la base (BEFORE, SECURITY INVOKER); esta funcion es tolerante: una arista fuera de la tabla no emite nada.
//
// Aristas "permitidas sin emision de ledger_writer" (declaradas en la spec, F-PR6-10/22): C6 (consent_decision GRANTED -> REVOKED; la emite transition_owner por apply_revocation) e I9
// (invitation * -> CANCELLED; la emite transition_owner por case_state.cancel_invitation_subject_mismatch, Q-18-I9). Aqui devuelven [].

import { BINDING_RESULT_PLACEHOLDER_OPEN_CT03 } from "./opaque-ref.ts";
import type { ActorRole, ActorType } from "./types.ts";
import type { EnrollmentRecord } from "../../ports/enrollment-repository.port.ts";
import type { InvitationRecord } from "../../ports/invitation-repository.port.ts";
import type { OtpVerificationRecord } from "../../ports/otp-verification-repository.port.ts";

export interface DerivedLedgerEvent {
  readonly eventType: string;
  readonly aggregateType: string;
  readonly aggregateId: string;
  readonly actorType: ActorType;
  readonly actorRole?: ActorRole;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly idempotencyKey: string;
}

export type LedgerEmitter = "ledger_writer" | "transition_owner" | "none";

/** Una fila de la tabla OLD->NEW de specs/ledger-derivation.spec.yaml. `from` null = INSERT. `emits` = pares `Agregado:EVENTO` en orden. */
export interface DerivationEdge {
  readonly id: string;
  readonly aggregate: string;
  readonly from: string | null;
  readonly to: string;
  readonly emits: readonly string[];
  readonly emitter: LedgerEmitter;
}

export const LEDGER_DERIVATION_EDGES: readonly DerivationEdge[] = [
  // Enrollment (EN0). ACTIVE -> CLOSED NO es una arista (F-PRB-03: closeReason pendiente, EN1 no implementado).
  { id: "EN0", aggregate: "Enrollment", from: null, to: "ACTIVE", emits: ["Enrollment:ENROLLMENT_STATUS_CHANGED"], emitter: "ledger_writer" },
  // otp_verification (DecisionMakerVerification), todos los scopes.
  { id: "V3", aggregate: "DecisionMakerVerification", from: "CODE_SENT", to: "VERIFIED", emits: ["DecisionMakerVerification:DECISION_MAKER_CHANNEL_VERIFIED"], emitter: "ledger_writer" },
  // Invitation. Toda arista * -> CANCELLED (I9) es "permitida sin emision de ledger_writer; emisor transition_owner (Q-18-I9)": el AFTER no emite (sin INVITATION_CANCELLED duplicado).
  { id: "I1", aggregate: "Invitation", from: null, to: "DRAFT", emits: ["Invitation:INVITATION_CREATED"], emitter: "ledger_writer" },
  { id: "I2", aggregate: "Invitation", from: "DRAFT", to: "READY", emits: ["Invitation:INVITATION_READY"], emitter: "ledger_writer" },
  { id: "I3", aggregate: "Invitation", from: "READY", to: "SENT", emits: ["Invitation:INVITATION_SENT"], emitter: "ledger_writer" },
  { id: "I4", aggregate: "Invitation", from: "SENT", to: "OPENED", emits: ["Invitation:INVITATION_OPENED"], emitter: "ledger_writer" },
  { id: "I5", aggregate: "Invitation", from: "OPENED", to: "VERIFIED", emits: ["Invitation:INVITATION_VERIFIED"], emitter: "ledger_writer" },
  { id: "I6", aggregate: "Invitation", from: "VERIFIED", to: "COMPLETED", emits: ["Invitation:INVITATION_COMPLETED"], emitter: "ledger_writer" },
  { id: "I7", aggregate: "Invitation", from: "VERIFIED", to: "DECLINED", emits: ["Invitation:INVITATION_DECLINED"], emitter: "ledger_writer" },
  { id: "I9-DRAFT", aggregate: "Invitation", from: "DRAFT", to: "CANCELLED", emits: [], emitter: "transition_owner" },
  { id: "I9-READY", aggregate: "Invitation", from: "READY", to: "CANCELLED", emits: [], emitter: "transition_owner" },
  { id: "I9-SENT", aggregate: "Invitation", from: "SENT", to: "CANCELLED", emits: [], emitter: "transition_owner" },
  { id: "I9-OPENED", aggregate: "Invitation", from: "OPENED", to: "CANCELLED", emits: [], emitter: "transition_owner" },
  { id: "I9", aggregate: "Invitation", from: "VERIFIED", to: "CANCELLED", emits: [], emitter: "transition_owner" },
];

const iso = (d: Date): string => d.toISOString();

/** Invitation: OLD (null = INSERT) -> NEW. ->CANCELLED no emite aqui (lo emite transition_owner). */
export function deriveInvitationEvents(prev: InvitationRecord | null, next: InvitationRecord): readonly DerivedLedgerEvent[] {
  const ref = next.invitationRef;
  const ev = (eventType: string, actorRole: ActorRole, payload: Record<string, unknown>, idempotencyKey: string): DerivedLedgerEvent[] => [
    { eventType, aggregateType: "Invitation", aggregateId: ref, actorType: "HUMAN", actorRole, payload, idempotencyKey },
  ];
  if (prev === null) {
    // Fixtures legacy sin enrollment/participation (la base los exige en el INSERT): en memoria no emiten.
    if (next.state !== "DRAFT" || next.enrollmentRef === undefined || next.participationRef === undefined) return [];
    return ev("INVITATION_CREATED", "INVITER", { invitationRef: ref, participationRef: next.participationRef, enrollmentRef: next.enrollmentRef, subjectRef: next.subjectRef, reissueOfRef: next.reissueOfRef ?? null }, ref);
  }
  if (prev.state === "DRAFT" && next.state === "READY" && next.expiresAt !== undefined && next.consentVersion !== undefined && next.recipientBinding !== undefined) {
    return ev("INVITATION_READY", "INVITER", { invitationRef: ref, consentVersion: next.consentVersion, expiresAt: iso(next.expiresAt), recipientBinding: next.recipientBinding }, `${ref}:ready`);
  }
  if (prev.state === "READY" && next.state === "SENT" && next.expiresAt !== undefined && next.deliveryChannel !== undefined) {
    return ev("INVITATION_SENT", "INVITER", { invitationRef: ref, deliveryChannel: next.deliveryChannel, expiresAt: iso(next.expiresAt) }, `${ref}:sent`);
  }
  if (prev.state === "SENT" && next.state === "OPENED") return ev("INVITATION_OPENED", "UNVERIFIED_BEARER", { invitationRef: ref }, `${ref}:opened`);
  if (prev.state === "OPENED" && next.state === "VERIFIED" && next.verifiedByRef !== undefined && next.dmRefKeyVersion !== undefined && next.boundDecisionMakerRef !== undefined) {
    return ev("INVITATION_VERIFIED", "DECISION_MAKER", {
      invitationRef: ref, verificationRef: next.verifiedByRef, decisionMakerRef: next.boundDecisionMakerRef, decisionMakerRefKeyVersion: next.dmRefKeyVersion, bindingResult: BINDING_RESULT_PLACEHOLDER_OPEN_CT03,
    }, `${ref}:${next.verifiedByRef}`);
  }
  if (prev.state === "VERIFIED" && next.state === "COMPLETED" && next.closedByConsentId !== undefined) return ev("INVITATION_COMPLETED", "DECISION_MAKER", { invitationRef: ref, consentId: next.closedByConsentId }, `${ref}:completed`);
  if (prev.state === "VERIFIED" && next.state === "DECLINED" && next.closedByConsentId !== undefined) return ev("INVITATION_DECLINED", "DECISION_MAKER", { invitationRef: ref, consentId: next.closedByConsentId }, `${ref}:declined`);
  return [];
}

/** Secuencia de eventos de un agregado derivados de OLD (null = INSERT) -> NEW. Pura y determinista. */
export function deriveEnrollmentEvents(prev: EnrollmentRecord | null, next: EnrollmentRecord): readonly DerivedLedgerEvent[] {
  if (prev === null && next.state === "ACTIVE") {
    return [
      {
        eventType: "ENROLLMENT_STATUS_CHANGED",
        aggregateType: "Enrollment",
        aggregateId: next.enrollmentRef,
        actorType: "HUMAN",
        actorRole: "INVITER",
        payload: { enrollmentRef: next.enrollmentRef, participationRef: next.participationRef, subjectRef: next.subjectRef, toStatus: "ACTIVE" },
        idempotencyKey: `${next.tenantId}:${next.subjectRef}:${next.participationRef}:en0`,
      },
    ];
  }
  return [];
}

export function deriveOtpEvents(prev: OtpVerificationRecord | null, next: OtpVerificationRecord): readonly DerivedLedgerEvent[] {
  if (prev !== null && prev.state === "CODE_SENT" && next.state === "VERIFIED" && next.decisionMakerRef !== undefined && next.dmRefKeyVersion !== undefined) {
    return [
      {
        eventType: "DECISION_MAKER_CHANNEL_VERIFIED",
        aggregateType: "DecisionMakerVerification",
        aggregateId: next.verificationRef,
        actorType: "HUMAN",
        actorRole: "DECISION_MAKER",
        payload: {
          verificationRef: next.verificationRef,
          parentRef: next.parentRef,
          decisionMakerRef: next.decisionMakerRef,
          decisionMakerRefKeyVersion: next.dmRefKeyVersion,
          scope: next.scope,
          method: "EMAIL_OTP",
          bindingResult: BINDING_RESULT_PLACEHOLDER_OPEN_CT03,
        },
        idempotencyKey: `${next.verificationRef}:verified`,
      },
    ];
  }
  return [];
}
