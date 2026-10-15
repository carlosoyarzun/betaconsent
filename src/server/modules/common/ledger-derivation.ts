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
];

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
