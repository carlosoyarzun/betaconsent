// Gobierna: contracts/openapi POST /staff/invitations/{ref}/ready (P-10, expiresAt lo fija el
// servidor) y .../send; invitation.spec.yaml GRD-IV-12 (expiresAt = SENT + P-10), events
// INVITATION_SENT.deliveryChannel (EXT-B / F-014, DEC-BR-014 §7: "sin fijar").
// Mismo patrón D4 que invitation-handle-policy.config.ts: SIN default de producción. P-10 no
// tiene valor en el repo (SEC-CNS-006 rev. 5 vive en Notion) y deliveryChannel es una decisión
// abierta de Carlos (EXT-B). El caller (dev.ts LOCAL-only, tests) pasa un override explícito;
// sin él, I2/I3 fallan cerrado (ERR-CM-12, GUARD_EVALUATOR_UNAVAILABLE).

import { APPROVED_P10_INVITATION_EXPIRES_IN_MS } from "../common/approved-parameters.ts";

// ACTUALIZADO (Carlos, 2026-10-01, CA-128): P-10 = 7 días APROBADO (default en cualquier entorno).
// deliveryChannel (EXT-B / F-014) sigue SIN aprobar: fail-closed. EXT-B (a): en IT0 se permiten
// invitaciones UNBOUND (sin destinatario) y no hay tabla de canales; RECIPIENT_CHANNEL sigue rechazado en pg.

export type InvitationDeliveryChannel = "SCHOOL_CHANNEL" | "CONSENT_APP_EMAIL";

const DELIVERY_CHANNELS: readonly InvitationDeliveryChannel[] = ["SCHOOL_CHANNEL", "CONSENT_APP_EMAIL"];

export interface InvitationIssuancePolicy {
  /** P-10: vigencia de la invitación desde SENT (y desde READY como cota provisoria, F-CT-05). */
  readonly expiresInMs: number;
  /** EXT-B / F-014: canal de entrega. Decisión de Carlos pendiente. */
  readonly deliveryChannel: InvitationDeliveryChannel;
}

export function loadInvitationIssuancePolicyConfig(
  overrides: Partial<InvitationIssuancePolicy> = {},
): InvitationIssuancePolicy {
  const expiresInMs = overrides.expiresInMs ?? APPROVED_P10_INVITATION_EXPIRES_IN_MS;
  const deliveryChannel = overrides.deliveryChannel;
  if (!Number.isFinite(expiresInMs) || expiresInMs <= 0) {
    throw new Error("Política de emisión de invitaciones inválida: P-10 (expiresInMs) debe ser un número positivo.");
  }
  if (deliveryChannel === undefined || !DELIVERY_CHANNELS.includes(deliveryChannel)) {
    throw new Error(
      "Política de emisión de invitaciones incompleta: deliveryChannel (EXT-B / F-014, DEC-BR-014 §7) no " +
        "está fijado. No hay default de producción; solo override LOCAL-only.",
    );
  }
  return { expiresInMs, deliveryChannel };
}
