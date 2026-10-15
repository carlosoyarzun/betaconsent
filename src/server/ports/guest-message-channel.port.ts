// Gobierna: UX-CNS-006 / UX-CNS-006b (e-mails del invitado, Carlos 2026-10-14, D-03/D-04),
// consent-decision.spec.yaml C3/C5 (RECEIPT_CREATED; C3 "emite el enlace de gestión SOLO al canal
// ligado"), revocation.spec.yaml managementLink. Puerto (ADR-001 §11) del canal de mensajes al
// canal ya verificado del DecisionMaker. En IT0 (DEC-BR-014 §4.2) el adaptador es un sink
// in-memory sin SMTP ni salida de red, mismo patrón que otp-channel / recovery-link-channel: el
// enlace de gestión en claro (con el token) vive SOLO en el mensaje MANAGEMENT_LINK dentro del
// sink; nunca en la respuesta HTTP, el comprobante, el ledger, el outbox ni logs.
//
// Dos mensajes distintos por decisión GRANTED (D-03): RECEIPT (sin ningún enlace) y
// MANAGEMENT_LINK (aparte). DECLINED solo emite RECEIPT (consent-decision.spec C5 no emite
// enlace de gestión; D-07).

export type GuestMessageKind = "RECEIPT" | "MANAGEMENT_LINK";

export interface GuestMessage {
  readonly kind: GuestMessageKind;
  /** Ref opaca del canal ligado a la invitación (nunca una dirección real en IT0). */
  readonly recipientChannelRef: string;
  readonly subject: string;
  /** Cuerpo HTML (estilos inline, sin recursos remotos ni JS). */
  readonly html: string;
  /** Alternativa en texto plano. */
  readonly text: string;
}

export interface GuestMessageChannelPort {
  send(message: GuestMessage): Promise<void>;
}
