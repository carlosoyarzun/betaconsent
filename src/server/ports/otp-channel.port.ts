// Gobierna: specs/state-machines/otp-challenge.spec.yaml V1/V2r (envío del código).
// Puerto (ADR-001 §11): el dominio nunca envía por SMTP ni ningún canal real (ADR-003
// rev. 7: sin infraestructura en IT0); el adaptador de IT0 es un sink en memoria.

export interface OtpChannelMessage {
  readonly channelRef: string;
  readonly verificationRef: string;
  /** Código EN CLARO, solo para el sink de IT0 (nunca al ledger ni a logs, INV-OT-02). */
  readonly code: string;
}

export interface OtpChannelPort {
  send(message: OtpChannelMessage): Promise<void>;
}
