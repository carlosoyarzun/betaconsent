// Gobierna: specs/state-machines/revocation.spec.yaml RV0 ("envío SOLO al channelRef ya
// ligado"). Puerto (ADR-001 §11) del canal de envío del enlace /r/{token}. En IT0 (DEC-BR-014
// §4.2) el adaptador es un sink in-memory sin SMTP ni ninguna salida de red, mismo patrón que
// otp-channel.port.ts: el enlace en claro (con el token) vive SOLO aquí, nunca en la respuesta
// HTTP de POST /manage/recovery-link ni en el ledger ni en logs (Cero PII).

export interface RecoveryLinkMessage {
  /** Ruta relativa de un solo uso (`/r/<token>`); el token en claro solo existe en este mensaje
   * y se descarta tras enviarse (GRD-RV-06: solo el hash persiste). */
  readonly recoveryPath: string;
}

export interface RecoveryLinkChannelPort {
  send(message: RecoveryLinkMessage): void;
}
