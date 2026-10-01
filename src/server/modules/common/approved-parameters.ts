// Gobierna: decisiones de Carlos del 2026-10-01 ("confirmo el paquete con D6 segun DEC-BR-014"), CA-128.
// Unica fuente de los parametros que pasaron de "sin valor aprobado" a APROBADOS. Aplican en CUALQUIER
// entorno (no solo LOCAL). Todo parametro que no figure aqui sigue fail-closed (P-15, P-18, OTP P-01..03,
// deliveryChannel EXT-B, etc.). Ver tambien manage-handle-policy.config.ts (TTL de /m, ver FINDING en CA-128).

/** P-33: TTL de la Idempotency-Key = 24 h (Carlos, 2026-10-01). */
export const APPROVED_P33_IDEMPOTENCY_TTL_MS = 24 * 60 * 60_000;

/** P-10: vigencia de la invitacion = 7 dias (Carlos, 2026-10-01). */
export const APPROVED_P10_INVITATION_EXPIRES_IN_MS = 7 * 24 * 60 * 60_000;

/** TTL de los handles /i y /m (cookies `__Host-cns-i-handle` / `__Host-cns-m-handle`) = 10 min (Carlos, 2026-10-01). */
export const APPROVED_LINK_HANDLE_TTL_MS = 10 * 60_000;
