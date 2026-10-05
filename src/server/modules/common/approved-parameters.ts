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

// ---------------------------------------------------------------------------------------------------------------------
// PROPUESTOS — pendiente aprobación de Carlos. NO son parámetros aprobados (CA-138, SEC-CNS-018 rev. 2 D-3,
// SEC-CNS-020 P2-3). Valores conservadores de la implementación; Carlos los confirma o los cambia. Hasta entonces se
// aplican solo como defaults de IT0 (LOCAL + CI, datos sintéticos) y el nombre lleva PROPOSED para que ningún
// consumidor los confunda con un APPROVED_*. Aplican a la sesión STAFF (`__Host-cns-staff`, staff-session.ts).
// ---------------------------------------------------------------------------------------------------------------------

/** PROPUESTO — pendiente aprobación de Carlos: vida ABSOLUTA de la sesión STAFF (exp = iat + este valor) = 8 h. */
export const PROPOSED_STAFF_SESSION_ABSOLUTE_TTL_MS = 8 * 60 * 60_000;

/** PROPUESTO — pendiente aprobación de Carlos: expiración por INACTIVIDAD de la sesión STAFF = 30 min sin request válido. */
export const PROPOSED_STAFF_SESSION_IDLE_TIMEOUT_MS = 30 * 60_000;

/** PROPUESTO — pendiente aprobación de Carlos: las filas de sesión expiradas se conservan 24 h tras su `exp` antes de la limpieza. */
export const PROPOSED_STAFF_SESSION_PURGE_RETENTION_MS = 24 * 60 * 60_000;
