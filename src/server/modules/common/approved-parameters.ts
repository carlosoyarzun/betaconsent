// Gobierna: decisiones de Carlos del 2026-10-01 ("confirmo el paquete con D6 segun DEC-BR-014"), CA-128.
// Unica fuente de los parametros que pasaron de "sin valor aprobado" a APROBADOS. Aplican en CUALQUIER
// entorno (no solo LOCAL). Todo parametro que no figure aqui sigue fail-closed (P-15, P-18, OTP P-06,
// deliveryChannel EXT-B, etc.). Ver tambien manage-handle-policy.config.ts (TTL de /m, ver FINDING en CA-128).

/** P-33: TTL de la Idempotency-Key = 24 h (Carlos, 2026-10-01). */
export const APPROVED_P33_IDEMPOTENCY_TTL_MS = 24 * 60 * 60_000;

/** P-10: vigencia de la invitacion = 7 dias (Carlos, 2026-10-01). */
export const APPROVED_P10_INVITATION_EXPIRES_IN_MS = 7 * 24 * 60 * 60_000;

/** TTL de los handles /i y /m (cookies `__Host-cns-i-handle` / `__Host-cns-m-handle`) = 10 min (Carlos, 2026-10-01). */
export const APPROVED_LINK_HANDLE_TTL_MS = 10 * 60_000;

// Sesión STAFF (`__Host-cns-staff`, staff-session.ts; CA-138, SEC-CNS-018 rev. 2 D-3, SEC-CNS-020 P2-3). Aprobados por Carlos, 2026-10-05.

/** Vida ABSOLUTA de la sesión STAFF (exp = iat + este valor) = 8 h (Carlos, 2026-10-05). */
export const APPROVED_STAFF_SESSION_ABSOLUTE_TTL_MS = 8 * 60 * 60_000;

/** Expiración por INACTIVIDAD de la sesión STAFF = 30 min sin request válido (Carlos, 2026-10-05). */
export const APPROVED_STAFF_SESSION_IDLE_TIMEOUT_MS = 30 * 60_000;

/** Las filas de sesión STAFF expiradas se conservan 24 h tras su `exp` antes de la limpieza (Carlos, 2026-10-05). */
export const APPROVED_STAFF_SESSION_PURGE_RETENTION_MS = 24 * 60 * 60_000;

// Sesión CASE (`__Host-cns-case`, case-session.ts; CA-139, SEC-CNS-018 rev. 2 D-3). Aprobados por Carlos, 2026-10-06 (mismos plazos que STAFF).

/** Vida ABSOLUTA de la sesión CASE (exp = iat + este valor) = 8 h (Carlos, 2026-10-06). */
export const APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS = 8 * 60 * 60_000;

/** Expiración por INACTIVIDAD de la sesión CASE = 30 min sin request válido (Carlos, 2026-10-06). */
export const APPROVED_CASE_SESSION_IDLE_TIMEOUT_MS = 30 * 60_000;

/** Las filas de sesión CASE expiradas se conservan 24 h tras su `exp` antes de la limpieza (Carlos, 2026-10-06). */
export const APPROVED_CASE_SESSION_PURGE_RETENTION_MS = 24 * 60 * 60_000;

// OTP (SEC-CNS-006 rev. 5 §1; decisión de Carlos 2026-10-08, D3 de SEC-CNS-021). Aplican en cualquier entorno.

/** P-01: longitud del código OTP = 6 dígitos, generados con crypto.randomInt sin sesgo (aprobado por Carlos). */
export const APPROVED_P01_OTP_CODE_LENGTH = 6;

/** P-02: vigencia del código OTP = 10 min, medida con hora de servidor (aprobado por Carlos). */
export const APPROVED_P02_OTP_TTL_MS = 10 * 60_000;

/** P-03: intentos fallidos máximos antes de LOCKED = 5 (aprobado por Carlos). */
export const APPROVED_P03_OTP_MAX_ATTEMPTS = 5;

/** P-06 (aprobado por Carlos): separación mínima entre envíos de una misma verificación = 60 s.
 * SIN CONSUMIDOR todavía: requiere timestamps de envío en OtpVerificationRecord (migración nueva); ver FINDING. */
export const APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS = 60_000;

/** P-06 (aprobado por Carlos): máximo de envíos por hora por verificación = 3. SIN CONSUMIDOR todavía
 * (ver APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS; además queda abierto si el 3 incluye el envío inicial). */
export const APPROVED_P06_OTP_MAX_SENDS_PER_HOUR = 3;

// P-34 (retención de ops.security_event y stores de OTP; SEC-CNS-021 PR-3). NO es un valor aprobado: LD-15 (LEGAL DECISION) sigue abierta.
// 30 días es un PLACEHOLDER de Carlos (2026-10-08) que la migración 0031 siembra en ops.retention_policy (decision_ref lo declara). Por eso el
// nombre NO lleva APPROVED_ y retention.config.ts NO lo usa como default: fuera de LOCAL/DEV la configuración explícita es obligatoria. Sirve
// solo como valor de referencia de tests/fixtures LOCAL.
export const PLACEHOLDER_P34_RETENTION_DAYS = 30;
