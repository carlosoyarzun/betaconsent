// Gobierna: decisiones de Carlos del 2026-10-01 ("confirmo el paquete con D6 segun DEC-BR-014"), CA-128.
// Unica fuente de los parametros que pasaron de "sin valor aprobado" a APROBADOS. Aplican en CUALQUIER
// entorno (no solo LOCAL). Todo parametro que no figure aqui sigue fail-closed (P-15, P-18,
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

/** P-04 (aprobado por Carlos, SEC-CNS-006 rev. 5; SEC-CNS-021 PR-4): máximo de FALLOS por clave de presupuesto (ops.otp_budget) = 10 por ventana DAY_1. */
export const APPROVED_P04_OTP_BUDGET_MAX_FAILURES = 10;

/** P-04 (aprobado): ventana fija DAY_1 = 24 h, que empieza en el primer fallo de la clave (no se desliza). */
export const APPROVED_P04_OTP_BUDGET_WINDOW_MS = 24 * 60 * 60_000;

/** P-07 (aprobado, scope DECISION): el 3.er challenge LOCKED de una misma invitación la marca otpExhausted (V6a, GRD-OT-09/14). */
export const APPROVED_P07_OTP_DECISION_MAX_LOCKED_CHALLENGES = 3;

/**
 * P-07 RIGHTS DAYS_30 (REVOCATION/MANAGE: 30 fallos / 30 días por chainRef, V6c): DIFERIDO por Carlos (D6, 2026-10-08) hasta la historia de rotación
 * del management token (ADR-006 §6.1; F-8). NO se aplica: ningún código reserva en la ventana DAYS_30 y el único tope de RIGHTS es P-04 (DAY_1).
 * Hay un test que verifica que sigue en false. Activarlo exige esa historia (y una DEC), no solo cambiar este valor.
 */
export const P07_RIGHTS_DAYS_30_CAP_ENFORCED = false;

/** P-06 (aprobado por Carlos): separación mínima entre envíos de una misma verificación = 60 s (V2r, GRD-OT-06). */
export const APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS = 60_000;

/** P-06 (aprobado por Carlos; D8, 2026-10-08): máximo de envíos por hora por verificación = 3, INCLUYENDO el envío inicial de V1
 * (V1 + 2 reenvíos). Ventana fija de 1 h que empieza en el envío inicial. */
export const APPROVED_P06_OTP_MAX_SENDS_PER_HOUR = 3;

/** P-06: duración de la ventana de envíos (1 h). */
export const APPROVED_P06_OTP_SEND_WINDOW_MS = 60 * 60_000;

// P-34 (retención de ops.security_event y stores de OTP; SEC-CNS-021 PR-3). NO es un valor aprobado: LD-15 (LEGAL DECISION) sigue abierta.
// 30 días es un PLACEHOLDER de Carlos (2026-10-08) que la migración 0031 siembra en ops.retention_policy (decision_ref lo declara). Por eso el
// nombre NO lleva APPROVED_ y retention.config.ts NO lo usa como default: fuera de LOCAL/DEV la configuración explícita es obligatoria. Sirve
// solo como valor de referencia de tests/fixtures LOCAL.
export const PLACEHOLDER_P34_RETENTION_DAYS = 30;
