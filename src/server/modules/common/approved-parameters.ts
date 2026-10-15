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

// ADR-010 rev. 5 §5.4 (decisiones G-6 y G-7 de Carlos, 2026-10-15; SEC-CNS-006 P-48..P-52): VALORES INICIALES CONFIGURABLES de los limites del login de operador. No son defaults de
// produccion: fuera de LOCAL la configuracion explicita es obligatoria y el proceso (platform / verifier) NO arranca sin ella. En LOCAL se usan como valor de trabajo y de referencia de tests.
// P-53 (tope global de filas AWAITING_CALLBACK) NO tiene valor aprobado: no hay constante; fuera de LOCAL falla cerrado.

/** P-48: intentos FALLIDOS de autenticacion por identidad (principal resuelto) en la ventana = 5. Los ATTESTED legitimos no cuentan. */
export const APPROVED_P48_LOGIN_MAX_FAILURES = 5;
/** P-48: ventana = 15 min. */
export const APPROVED_P48_LOGIN_WINDOW_SECONDS = 15 * 60;
/** P-49: intentos de autenticacion por IP (truncada, en memoria, sin persistir) en la ventana = 20. Detras de NAT/VPN el contador es compartido (limitacion documentada). */
export const APPROVED_P49_AUTH_MAX_PER_IP = 20;
/** P-49: ventana = 15 min. */
export const APPROVED_P49_AUTH_WINDOW_SECONDS = 15 * 60;
/** P-50: solicitudes autenticadas por operador por minuto = 30 (ventana de 60 s). */
export const APPROVED_P50_REQUESTS_MAX_PER_MINUTE = 30;
export const APPROVED_P50_WINDOW_SECONDS = 60;
/** P-51: intentos de confirmacion de acciones sensibles por operador en la ventana = 5. */
export const APPROVED_P51_STEP_UP_MAX_ATTEMPTS = 5;
/** P-51: ventana = 10 min. */
export const APPROVED_P51_STEP_UP_WINDOW_SECONDS = 10 * 60;
/** P-52: vida de la asercion LOGIN contada DESDE auth_time = 5 min; un solo uso; la base no admite mas de 300 s. */
export const APPROVED_P52_LOGIN_ASSERTION_SECONDS = 5 * 60;

// ADR-010 rev. 5 PR-6c (SEC-CNS-006 rev. 5 §1, ACCEPTED 2026-09-26; ADR-010 rev. 5 remite a estos valores): sesiones de operador del proceso platform.

/** P-36: vida ABSOLUTA de la sesion PLATFORM = 4 h. P-25: la de la sesion CASE = min(valid_until del grant, 4 h). */
export const APPROVED_PLATFORM_SESSION_ABSOLUTE_SECONDS = 4 * 60 * 60;
/** P-36 / P-25: expiracion por INACTIVIDAD de las sesiones PLATFORM y CASE = 15 min. */
export const APPROVED_PLATFORM_SESSION_IDLE_SECONDS = 15 * 60;
/** P-23: vida maxima de un rights_case_grant = 4 h (por defecto 2 h; renovar = nueva doble aprobacion). P-37: grant_request pendiente expira a 1 h. */
export const APPROVED_P23_GRANT_MAX_SECONDS = 4 * 60 * 60;
export const APPROVED_P23_GRANT_DEFAULT_SECONDS = 2 * 60 * 60;
export const APPROVED_P37_GRANT_REQUEST_EXPIRY_SECONDS = 60 * 60;
