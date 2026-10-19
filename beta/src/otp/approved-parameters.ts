// origen: src/server/modules/common/approved-parameters.ts:39-72@9345b78 (solo los parámetros OTP; valores aprobados por Carlos, SEC-CNS-006 rev. 5 §1).
// Estos valores se APLICAN en la base (db/migrations/0003_functions.sql, constantes de issue_otp/verify_otp); un test comprueba que coinciden.

/** P-01: longitud del código OTP = 6 dígitos. */
export const APPROVED_P01_OTP_CODE_LENGTH = 6;
/** P-02: vigencia del código OTP = 10 min (hora de servidor). */
export const APPROVED_P02_OTP_TTL_MS = 10 * 60_000;
/** P-03: intentos fallidos máximos antes de LOCKED = 5. */
export const APPROVED_P03_OTP_MAX_ATTEMPTS = 5;
/** P-04: máximo de fallos por clave de presupuesto = 10 por ventana fija de 24 h desde el primer fallo. */
export const APPROVED_P04_OTP_BUDGET_MAX_FAILURES = 10;
export const APPROVED_P04_OTP_BUDGET_WINDOW_MS = 24 * 60 * 60_000;
/** P-06: separación mínima entre envíos = 60 s; máximo 3 envíos por hora (incluye el inicial). */
export const APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS = 60_000;
export const APPROVED_P06_OTP_MAX_SENDS_PER_HOUR = 3;
export const APPROVED_P06_OTP_SEND_WINDOW_MS = 60 * 60_000;
/** SUPUESTO de beta (no aprobado): ventana tras verificar el OTP para registrar la decisión o la revocación = 30 min. */
export const BETA_VERIFIED_SESSION_WINDOW_MS = 30 * 60_000;
