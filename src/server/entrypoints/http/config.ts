// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-10 (csrf_and_origin).
// Configuración del entrypoint HTTP. El origen permitido SIEMPRE se inyecta desde
// configuración (variable de entorno o el `config` explícito que reciba el caller); este
// archivo no declara ningún dominio real como valor por defecto (CLAUDE.md: "nunca
// hardcodeado a un dominio real"). Nombres de cookie con prefijo `__Host-` per
// contracts/openapi (x-pending P-26: nombre exacto de la cookie CSRF, no fijado aún).

export interface RightsCaseHttpConfig {
  /** Origen permitido para GRD-CM-10 (comparación por igualdad exacta). Sin default: si no se
   * provee explícitamente ni por env, el servidor no arranca (fail-closed). */
  readonly allowedOrigin: string;
  /** Cookie que porta el handle MANAGE_ENTRY de /m/ (contracts/openapi securitySchemes.manageHandle). */
  readonly manageHandleCookieName: string;
  /** Cookie CSRF del double-submit (P-26 PENDING: nombre exacto de cabecera/cookie). */
  readonly csrfCookieName: string;
  /** Cabecera CSRF (contracts/openapi parameters.CsrfToken: X-CSRF-Token). */
  readonly csrfHeaderName: string;
  /** Cookie de sesión del flujo invitación/otp/decisión (D5, PENDING de P-26; ver consent-session.ts). */
  readonly sessionCookieName: string;
  /** Cookie del handle RECOVERY (SEC-CNS-014, recovery-handle.ts; contracts/openapi
   * securitySchemes.recoveryHandle). Nunca la misma cookie que sessionCookieName. */
  readonly recoveryHandleCookieName: string;
  /** SEC-CNS-014 patrón (Carlos, 2026-09-28), link-handle.ts: cookie que porta SOLO el hash
   * fijado por GET /i/{token} (typ INVITATION_LANDING), hasta que GET /welcome lo resuelve en
   * solo lectura y crea la sesión real (sessionCookieName). Nunca la misma cookie que
   * sessionCookieName, recoveryHandleCookieName ni manageEntryHandleCookieName. */
  readonly invitationHandleCookieName: string;
  /** SEC-CNS-014 patrón (Carlos, 2026-09-28), link-handle.ts: cookie que porta SOLO el hash
   * fijado por GET /m/{token} (typ MANAGE_ENTRY), hasta que GET /manage lo resuelve en solo
   * lectura y crea la sesión real. Distinta de `manageHandleCookieName` (contracts/openapi
   * securitySchemes.manageHandle, __Host-cns-manage): esa cookie es un handle EN CLARO, pendiente
   * de integrar con RC2u (rights-case-resume.handler.ts); esta lleva solo el hash. */
  readonly manageEntryHandleCookieName: string;
  /** Cookie de la sesión CASE (contracts/openapi securitySchemes.caseSession, nombre exacto
   * `__Host-cns-case` ya fijado en el contrato; P-26 pendiente para el resto de las cookies de
   * este archivo, no para esta). CA-128 (API-CNS-138). */
  readonly caseSessionCookieName: string;
  /** Cookie CSRF propia de la consola CASE (P-26 PENDIENTE, nombre provisional): aislada de
   * csrfCookieName (bearer) para que comprometer una no comprometa la otra, mismo criterio que
   * recoveryHandleCookieName. */
  readonly caseCsrfCookieName: string;
}

const DEFAULT_MANAGE_HANDLE_COOKIE_NAME = "__Host-cns-manage";
const DEFAULT_CSRF_COOKIE_NAME = "__Host-cns-csrf";
const DEFAULT_CSRF_HEADER_NAME = "x-csrf-token";
const DEFAULT_SESSION_COOKIE_NAME = "__Host-cns-session";
const DEFAULT_RECOVERY_HANDLE_COOKIE_NAME = "__Host-cns-recovery";
const DEFAULT_INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const DEFAULT_MANAGE_ENTRY_HANDLE_COOKIE_NAME = "__Host-cns-m-handle";
const DEFAULT_CASE_SESSION_COOKIE_NAME = "__Host-cns-case";
const DEFAULT_CASE_CSRF_COOKIE_NAME = "__Host-cns-case-csrf";

/**
 * Construye la configuración del entrypoint. `allowedOrigin` debe venir siempre de
 * configuración externa (env `CNS_ALLOWED_ORIGIN` u override explícito de caller/test); nunca
 * de un literal de dominio real en este archivo.
 */
export function loadRightsCaseHttpConfig(overrides: Partial<RightsCaseHttpConfig> = {}): RightsCaseHttpConfig {
  const allowedOrigin = overrides.allowedOrigin ?? process.env.CNS_ALLOWED_ORIGIN;
  if (!allowedOrigin) {
    throw new Error(
      "CNS_ALLOWED_ORIGIN no está configurado: GRD-CM-10 exige un origen permitido explícito, " +
        "nunca un dominio hardcodeado (fail-closed).",
    );
  }
  return {
    allowedOrigin,
    manageHandleCookieName: overrides.manageHandleCookieName ?? DEFAULT_MANAGE_HANDLE_COOKIE_NAME,
    csrfCookieName: overrides.csrfCookieName ?? DEFAULT_CSRF_COOKIE_NAME,
    csrfHeaderName: overrides.csrfHeaderName ?? DEFAULT_CSRF_HEADER_NAME,
    sessionCookieName: overrides.sessionCookieName ?? DEFAULT_SESSION_COOKIE_NAME,
    recoveryHandleCookieName: overrides.recoveryHandleCookieName ?? DEFAULT_RECOVERY_HANDLE_COOKIE_NAME,
    invitationHandleCookieName: overrides.invitationHandleCookieName ?? DEFAULT_INVITATION_HANDLE_COOKIE_NAME,
    manageEntryHandleCookieName: overrides.manageEntryHandleCookieName ?? DEFAULT_MANAGE_ENTRY_HANDLE_COOKIE_NAME,
    caseSessionCookieName: overrides.caseSessionCookieName ?? DEFAULT_CASE_SESSION_COOKIE_NAME,
    caseCsrfCookieName: overrides.caseCsrfCookieName ?? DEFAULT_CASE_CSRF_COOKIE_NAME,
  };
}
