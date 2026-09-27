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
}

const DEFAULT_MANAGE_HANDLE_COOKIE_NAME = "__Host-cns-manage";
const DEFAULT_CSRF_COOKIE_NAME = "__Host-cns-csrf";
const DEFAULT_CSRF_HEADER_NAME = "x-csrf-token";
const DEFAULT_SESSION_COOKIE_NAME = "__Host-cns-session";

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
  };
}
