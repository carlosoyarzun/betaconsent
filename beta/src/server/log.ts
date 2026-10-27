// Gobierna: plan v2 H1-05 (logging estructurado sin PII). Una línea JSON por petición: método, ruta NORMALIZADA, status, duración y request-id.
// Nunca: query string, cookies, cabeceras, cuerpo, correos, códigos OTP ni tokens. La ruta se reduce a una lista cerrada de plantillas; cualquier otra es "/other".

export type LogFields = Record<string, string | number | boolean>;

export interface Logger {
  info(msg: string, fields?: LogFields): void;
  warn(msg: string, fields?: LogFields): void;
  error(msg: string, fields?: LogFields): void;
}

const STATIC_ROUTES = new Set([
  "/healthz",
  "/welcome",
  "/verify",
  "/decision",
  "/manage",
  "/manage/verify",
  "/manage/revocation/verify",
  "/manage/revocation/confirm",
  "/recovery/confirm",
  "/decision/page-state",
  "/manage/page-state",
  "/invitation/open",
  "/otp/request",
  "/otp/submit",
  "/otp/resend",
  "/decision/steps",
  "/decision/submit",
  "/decision/subject-mismatch",
  "/manage/revocation",
  "/manage/revocation/withdraw",
  "/manage/recovery-link",
  "/recovery/revoke",
]);

/** Ruta sin tokens ni query: `/i/<token>` => `/i/:token`; rutas desconocidas => `/other`. Solo recibe el pathname (nunca la URL completa). */
export function normalizeRoute(pathname: string): string {
  if (/^\/(i|m|r)\/[^/]+$/.test(pathname)) return `/${pathname[1]}/:token`;
  if (pathname.startsWith("/assets/")) return "/assets/:file";
  return STATIC_ROUTES.has(pathname) ? pathname : "/other";
}

export function createJsonLogger(write: (line: string) => void = (l) => process.stdout.write(`${l}\n`), now: () => Date = () => new Date()): Logger {
  const emit = (level: string, msg: string, fields?: LogFields): void => write(JSON.stringify({ ts: now().toISOString(), level, msg, ...fields }));
  return {
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
  };
}
