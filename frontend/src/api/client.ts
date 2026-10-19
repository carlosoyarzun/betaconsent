// Cliente HTTP único de la SPA. Reproduce el `postJson` de los assets/*.js del SSR (UX-CNS-001..004):
//  - `credentials: "same-origin"` (la cookie de sesión HttpOnly viaja sola; la SPA nunca la lee).
//  - `content-type: application/json`.
//  - CSRF double-submit (GRD-CM-10): copia la cookie `__Host-cns-csrf` (no HttpOnly, la fija el servidor en cada GET de
//    página) a la cabecera `x-csrf-token`; el servidor compara igualdad. `Origin` lo pone el navegador.
// Errores: nunca lanza. Devuelve `{ ok: false, error }` con `kind` "http" (4xx/5xx, con `code` y `correlationId` del
// cuerpo JSON/problem+json si existen) o "network" (fetch falló). No se registra ni se refleja ningún cuerpo.

export const CSRF_COOKIE_NAME = "__Host-cns-csrf";
export const CSRF_HEADER_NAME = "x-csrf-token";

export interface ApiError {
  readonly kind: "http" | "network";
  /** 0 en errores de red. */
  readonly status: number;
  readonly code?: string;
  readonly correlationId?: string;
}

export type ApiResult<T> =
  | { readonly ok: true; readonly status: number; readonly data: T | undefined }
  | { readonly ok: false; readonly error: ApiError };

export function readCookie(name: string, cookieSource: string = document.cookie): string | null {
  const parts = cookieSource ? cookieSource.split(";") : [];
  for (const raw of parts) {
    const part = raw.trim();
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq) === name) {
      try {
        return decodeURIComponent(part.slice(eq + 1));
      } catch {
        return null;
      }
    }
  }
  return null;
}

async function parseBody(res: Response): Promise<Record<string, unknown> | undefined> {
  try {
    const parsed: unknown = await res.json();
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined; // cuerpo vacío o no-JSON (p. ej. 503 sin cuerpo)
  }
}

function toApiError(status: number, body: Record<string, unknown> | undefined): ApiError {
  const code = typeof body?.code === "string" ? body.code : undefined;
  const correlationId = typeof body?.correlationId === "string" ? body.correlationId : undefined;
  return {
    kind: "http",
    status,
    ...(code !== undefined ? { code } : {}),
    ...(correlationId !== undefined ? { correlationId } : {}),
  };
}

export async function postJson<T = unknown>(path: string, body: unknown = {}): Promise<ApiResult<T>> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const csrf = readCookie(CSRF_COOKIE_NAME);
  if (csrf) headers[CSRF_HEADER_NAME] = csrf;
  let res: Response;
  try {
    res = await fetch(path, { method: "POST", headers, body: JSON.stringify(body), credentials: "same-origin" });
  } catch {
    return { ok: false, error: { kind: "network", status: 0 } };
  }
  const parsed = await parseBody(res);
  if (!res.ok) return { ok: false, error: toApiError(res.status, parsed) };
  return { ok: true, status: res.status, data: parsed as T | undefined };
}
