// origen: src/server/entrypoints/http/cookies.ts@9345b78 (sin cambios).
// Gobierna: contracts/openapi/consent-it0.openapi.yaml (securitySchemes manageHandle, in: cookie).
// Parser mínimo de la cabecera Cookie (sin dependencias). Solo lectura; el entrypoint nunca
// confía en un valor de cookie para nada más que resolver el handle o el token CSRF, siempre
// contra los ports/guards correspondientes (nunca se usa directo como identidad).

/** Parsea la cabecera `Cookie: a=1; b=2` a un mapa. Entradas malformadas se ignoran. */
export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name.length === 0) continue;
    // Cambio respecto del origen: un valor mal codificado se ignora en vez de lanzar (no debe tumbar la petición).
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      continue;
    }
  }
  return out;
}
