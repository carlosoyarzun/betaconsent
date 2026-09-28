// Gobierna: CLAUDE.md (UX-CNS-001, /welcome). Lista blanca explícita de estáticos servidos
// bajo /assets/**: el lookup es por IGUALDAD EXACTA de la ruta contra las claves de un Map ya
// construido en memoria, nunca por `path.join(baseDir, req.path)`. Eso hace que un intento de
// traversal (`/assets/../otp-policy.config.ts`, `%2e%2e`, etc.) simplemente no tenga entrada en
// el mapa: no hay forma de "escapar" del whitelist porque no se resuelve ninguna ruta a partir
// de la entrada del cliente (fail-closed por diseño, no por saneo de string).
//
// El CSS del design system (design-system/css/*.css, importado por index.css vía @import) se
// sirve reexponiendo cada archivo bajo /assets/design-system/... con la misma estructura
// relativa que index.css espera, para que el navegador resuelva esos @import sin reescrituras.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const HTTP_DIR = fileURLToPath(new URL(".", import.meta.url));
const PROJECT_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));

function designSystemPath(relative: string): string {
  return `${PROJECT_ROOT}design-system/${relative}`;
}

function appAssetPath(fileName: string): string {
  return `${HTTP_DIR}assets/${fileName}`;
}

export interface StaticAsset {
  readonly filePath: string;
  readonly contentType: string;
}

/** Lista blanca cerrada: exactamente estas rutas existen bajo /assets/**, ninguna otra
 * (design-system/ y contracts/ nunca se editan desde esta tarea, solo se leen). */
const STATIC_ASSETS: ReadonlyMap<string, StaticAsset> = new Map([
  ["/assets/design-system/index.css", { filePath: designSystemPath("index.css"), contentType: "text/css; charset=utf-8" }],
  ["/assets/design-system/css/tokens.css", { filePath: designSystemPath("css/tokens.css"), contentType: "text/css; charset=utf-8" }],
  ["/assets/design-system/css/layouts.css", { filePath: designSystemPath("css/layouts.css"), contentType: "text/css; charset=utf-8" }],
  ["/assets/design-system/css/components.css", { filePath: designSystemPath("css/components.css"), contentType: "text/css; charset=utf-8" }],
  ["/assets/design-system/css/patterns.css", { filePath: designSystemPath("css/patterns.css"), contentType: "text/css; charset=utf-8" }],
  ["/assets/app.css", { filePath: appAssetPath("app.css"), contentType: "text/css; charset=utf-8" }],
  ["/assets/welcome.js", { filePath: appAssetPath("welcome.js"), contentType: "text/javascript; charset=utf-8" }],
  ["/assets/verify.js", { filePath: appAssetPath("verify.js"), contentType: "text/javascript; charset=utf-8" }],
  ["/assets/decision.js", { filePath: appAssetPath("decision.js"), contentType: "text/javascript; charset=utf-8" }],
  ["/assets/manage.js", { filePath: appAssetPath("manage.js"), contentType: "text/javascript; charset=utf-8" }],
  ["/assets/revocation.js", { filePath: appAssetPath("revocation.js"), contentType: "text/javascript; charset=utf-8" }],
]);

export interface ResolvedStaticAsset {
  readonly content: Buffer;
  readonly contentType: string;
}

/**
 * Resuelve `requestPath` contra la lista blanca. Cualquier ruta que no sea una de las claves
 * exactas de arriba (incluida cualquier variante con `..`, codificada o no) devuelve `null`, sin
 * tocar el filesystem. Se lee del disco en cada request (sin caché de proceso): el volumen de
 * estáticos de IT0 es mínimo y así no hay que invalidar caché entre tests.
 */
export function resolveStaticAsset(requestPath: string): ResolvedStaticAsset | null {
  const asset = STATIC_ASSETS.get(requestPath);
  if (!asset) return null;
  try {
    return { content: readFileSync(asset.filePath), contentType: asset.contentType };
  } catch {
    return null;
  }
}
