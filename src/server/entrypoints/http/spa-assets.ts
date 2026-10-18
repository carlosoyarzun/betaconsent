// Gobierna: ADR-001 rev. 8 F1 (SPA estática servida por el backend) y §3 (CSP sin inline). Carga, al arrancar, el
// build de Vite (`dist/`, `npm run build:frontend`) y construye una lista blanca por IGUALDAD EXACTA de rutas (misma
// idea que static-assets.ts: nunca `path.join(dist, req.path)`, así que no existe traversal por construcción).
//
// - `dist/index.html` se lee UNA vez. Se precomputan dos variantes: "ready" (200) y "uniform-error" (404 uniforme,
//   INV-CM-05). La SPA lee `<meta name="cns-page-state">` para saber cuál mostrar sin un request extra y sin inline.
// - `dist/assets/**` (archivos con hash en el nombre) se registra como `/assets/<archivo>`; nada más.
// - Los assets con hash son inmutables (`Cache-Control: public, max-age=31536000, immutable`); el HTML, `no-store`.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { extname, join } from "node:path";

const PROJECT_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
export const DEFAULT_SPA_DIST_DIR = `${PROJECT_ROOT}dist`;

export type UiMode = "ssr" | "spa";

/** `CNS_UI_MODE`: ausente o vacío = `ssr` (default). Cualquier otro valor inválido aborta (fail-closed). */
export function parseUiMode(raw: string | undefined): UiMode {
  if (raw === undefined || raw === "" || raw === "ssr") return "ssr";
  if (raw === "spa") return "spa";
  throw new Error(`CNS_UI_MODE inválido (valores: ssr|spa).`);
}

const PAGE_STATE_READY = '<meta name="cns-page-state" content="ready">';
const PAGE_STATE_UNIFORM_ERROR = '<meta name="cns-page-state" content="uniform-error">';

const CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".json": "application/json",
};

export interface SpaAsset {
  readonly content: Buffer;
  readonly contentType: string;
}

export interface SpaBundle {
  readonly indexReady: string;
  readonly indexUniformError: string;
  /** Ruta `/assets/<archivo>` -> contenido (leído al arrancar). Solo igualdad exacta. */
  readonly assets: ReadonlyMap<string, SpaAsset>;
}

function listFiles(dir: string, prefix: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const rel = `${prefix}/${name}`;
    if (statSync(full).isDirectory()) out.push(...listFiles(full, rel));
    else out.push(rel);
  }
  return out;
}

export function loadSpaBundle(distDir: string = DEFAULT_SPA_DIST_DIR): SpaBundle {
  const indexPath = join(distDir, "index.html");
  if (!existsSync(indexPath)) {
    throw new Error("CNS_UI_MODE=spa requiere el build del frontend (dist/index.html): ejecutar `npm run build:frontend`.");
  }
  const indexReady = readFileSync(indexPath, "utf8");
  if (!indexReady.includes(PAGE_STATE_READY)) {
    throw new Error("dist/index.html no contiene el marcador <meta name=\"cns-page-state\" content=\"ready\">; el build del frontend no es válido.");
  }
  const assets = new Map<string, SpaAsset>();
  const assetsDir = join(distDir, "assets");
  if (existsSync(assetsDir)) {
    for (const rel of listFiles(assetsDir, "/assets")) {
      const contentType = CONTENT_TYPES[extname(rel).toLowerCase()];
      if (!contentType) continue; // tipo desconocido: no se sirve (fail-closed)
      assets.set(rel, { content: readFileSync(join(distDir, rel)), contentType });
    }
  }
  return { indexReady, indexUniformError: indexReady.replace(PAGE_STATE_READY, PAGE_STATE_UNIFORM_ERROR), assets };
}
