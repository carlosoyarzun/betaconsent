// Gobierna: ADR-001 rev. 8 F1 (SPA estática servida por el backend) y §3 (CSP sin inline). Carga, al arrancar, el
// build de Vite (`dist/`, `npm run build:frontend`) y construye una lista blanca por IGUALDAD EXACTA de rutas (misma
// idea que static-assets.ts: nunca `path.join(dist, req.path)`, así que no existe traversal por construcción).
//
// - `dist/index.html` se lee UNA vez. Se precomputan dos variantes: "ready" (200) y "uniform-error" (404 uniforme,
//   INV-CM-05). La SPA lee `<meta name="cns-page-state">` para saber cuál mostrar sin un request extra y sin inline.
// - `dist/assets/**` (archivos con hash en el nombre) se registra como `/assets/<archivo>`; nada más.
// - Los assets con hash son inmutables (`Cache-Control: public, max-age=31536000, immutable`); el HTML, `no-store`.

import { existsSync, lstatSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { extname, join } from "node:path";
import { checkDist } from "./dist-validation.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
export const DEFAULT_SPA_DIST_DIR = `${PROJECT_ROOT}dist`;

export type UiMode = "ssr" | "spa";

/** SEC-UI R4 — ÚNICO PUNTO DE CAMBIO: mientras 7 de las 8 pantallas sean esqueletos, `spa` solo se acepta con catálogo LOCAL.
 * Retirar esta restricción (y su test TEST-CNS-1897) al terminar la migración de las 8 pantallas y verificar equivalencia. */
export const SPA_ALLOWED_ENVIRONMENTS: readonly string[] = ["LOCAL"];

export function assertSpaAllowed(environment: string | undefined): void {
  if (environment === undefined || !SPA_ALLOWED_ENVIRONMENTS.includes(environment)) {
    throw new Error("CNS_UI_MODE=spa solo se acepta con catálogo LOCAL mientras falten pantallas por migrar (ADR-001 F1).");
  }
}

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

/** Rutas `assets/...` que declara el manifiesto de Vite (file/css/assets, recursivo por imports). */
function manifestFiles(distDir: string): Set<string> {
  const manifestPath = join(distDir, ".vite", "manifest.json");
  if (!existsSync(manifestPath)) throw new Error("dist/.vite/manifest.json ausente; el build del frontend no es válido (npm run build:frontend).");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, { file?: string; css?: string[]; assets?: string[] }>;
  const out = new Set<string>();
  for (const chunk of Object.values(manifest)) {
    for (const f of [chunk.file, ...(chunk.css ?? []), ...(chunk.assets ?? [])]) {
      if (f && f.startsWith("assets/") && !f.includes("..")) out.add(f);
    }
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
  if (existsSync(join(distDir, "assets")) && !lstatSync(join(distDir, "assets")).isDirectory()) throw new Error("dist/assets no es un directorio regular; build inválido.");
  for (const rel of manifestFiles(distDir)) {
    const contentType = CONTENT_TYPES[extname(rel).toLowerCase()];
    if (!contentType) continue; // tipo desconocido: no se sirve (fail-closed)
    const full = join(distDir, rel);
    const st = lstatSync(full); // lstat: un symlink o un no-regular se rechaza (no se sigue)
    if (!st.isFile()) throw new Error(`dist/${rel} no es un archivo regular; build inválido.`);
    assets.set(`/${rel}`, { content: readFileSync(full), contentType });
  }
  // SEC-UI R2: mismas comprobaciones que el guardrail de CI, también al arrancar (sin inline, refs a assets existentes).
  const violations = checkDist({
    indexHtml: indexReady,
    assetPaths: new Set(assets.keys()),
    cssContents: [...assets.entries()].filter(([k]) => k.endsWith(".css")).map(([, a]) => a.content.toString("utf8")),
  });
  if (violations.length > 0) throw new Error(`dist/ inválido (ADR-001 §3): ${violations.join("; ")}`);
  return { indexReady, indexUniformError: indexReady.replace(PAGE_STATE_READY, PAGE_STATE_UNIFORM_ERROR), assets };
}
