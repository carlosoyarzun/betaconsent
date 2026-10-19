// Gobierna: ADR-001 rev. 8 F1 (AD-1 cerrada: la SPA es el único modo; el web falla al arrancar sin dist/ válido).
// Directorio `dist/` SINTÉTICO (temporal, sin depender de `npm run build:frontend`) que los tests de integración/contrato
// pasan como `spaDistDir` a createConsentFlowHttpServer. Contiene exactamente lo que exige loadSpaBundle/checkDist:
// index.html con <meta name="cns-page-state" content="ready">, un script y una hoja bajo /assets/ con hash, y manifiesto.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const SYNTHETIC_JS_NAME = "index-Ab12Cd34.js";
export const SYNTHETIC_CSS_NAME = "style-Ef56Gh78.css";
export const SYNTHETIC_ORPHAN_NAME = "huerfano-00000000.js";
export const SYNTHETIC_INDEX_HTML = `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="cns-page-state" content="ready"><title>Consent App</title>
<script type="module" crossorigin src="/assets/${SYNTHETIC_JS_NAME}"></script><link rel="stylesheet" crossorigin href="/assets/${SYNTHETIC_CSS_NAME}"></head>
<body class="lp-guest-body"><div id="root"></div></body></html>
`;

/** Crea un dist sintético nuevo (el llamador lo borra); `extraIndex` permite fabricar builds inválidos. */
export function makeSyntheticDist(indexHtml: string = SYNTHETIC_INDEX_HTML): string {
  const dir = mkdtempSync(join(tmpdir(), "cns-spa-dist-"));
  mkdirSync(join(dir, "assets"));
  mkdirSync(join(dir, ".vite"));
  writeFileSync(join(dir, "index.html"), indexHtml);
  writeFileSync(join(dir, "assets", SYNTHETIC_JS_NAME), "console.log('synthetic');\n");
  writeFileSync(join(dir, "assets", SYNTHETIC_CSS_NAME), ".lp-guest-body{margin:0}\n");
  writeFileSync(
    join(dir, ".vite", "manifest.json"),
    JSON.stringify({ "index.html": { file: `assets/${SYNTHETIC_JS_NAME}`, isEntry: true }, "style.css": { file: `assets/${SYNTHETIC_CSS_NAME}` } }),
  );
  writeFileSync(join(dir, "assets", SYNTHETIC_ORPHAN_NAME), "// no está en el manifiesto\n");
  return dir;
}

/** Dist compartido por proceso de test (se borra al salir). */
export const SYNTHETIC_SPA_DIST_DIR: string = makeSyntheticDist();
process.on("exit", () => {
  try {
    rmSync(SYNTHETIC_SPA_DIST_DIR, { recursive: true, force: true });
  } catch {
    // best effort
  }
});
