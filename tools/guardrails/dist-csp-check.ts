#!/usr/bin/env node
// Gobierna: ADR-001 rev. 8 F1 y §3. CLI: node tools/guardrails/dist-csp-check.ts  (tras `npm run build:frontend`).
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkDist } from "./dist-csp.ts";

const DIST = join(resolve(dirname(fileURLToPath(import.meta.url)), "..", ".."), "dist");
if (!existsSync(join(DIST, "index.html"))) {
  console.error("[dist-csp] FALLÓ — no existe dist/index.html (ejecutar `npm run build:frontend`).");
  process.exit(1);
}
const names = existsSync(join(DIST, "assets")) ? readdirSync(join(DIST, "assets")) : [];
const violations = checkDist({
  indexHtml: readFileSync(join(DIST, "index.html"), "utf8"),
  assetPaths: new Set(names.map((n) => `/assets/${n}`)),
  cssContents: names.filter((n) => n.endsWith(".css")).map((n) => readFileSync(join(DIST, "assets", n), "utf8")),
});
if (violations.length > 0) {
  console.error(`[dist-csp] FALLÓ — ${violations.length} violación(es) (ADR-001 §3):`);
  for (const x of violations) console.error(`  - ${x}`);
  process.exit(1);
}
console.log(`[dist-csp] OK — dist/index.html sin inline; ${names.length} asset(s) con hash referenciables.`);
