#!/usr/bin/env node
// Gobierna: ADR-001 rev. 8 F1 (fase A). CLI del guardrail de frontera de frontend/ (lógica en ./frontend-boundary.ts).
// Uso: node tools/guardrails/frontend-boundary-check.ts  (escanea frontend/src y frontend/tests: .ts .tsx .js .jsx .mjs .cjs .css)
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { checkFrontendBoundary, type SourceFile } from "./frontend-boundary.ts";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCAN_ROOTS = ["frontend/src", "frontend/tests"];
const SOURCE_RE = /\.(ts|tsx|js|jsx|mjs|cjs|css)$/;

function walk(dir: string, out: SourceFile[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`symlink en frontend/ no permitido: ${relative(REPO_ROOT, full)}`);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && SOURCE_RE.test(entry.name)) {
      out.push({ path: relative(REPO_ROOT, full).split(sep).join("/"), content: readFileSync(full, "utf8") });
    }
  }
}

const files: SourceFile[] = [];
for (const root of SCAN_ROOTS) {
  const abs = join(REPO_ROOT, root);
  if (existsSync(abs)) walk(abs, files);
}
const violations = checkFrontendBoundary(files);
if (violations.length > 0) {
  console.error(`[frontend-boundary] FALLÓ — ${violations.length} violación(es) (ADR-001 F1):`);
  for (const v of violations) console.error(`  - ${v}`);
  process.exit(1);
}
console.log(`[frontend-boundary] OK — ${files.length} archivo(s) de frontend/ sin imports fuera de frontend/.`);
