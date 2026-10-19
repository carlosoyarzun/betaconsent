// Gobierna: ADR-001 rev. 8 F1 (SPA React; decisión de Carlos 2026-10-18, fase A) + §11 (el código de UI no cruza al dominio).
// Lógica pura del guardrail de frontera de `frontend/`: ningún archivo de frontend/src ni frontend/tests puede importar
// (ni vía @import de CSS) algo que resuelva FUERA de frontend/, salvo:
//   - `import type` hacia contracts/** (tipos de contrato, si existen), y
//   - las excepciones exactas de EXACT_EXCEPTIONS (enlace de CSS al design system; app.css ya vive en frontend/, SSR retirado).
// El I/O vive en ./frontend-boundary-check.ts; probada con fixtures en memoria en tests/unit/framework/frontend-boundary.test.ts.

import { posix } from "node:path";

export interface SourceFile {
  /** Ruta POSIX relativa a la raíz del repo, p. ej. `frontend/src/pages/welcome.tsx`. */
  readonly path: string;
  readonly content: string;
}

/** Excepciones exactas `archivo -> destino` (relativos a la raíz del repo). */
export const EXACT_EXCEPTIONS: ReadonlyArray<{ readonly from: string; readonly to: string }> = [
  { from: "frontend/src/styles/index.css", to: "design-system/index.css" },
];

interface Specifier {
  readonly value: string;
  readonly typeOnly: boolean;
}

const JS_PATTERNS: readonly RegExp[] = [
  /\b(?:import|export)\s+(type\s+)?(?:[^'"`;]*?\s+from\s+)?["']([^"']+)["']/g,
  /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
  /\bnew\s+URL\s*\(\s*["']([^"']+)["']/g, // SEC-UI R6: new URL("../../src/x", import.meta.url)
  /\bimport\.meta\.glob(?:Eager)?\s*\(\s*\[?\s*["']([^"']+)["']/g, // import.meta.glob("../../src/**")
];
const CSS_PATTERNS: readonly RegExp[] = [/@import\s+(?:url\(\s*)?["']([^"']+)["']/g, /\burl\(\s*["']?([^"')\s]+)["']?\s*\)/g];

export function extractSpecifiers(path: string, content: string): Specifier[] {
  const out: Specifier[] = [];
  if (path.endsWith(".css")) {
    for (const re of CSS_PATTERNS) for (const m of content.matchAll(re)) out.push({ value: m[1] as string, typeOnly: false });
    return out;
  }
  const first = JS_PATTERNS[0] as RegExp;
  for (const m of content.matchAll(first)) out.push({ value: m[2] as string, typeOnly: m[1] !== undefined });
  for (const re of JS_PATTERNS.slice(1)) {
    for (const m of content.matchAll(re)) out.push({ value: m[1] as string, typeOnly: false });
  }
  return out;
}

export function checkFrontendBoundary(files: readonly SourceFile[]): string[] {
  const violations: string[] = [];
  for (const file of files) {
    for (const spec of extractSpecifiers(file.path, file.content)) {
      const isRelative = spec.value.startsWith(".");
      const isAbsolute = spec.value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(spec.value);
      if (!isRelative && !isAbsolute) continue; // paquete npm
      if (isAbsolute) {
        violations.push(`${file.path}: import absoluto "${spec.value}" (frontend/ solo importa dentro de frontend/ o paquetes npm)`);
        continue;
      }
      const resolved = posix.normalize(posix.join(posix.dirname(file.path), spec.value));
      if (resolved === "frontend" || resolved.startsWith("frontend/")) continue;
      if (EXACT_EXCEPTIONS.some((e) => e.from === file.path && e.to === resolved)) continue;
      if (spec.typeOnly && resolved.startsWith("contracts/")) continue;
      violations.push(`${file.path}: importa "${spec.value}" -> ${resolved}, fuera de frontend/ (solo \`import type\` de contracts/** está permitido)`);
    }
  }
  return violations;
}
