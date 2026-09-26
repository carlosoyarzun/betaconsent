// Gobierna: ADR-001 §11, CA-136 (H21).
// Recorrido de árbol de archivos sin dependencias externas (sin fast-glob ni similares).

import { readdirSync, statSync } from "node:fs";
import type { Dirent } from "node:fs";
import { join } from "node:path";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage"]);
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"];

export function isSourceFile(filePath: string): boolean {
  return SOURCE_EXTENSIONS.some((ext) => filePath.endsWith(ext));
}

/** Recorre recursivamente `dir` y devuelve las rutas absolutas de todos los archivos fuente. */
export function walkSourceFiles(dir: string): string[] {
  let entries: Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const results: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      results.push(...walkSourceFiles(join(dir, entry.name)));
    } else if (entry.isFile() && isSourceFile(entry.name)) {
      results.push(join(dir, entry.name));
    }
  }
  return results;
}

export function pathExists(path: string): boolean {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}
