// Gobierna: ADR-001 §11, CA-136 (H21), SEC-CNS-010 (P1-02).
// Recorrido de árbol de archivos sin dependencias externas (sin fast-glob ni similares).
// Fail-closed: symlinks bajo src/ son violación (no se siguen); node_modules/dist/build/
// coverage bajo src/ son violación pero SE recorren (no se saltan, fail-closed: si alguien
// vendoriza un SDK ahí, se escanea igual); un error de lectura distinto de "el directorio
// raíz no existe" se propaga (no se traga como árbol vacío).

import { readdirSync, statSync } from "node:fs";
import type { Dirent } from "node:fs";
import { join } from "node:path";

const FORBIDDEN_DIR_NAMES = new Set(["node_modules", "dist", "build", "coverage"]);
// El stack de Consent App es React + TS (ADR-001 §1); .vue/.svelte no tienen lugar legítimo
// aquí, pero se escanean igual (fail-closed: una extensión inusual no es forma de evadir el
// guardrail, SEC-CNS-010, corpus de evasión).
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs", ".vue", ".svelte"];

export function isSourceFile(filePath: string): boolean {
  return SOURCE_EXTENSIONS.some((ext) => filePath.endsWith(ext));
}

export interface WalkResult {
  /** Rutas absolutas de archivos fuente (incluye los que están dentro de un directorio prohibido). */
  files: string[];
  /** Rutas absolutas de symlinks (archivo o directorio) encontrados bajo la raíz. No se siguen. */
  symlinks: string[];
  /** Rutas absolutas de directorios node_modules/dist/build/coverage encontrados bajo la raíz. */
  forbiddenDirs: string[];
}

function walk(dir: string, acc: WalkResult): void {
  const entries: Dirent[] = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      // Fail-closed: no se sigue el symlink (podría escapar de la raíz escaneada);
      // su sola presencia bajo src/ es una violación.
      acc.symlinks.push(entryPath);
      continue;
    }
    if (entry.isDirectory()) {
      if (FORBIDDEN_DIR_NAMES.has(entry.name)) {
        acc.forbiddenDirs.push(entryPath);
      }
      walk(entryPath, acc);
    } else if (entry.isFile() && isSourceFile(entry.name)) {
      acc.files.push(entryPath);
    }
  }
}

/**
 * Recorre `root` recursivamente. Si `root` no existe (p.ej. no hay `src/` todavía), devuelve
 * un resultado vacío: eso es válido (repo pre-build). Cualquier otro error de lectura (permisos,
 * directorio desaparece a mitad del recorrido, etc.) se propaga sin capturar.
 */
export function walkSourceFiles(root: string): WalkResult {
  const acc: WalkResult = { files: [], symlinks: [], forbiddenDirs: [] };
  try {
    walk(root, acc);
  } catch (err: unknown) {
    if (err !== null && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      return acc;
    }
    throw err;
  }
  return acc;
}

export function pathExists(path: string): boolean {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}
