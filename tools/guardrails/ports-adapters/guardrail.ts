// Gobierna: ADR-001 §11, CA-136 (H21).
// Orquestador del guardrail Ports & Adapters. Expone `runGuardrail(root)` para uso
// programático (tests) y para el CLI (check.ts).

import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { DenyList } from "./deny-list-matcher.ts";
import { findDenyListMatch } from "./deny-list-matcher.ts";
import { scanFileForImports } from "./import-scanner.ts";
import type { DetectedImport } from "./import-scanner.ts";
import { walkSourceFiles, pathExists } from "./file-walker.ts";
import { findApplicableBoundaries, resolveRelativeSpecifier } from "./layer-rules.ts";

export type ViolationKind =
  | "DENY_LIST_OUTSIDE_ADAPTERS"
  | "LAYER_BOUNDARY"
  | "MANIFEST_SDK_WITHOUT_ADAPTER";

export interface Violation {
  kind: ViolationKind;
  file?: string; // relativo a root
  line?: number;
  specifier?: string;
  message: string;
}

export interface GuardrailResult {
  violations: Violation[];
  filesScanned: number;
}

const ADAPTERS_DIR = "src/infra/adapters";

function toRelPosix(root: string, absPath: string): string {
  return relative(root, absPath).split(sep).join("/");
}

function isUnderAdapters(fileRelPath: string): boolean {
  return fileRelPath === ADAPTERS_DIR || fileRelPath.startsWith(`${ADAPTERS_DIR}/`);
}

function loadDenyList(root: string): DenyList {
  // La lista de denegación vive junto al guardrail (versionada, CODEOWNERS propio),
  // no dentro del árbol escaneado.
  const denyListPath = join(new URL(".", import.meta.url).pathname, "deny-list.json");
  const raw = readFileSync(denyListPath, "utf-8");
  return JSON.parse(raw) as DenyList;
}

function loadManifestDependencyNames(root: string): string[] {
  const manifestPath = join(root, "package.json");
  if (!pathExists(manifestPath)) {
    return [];
  }
  const raw = readFileSync(manifestPath, "utf-8");
  const manifest = JSON.parse(raw) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  return [...Object.keys(manifest.dependencies ?? {}), ...Object.keys(manifest.devDependencies ?? {})];
}

export function runGuardrail(root: string): GuardrailResult {
  const denyList = loadDenyList(root);
  const srcDir = join(root, "src");
  const absFiles = walkSourceFiles(srcDir);

  const violations: Violation[] = [];
  /** Nombres de paquete (ya resueltos contra la deny-list) importados desde algún adaptador. */
  const packagesImportedByAdapters = new Set<string>();

  interface FileImports {
    relPath: string;
    absPath: string;
    imports: DetectedImport[];
  }
  const perFile: FileImports[] = [];

  for (const absPath of absFiles) {
    const relPath = toRelPosix(root, absPath);
    const sourceText = readFileSync(absPath, "utf-8");
    const imports = scanFileForImports(absPath, sourceText);
    perFile.push({ relPath, absPath, imports });
  }

  for (const { relPath, absPath, imports } of perFile) {
    const underAdapters = isUnderAdapters(relPath);

    for (const imp of imports) {
      // Regla: SDK de la lista de denegación fuera de src/infra/adapters/**.
      const match = findDenyListMatch(imp.specifier, denyList);
      if (match !== null) {
        if (underAdapters) {
          packagesImportedByAdapters.add(match.package);
        } else {
          violations.push({
            kind: "DENY_LIST_OUTSIDE_ADAPTERS",
            file: relPath,
            line: imp.line,
            specifier: imp.specifier,
            message: `"${imp.specifier}" está en la lista de denegación de SDKs de proveedor (ADR-001 §11) y solo puede importarse desde ${ADAPTERS_DIR}/**. Encontrado en ${relPath}:${imp.line} (${imp.kind}).`,
          });
        }
      }

      // Regla: límites de capa (dominio/aplicación/plataforma/ports no importan infra;
      // cliente no importa server ni infra).
      const boundaries = findApplicableBoundaries(relPath);
      if (boundaries.length > 0) {
        const resolvedTarget = resolveRelativeSpecifier(root, absPath, imp.specifier);
        if (resolvedTarget !== null) {
          for (const boundary of boundaries) {
            const hitsForbidden = boundary.forbiddenTargets.some(
              (forbidden) => resolvedTarget === forbidden || resolvedTarget.startsWith(`${forbidden}/`),
            );
            if (hitsForbidden) {
              violations.push({
                kind: "LAYER_BOUNDARY",
                file: relPath,
                line: imp.line,
                specifier: imp.specifier,
                message: `${boundary.description}. ${relPath}:${imp.line} importa "${imp.specifier}" (resuelto a ${resolvedTarget}).`,
              });
            }
          }
        }
      }
    }
  }

  // Regla: SDK de proveedor en el manifiesto sin adaptador consumidor.
  const manifestDeps = loadManifestDependencyNames(root);
  for (const depName of manifestDeps) {
    const match = findDenyListMatch(depName, denyList);
    if (match !== null && !packagesImportedByAdapters.has(match.package)) {
      violations.push({
        kind: "MANIFEST_SDK_WITHOUT_ADAPTER",
        specifier: depName,
        message: `"${depName}" está declarado en package.json y en la lista de denegación de SDKs de proveedor, pero ningún archivo bajo ${ADAPTERS_DIR}/** lo importa (ADR-001 §11).`,
      });
    }
  }

  return { violations, filesScanned: perFile.length };
}
