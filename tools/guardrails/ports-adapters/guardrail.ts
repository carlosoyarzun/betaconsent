// Gobierna: ADR-001 §11, CA-136 (H21), SEC-CNS-010 (P1-01..P1-06).
// Orquestador del guardrail Ports & Adapters. Expone `runGuardrail(root)` para uso
// programático (tests) y para el CLI (check.ts). Fail-closed en cada regla: ante
// ambigüedad o construcción no reconocida, se reporta violación en vez de omitirla.

import { readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { DenyList } from "./deny-list-matcher.ts";
import { findDenyListMatch, findDenyListMatchForPackageName } from "./deny-list-matcher.ts";
import { scanFileForFindings, moduleSpecifierFindings, primitiveFindings } from "./import-scanner.ts";
import type { PrimitiveFindingKind } from "./import-scanner.ts";
import { walkSourceFiles } from "./file-walker.ts";
import { classifySpecifier, isInfraTarget, isServerTarget, isClientFile, mayImportInfra } from "./layer-rules.ts";
import {
  declaredPackageNames,
  listResolvedDependencies,
  lockfilePackageNames,
  manifestHasUnsupportedAliasFields,
} from "./manifest.ts";

export type ViolationKind =
  | "DENY_LIST_OUTSIDE_ADAPTERS"
  | "DENY_LIST_FORBIDDEN"
  | "LAYER_BOUNDARY"
  | "MANIFEST_SDK_WITHOUT_ADAPTER"
  | "MANIFEST_FORBIDDEN_SDK"
  | "MANIFEST_FORBIDDEN_SDK_TRANSITIVE"
  | "MANIFEST_NPM_ALIAS_SDK"
  | "MANIFEST_NONREGISTRY_DEPENDENCY"
  | "UNRESOLVED_SPECIFIER"
  | "CONFIG_ALIAS_NOT_SUPPORTED"
  | "SYMLINK_UNDER_SRC"
  | "FORBIDDEN_DIR_UNDER_SRC"
  | "NON_LITERAL_DYNAMIC_CALL"
  | "FORBIDDEN_REQUIRE_USAGE"
  | "FORBIDDEN_GLOBAL_REQUIRE_ACCESS"
  | "FORBIDDEN_EVAL_OR_FUNCTION"
  | "FORBIDDEN_IMPORT_META_RESOLVE"
  | "FORBIDDEN_CREATE_REQUIRE_REFERENCE"
  | "FORBIDDEN_DANGEROUS_MODULE_IMPORT";

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

/** Módulos de Node cuya sola importación fuera de src/infra/adapters/** es peligrosa
 * (permiten reconstruir `require` dinámico o ejecutar procesos). SEC-CNS-010 P1-01. */
const DANGEROUS_BUILTIN_SPECIFIERS = new Set([
  "module",
  "node:module",
  "vm",
  "node:vm",
  "child_process",
  "node:child_process",
]);

function toRelPosix(root: string, absPath: string): string {
  return relative(root, absPath).split(sep).join("/");
}

function isUnderAdapters(fileRelPath: string): boolean {
  return fileRelPath === ADAPTERS_DIR || fileRelPath.startsWith(`${ADAPTERS_DIR}/`);
}

function loadDenyList(): DenyList {
  // La lista de denegación vive junto al guardrail (versionada, CODEOWNERS propio),
  // no dentro del árbol escaneado.
  const denyListPath = join(new URL(".", import.meta.url).pathname, "deny-list.json");
  const raw = readFileSync(denyListPath, "utf-8");
  return JSON.parse(raw) as DenyList;
}

/** tsconfig*.json (solo nivel superior de `root`) con `paths` o `baseUrl` configurados. */
function findTsconfigAliasFiles(root: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return [];
  }
  const hits: string[] = [];
  for (const name of entries) {
    if (!/^tsconfig(\..+)?\.json$/.test(name)) continue;
    try {
      const raw = readFileSync(join(root, name), "utf-8");
      const parsed = JSON.parse(raw) as { compilerOptions?: { paths?: unknown; baseUrl?: unknown } };
      const co = parsed.compilerOptions;
      if (co !== undefined && (co.paths !== undefined || co.baseUrl !== undefined)) {
        hits.push(name);
      }
    } catch {
      // Un tsconfig ilegible no es responsabilidad de este guardrail (typecheck lo cubre).
    }
  }
  return hits;
}

export function runGuardrail(root: string): GuardrailResult {
  const denyList = loadDenyList();
  const srcDir = join(root, "src");
  const walk = walkSourceFiles(srcDir);

  const violations: Violation[] = [];
  const declaredPkgs = declaredPackageNames(root);
  /** Nombres de paquete (ya resueltos contra la deny-list) importados desde algún adaptador. */
  const packagesImportedByAdapters = new Set<string>();

  // --- Estructura del árbol: symlinks y directorios prohibidos bajo src/ (P1-02) ---
  for (const symlinkAbs of walk.symlinks) {
    violations.push({
      kind: "SYMLINK_UNDER_SRC",
      file: toRelPosix(root, symlinkAbs),
      message: `Symlink bajo src/: "${toRelPosix(root, symlinkAbs)}". Prohibido (SEC-CNS-010 P1-02); no se sigue.`,
    });
  }
  for (const forbiddenDirAbs of walk.forbiddenDirs) {
    violations.push({
      kind: "FORBIDDEN_DIR_UNDER_SRC",
      file: toRelPosix(root, forbiddenDirAbs),
      message: `Directorio prohibido bajo src/: "${toRelPosix(root, forbiddenDirAbs)}" (node_modules/dist/build/coverage no pueden vivir bajo src/, SEC-CNS-010 P1-02).`,
    });
  }

  // --- Configuración de alias no soportada (P1-03) ---
  for (const tsconfigName of findTsconfigAliasFiles(root)) {
    violations.push({
      kind: "CONFIG_ALIAS_NOT_SUPPORTED",
      file: tsconfigName,
      message: `"${tsconfigName}" define "paths" o "baseUrl": este guardrail no resuelve alias de import, así que no puede garantizar sus reglas de capas/deny-list mientras existan (SEC-CNS-010 P1-03).`,
    });
  }
  if (manifestHasUnsupportedAliasFields(root)) {
    violations.push({
      kind: "CONFIG_ALIAS_NOT_SUPPORTED",
      file: "package.json",
      message: `package.json define "imports" o "workspaces": este guardrail no resuelve alias de import ni workspaces (SEC-CNS-010 P1-03).`,
    });
  }

  interface FileFindings {
    relPath: string;
    absPath: string;
    findings: ReturnType<typeof scanFileForFindings>;
  }
  const perFile: FileFindings[] = [];

  for (const absPath of walk.files) {
    const relPath = toRelPosix(root, absPath);
    const sourceText = readFileSync(absPath, "utf-8");
    const findings = scanFileForFindings(absPath, sourceText);
    perFile.push({ relPath, absPath, findings });
  }

  for (const { relPath, absPath, findings } of perFile) {
    const underAdapters = isUnderAdapters(relPath);

    // --- Primitivas peligrosas (P1-01): se aplican en todo src/**, incl. adaptadores,
    // salvo las dos marcadas explícitamente como "fuera de adaptadores" abajo. ---
    for (const p of primitiveFindings(findings)) {
      if (p.kind === "forbidden-create-require-reference") {
        if (!underAdapters) {
          violations.push({
            kind: "FORBIDDEN_CREATE_REQUIRE_REFERENCE",
            file: relPath,
            line: p.line,
            message: `${relPath}:${p.line} referencia "createRequire" fuera de ${ADAPTERS_DIR}/**: permite fabricar require dinámico y evadir la deny-list (SEC-CNS-010 P1-01).`,
          });
        }
        continue;
      }
      const kindMap: Record<Exclude<PrimitiveFindingKind, "forbidden-create-require-reference">, ViolationKind> = {
        "non-literal-dynamic-call": "NON_LITERAL_DYNAMIC_CALL",
        "forbidden-require-usage": "FORBIDDEN_REQUIRE_USAGE",
        "forbidden-global-require-access": "FORBIDDEN_GLOBAL_REQUIRE_ACCESS",
        "forbidden-eval-or-function": "FORBIDDEN_EVAL_OR_FUNCTION",
        "forbidden-import-meta-resolve": "FORBIDDEN_IMPORT_META_RESOLVE",
      };
      violations.push({
        kind: kindMap[p.kind],
        file: relPath,
        line: p.line,
        message: `${relPath}:${p.line} usa una construcción prohibida (${p.kind}); no es auditable de forma estática (SEC-CNS-010 P1-01).`,
      });
    }

    for (const imp of moduleSpecifierFindings(findings)) {
      // --- Builtins peligrosos fuera de adaptadores (module/vm/child_process) ---
      if (DANGEROUS_BUILTIN_SPECIFIERS.has(imp.specifier) && !underAdapters) {
        violations.push({
          kind: "FORBIDDEN_DANGEROUS_MODULE_IMPORT",
          file: relPath,
          line: imp.line,
          specifier: imp.specifier,
          message: `${relPath}:${imp.line} importa "${imp.specifier}" fuera de ${ADAPTERS_DIR}/** (SEC-CNS-010 P1-01, ADR-001 §6.1).`,
        });
      }

      // --- Deny-list (por modo): adapters-only vs forbidden ---
      const match = findDenyListMatch(imp.specifier, denyList);
      if (match !== null) {
        if (match.mode === "forbidden") {
          violations.push({
            kind: "DENY_LIST_FORBIDDEN",
            file: relPath,
            line: imp.line,
            specifier: imp.specifier,
            message: `"${imp.specifier}" está en modo "forbidden" (${match.category ?? "sin categoría"}): prohibido en todo src/**, incluidos los adaptadores, durante IT0 (ADR-001 §11 regla 6/§7; SEC-CNS-010 P1-06). ${relPath}:${imp.line} (${imp.kind}).`,
          });
        } else if (underAdapters) {
          packagesImportedByAdapters.add(match.package.toLowerCase());
        } else {
          violations.push({
            kind: "DENY_LIST_OUTSIDE_ADAPTERS",
            file: relPath,
            line: imp.line,
            specifier: imp.specifier,
            message: `"${imp.specifier}" está en la lista de denegación (modo adapters-only, ADR-001 §11) y solo puede importarse desde ${ADAPTERS_DIR}/**. Encontrado en ${relPath}:${imp.line} (${imp.kind}).`,
          });
        }
      }

      // --- Capas: allowlist para src/infra/**, prohibición dura para client -> server/infra,
      // y especificador no resoluble (P1-03) ---
      const classification = classifySpecifier(root, absPath, imp.specifier, declaredPkgs);
      if (classification.type === "relative-internal") {
        const target = classification.relTarget;
        if (isInfraTarget(target) && !mayImportInfra(relPath)) {
          violations.push({
            kind: "LAYER_BOUNDARY",
            file: relPath,
            line: imp.line,
            specifier: imp.specifier,
            message: `Solo src/server/entrypoints/** y src/infra/** pueden importar src/infra/** (ADR-001 §11, SEC-CNS-010 P1-04). ${relPath}:${imp.line} importa "${imp.specifier}" (resuelto a ${target}).`,
          });
        }
        if (isClientFile(relPath) && (isServerTarget(target) || isInfraTarget(target))) {
          violations.push({
            kind: "LAYER_BOUNDARY",
            file: relPath,
            line: imp.line,
            specifier: imp.specifier,
            message: `src/client/** no puede importar src/server/** ni src/infra/** (ADR-001 §11). ${relPath}:${imp.line} importa "${imp.specifier}" (resuelto a ${target}).`,
          });
        }
      } else if (classification.type === "unresolved" || classification.type === "relative-unresolved") {
        violations.push({
          kind: "UNRESOLVED_SPECIFIER",
          file: relPath,
          line: imp.line,
          specifier: imp.specifier,
          message: `${relPath}:${imp.line} importa "${imp.specifier}", que no es relativo-y-resoluble dentro de la raíz, ni un built-in de Node, ni un paquete declarado en package.json (SEC-CNS-010 P1-03; fail-closed).`,
        });
      }
      // classification.type === "builtin" | "declared-package": sin violación de capas/resolución.
    }
  }

  // --- Reglas de manifiesto (P1-05, P1-06) ---
  const resolvedDeps = listResolvedDependencies(root);
  for (const dep of resolvedDeps) {
    if (dep.isNonRegistry) {
      violations.push({
        kind: "MANIFEST_NONREGISTRY_DEPENDENCY",
        specifier: dep.key,
        message: `"${dep.key}" (${dep.field}) usa un especificador no-registry ("${dep.versionSpec}"): file:/link:/git/URL no se pueden auditar como SDK de proveedor; prohibido durante IT0 (SEC-CNS-010 P1-05).`,
      });
    }
    const match = findDenyListMatchForPackageName(dep.effectivePackageName, denyList);
    if (match === null) continue;

    if (dep.isNpmAlias) {
      violations.push({
        kind: "MANIFEST_NPM_ALIAS_SDK",
        specifier: dep.key,
        message: `"${dep.key}" (${dep.field}) es un alias npm: hacia "${dep.effectivePackageName}", que está en la deny-list (${match.mode}). Los alias evaden la detección por nombre; prohibido (SEC-CNS-010 P1-05).`,
      });
      continue;
    }

    if (match.mode === "forbidden") {
      violations.push({
        kind: "MANIFEST_FORBIDDEN_SDK",
        specifier: dep.key,
        message: `"${dep.key}" (${dep.field}) está en modo "forbidden" (${match.category ?? "sin categoría"}) y no puede declararse en package.json durante IT0 (SEC-CNS-010 P1-06).`,
      });
    } else if (!packagesImportedByAdapters.has(match.package.toLowerCase())) {
      violations.push({
        kind: "MANIFEST_SDK_WITHOUT_ADAPTER",
        specifier: dep.key,
        message: `"${dep.key}" (${dep.field}) está declarado y en la deny-list (adapters-only), pero ningún archivo bajo ${ADAPTERS_DIR}/** lo importa (ADR-001 §11).`,
      });
    }
  }

  // --- package-lock.json: transitivos en modo "forbidden" (P1-05) ---
  for (const lockedName of lockfilePackageNames(root)) {
    const match = findDenyListMatchForPackageName(lockedName, denyList);
    if (match !== null && match.mode === "forbidden") {
      violations.push({
        kind: "MANIFEST_FORBIDDEN_SDK_TRANSITIVE",
        specifier: lockedName,
        message: `"${lockedName}" aparece en package-lock.json (directo o transitivo) y está en modo "forbidden" (${match.category ?? "sin categoría"}); prohibido durante IT0 (SEC-CNS-010 P1-05/P1-06).`,
      });
    }
  }

  return { violations, filesScanned: perFile.length };
}
