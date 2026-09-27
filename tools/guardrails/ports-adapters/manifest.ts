// Gobierna: ADR-001 §11, CA-136 (H21), SEC-CNS-010 (P1-03, P1-05).
// Lectura de package.json y package-lock.json para las reglas de manifiesto y de
// configuración de alias, fail-closed.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathExists } from "./file-walker.ts";

export interface ManifestDependency {
  /** Nombre de la clave en el campo de dependencias (puede ser un alias). */
  key: string;
  /** Especificador de versión tal cual aparece en el manifiesto. */
  versionSpec: string;
  field: "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies" | "bundleDependencies";
}

export interface ResolvedDependency extends ManifestDependency {
  /** Nombre de paquete real, resuelto si `versionSpec` es un alias `npm:pkg@version`. */
  effectivePackageName: string;
  /** true si `versionSpec` es un alias `npm:...`. */
  isNpmAlias: boolean;
  /** true si `versionSpec` no es del registry (file:, link:, git, URL). */
  isNonRegistry: boolean;
}

interface RawManifest {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  bundleDependencies?: string[] | boolean;
  imports?: Record<string, unknown>;
  workspaces?: unknown;
  overrides?: Record<string, unknown>;
}

const NON_REGISTRY_PREFIXES = ["file:", "link:", "git:", "git+", "http:", "https:"];

function parseNpmAlias(versionSpec: string): string | null {
  if (!versionSpec.startsWith("npm:")) return null;
  const rest = versionSpec.slice("npm:".length);
  if (rest.startsWith("@")) {
    // "@scope/name@version" o "@scope/name"
    const secondAt = rest.indexOf("@", 1);
    return secondAt === -1 ? rest : rest.slice(0, secondAt);
  }
  const at = rest.indexOf("@");
  return at === -1 ? rest : rest.slice(0, at);
}

export function loadRawManifest(root: string): RawManifest {
  const manifestPath = join(root, "package.json");
  if (!pathExists(manifestPath)) return {};
  const raw = readFileSync(manifestPath, "utf-8");
  return JSON.parse(raw) as RawManifest;
}

/** Todas las dependencias declaradas (dependencies, devDependencies, optional, peer, bundle),
 * con el alias npm: resuelto y marca de dependencia no-registry (file:/link:/git/URL). */
export function listResolvedDependencies(root: string): ResolvedDependency[] {
  const manifest = loadRawManifest(root);
  const results: ResolvedDependency[] = [];

  const fields: Array<[ManifestDependency["field"], Record<string, string> | undefined]> = [
    ["dependencies", manifest.dependencies],
    ["devDependencies", manifest.devDependencies],
    ["optionalDependencies", manifest.optionalDependencies],
    ["peerDependencies", manifest.peerDependencies],
  ];

  for (const [field, deps] of fields) {
    for (const [key, versionSpec] of Object.entries(deps ?? {})) {
      const alias = parseNpmAlias(versionSpec);
      const isNonRegistry = NON_REGISTRY_PREFIXES.some((prefix) => versionSpec.startsWith(prefix));
      results.push({
        key,
        versionSpec,
        field,
        effectivePackageName: alias ?? key,
        isNpmAlias: alias !== null,
        isNonRegistry,
      });
    }
  }

  if (Array.isArray(manifest.bundleDependencies)) {
    for (const key of manifest.bundleDependencies) {
      results.push({
        key,
        versionSpec: "(bundleDependencies)",
        field: "bundleDependencies",
        effectivePackageName: key,
        isNpmAlias: false,
        isNonRegistry: false,
      });
    }
  }

  return results;
}

/** Nombres de paquete declarados (claves tal cual, sin resolver alias) para clasificar
 * especificadores de import como "paquete declarado" (layer-rules.classifySpecifier). */
export function declaredPackageNames(root: string): Set<string> {
  return new Set(listResolvedDependencies(root).map((d) => d.key));
}

/** true si package.json declara `imports` (subpath imports) o `workspaces`. */
export function manifestHasUnsupportedAliasFields(root: string): boolean {
  const manifest = loadRawManifest(root);
  return manifest.imports !== undefined || manifest.workspaces !== undefined;
}

export type LockfileCheckResult =
  | { status: "ok"; names: Set<string> }
  | { status: "missing" }
  | { status: "unsupported-version"; version: number | undefined };

interface LockfilePackageEntry {
  /** Nombre real del paquete (SEC-CNS-010 P2): puede diferir del segmento de ruta
   * node_modules/<segmento> cuando el paquete se instaló bajo un alias `npm:`. */
  name?: string;
}

/**
 * Nombres de paquete presentes en package-lock.json (lockfile v3 con clave `packages`),
 * incluidos transitivos, preferentes el campo `name` de cada entrada (cubre el alias
 * transitivo `npm:`) sobre el segmento de ruta `node_modules/<segmento>`. Fail-closed
 * (SEC-CNS-010 P2): si no hay lockfile o no es v3, el resultado es un estado explícito de
 * error, no un Set vacío silencioso (el guardrail lo trata como violación).
 */
export function checkLockfile(root: string): LockfileCheckResult {
  const lockPath = join(root, "package-lock.json");
  if (!pathExists(lockPath)) return { status: "missing" };
  const raw = readFileSync(lockPath, "utf-8");
  const lock = JSON.parse(raw) as {
    lockfileVersion?: number;
    packages?: Record<string, LockfilePackageEntry>;
  };
  if (lock.lockfileVersion !== 3 || lock.packages === undefined) {
    return { status: "unsupported-version", version: lock.lockfileVersion };
  }
  const names = new Set<string>();
  for (const [pkgPath, entry] of Object.entries(lock.packages)) {
    if (pkgPath === "") continue; // el paquete raíz
    if (typeof entry.name === "string" && entry.name.length > 0) {
      names.add(entry.name);
      continue;
    }
    const idx = pkgPath.lastIndexOf("node_modules/");
    if (idx === -1) continue;
    const afterNodeModules = pkgPath.slice(idx + "node_modules/".length);
    const segments = afterNodeModules.split("/");
    const name = afterNodeModules.startsWith("@") ? `${segments[0]}/${segments[1]}` : segments[0];
    if (name !== undefined) names.add(name);
  }
  return { status: "ok", names };
}
