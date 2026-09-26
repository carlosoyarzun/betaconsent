// Gobierna: ADR-001 §11, CA-136 (H21), SEC-CNS-010 (P1-03, P1-04).
// Reglas de capas (Ports & Adapters), fail-closed:
//   (1) ALLOWLIST: solo src/server/entrypoints/** y src/infra/** pueden resolver (import
//       relativo) hacia src/infra/** (ADR-001 §11: "los adaptadores ... solo los importa
//       src/server/entrypoints/**"). Cualquier otro directorio bajo src/ (modules, platform,
//       ports, client, o uno nuevo que se cree) que importe src/infra/** de forma relativa
//       es una violación.
//   (2) src/client/** nunca importa src/server/** ni src/infra/** (de forma relativa).
//   (3) Todo especificador que no sea relativo-y-resoluble dentro de la raíz, built-in de
//       Node, o un paquete declarado en package.json → UNRESOLVED_SPECIFIER (fail-closed):
//       cubre alias de tsconfig (`baseUrl`/`paths`), subpath imports (`#foo`), rutas
//       absolutas, URLs `file://` y especificadores "pelados" que casualmente coinciden
//       con una ruta interna (`src/infra/...`).
//
// Limitación conocida (documentada en README y en la spec): solo se resuelven
// especificadores relativos ("./", "../"). tsconfig `paths`/`baseUrl` y package.json
// `imports`/`workspaces` no se resuelven: su sola presencia en la configuración es, en
// cambio, una violación aparte (ver `guardrail.ts`, CONFIG_ALIAS_NOT_SUPPORTED).

import { builtinModules } from "node:module";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

const BUILTIN_MODULE_NAMES = new Set<string>([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

export function isNodeBuiltin(specifier: string): boolean {
  return BUILTIN_MODULE_NAMES.has(specifier);
}

function normalize(p: string): string {
  return p.split(sep).join("/");
}

/** true si `filePath` (relativo a root, con "/") está bajo `dirPath` (relativo a root, con "/"). */
export function isUnder(filePath: string, dirPath: string): boolean {
  return filePath === dirPath || filePath.startsWith(`${dirPath}/`);
}

export type SpecifierClassification =
  | { type: "relative-internal"; relTarget: string }
  | { type: "relative-unresolved" } // relativo pero escapa de la raíz escaneada
  | { type: "builtin" }
  | { type: "declared-package"; packageName: string }
  | { type: "unresolved" };

/**
 * Clasifica un especificador visto desde `fileAbsPath` (dentro de `root`).
 * `declaredPackageNames` son los nombres de paquete exactos declarados en package.json
 * (dependencies/devDependencies/optionalDependencies/peerDependencies), ya usados tal cual
 * (sin wildcard) porque package.json nunca declara subpaths.
 */
export function classifySpecifier(
  root: string,
  fileAbsPath: string,
  specifier: string,
  declaredPackageNames: ReadonlySet<string>,
): SpecifierClassification {
  if (specifier.startsWith(".")) {
    // SEC-CNS-010 R-02: la raíz protegida es src/, no `root` completo (root también
    // contiene tools/, tests/, etc. fuera del árbol escaneado); y la comparación es por
    // segmentos de ruta (path.relative), no por prefijo de cadena ingenuo (evita que
    // "src/infra" acepte "src/infra-evil" o que ".." acabe dentro de root/node_modules
    // sin que se note).
    const resolved = resolve(dirname(fileAbsPath), specifier);
    const srcDirAbs = resolve(root, "src");
    const relFromSrc = normalize(relative(srcDirAbs, resolved));
    const escapesSrc = relFromSrc === ".." || relFromSrc.startsWith("../") || isAbsolute(relFromSrc);
    const segments = relFromSrc.split("/");
    const passesThroughNodeModules = segments.includes("node_modules");
    if (escapesSrc || passesThroughNodeModules) {
      return { type: "relative-unresolved" };
    }
    const relTarget = relFromSrc === "" ? "src" : `src/${relFromSrc}`;
    return { type: "relative-internal", relTarget };
  }
  if (isNodeBuiltin(specifier)) {
    return { type: "builtin" };
  }
  const packageName = extractBarePackageName(specifier);
  if (packageName !== null && declaredPackageNames.has(packageName)) {
    return { type: "declared-package", packageName };
  }
  return { type: "unresolved" };
}

/** Igual idea que deny-list-matcher.extractPackageName, sin normalizar a minúsculas (se usa
 * para comparar contra nombres declarados en package.json tal cual están escritos). */
function extractBarePackageName(specifier: string): string | null {
  if (specifier.startsWith(".") || specifier.startsWith("/")) {
    return null;
  }
  const segments = specifier.split("/");
  if (specifier.startsWith("@")) {
    if (segments.length < 2) return null;
    return `${segments[0]}/${segments[1]}`;
  }
  return segments[0] !== undefined && segments[0].length > 0 ? segments[0] : null;
}

const INFRA_DIR = "src/infra";
const CLIENT_DIR = "src/client";
const SERVER_DIR = "src/server";
const ENTRYPOINTS_DIR = "src/server/entrypoints";

/**
 * Verdadero si `fileRelPath` tiene permiso (por allowlist) de importar dentro de src/infra/**.
 */
export function mayImportInfra(fileRelPath: string): boolean {
  return isUnder(fileRelPath, ENTRYPOINTS_DIR) || isUnder(fileRelPath, INFRA_DIR);
}

export function isInfraTarget(relTarget: string): boolean {
  return isUnder(relTarget, INFRA_DIR);
}

export function isServerTarget(relTarget: string): boolean {
  return isUnder(relTarget, SERVER_DIR);
}

export function isClientFile(fileRelPath: string): boolean {
  return isUnder(fileRelPath, CLIENT_DIR);
}
