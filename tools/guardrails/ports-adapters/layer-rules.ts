// Gobierna: ADR-001 §11, CA-136 (H21).
// Reglas de capas (Ports & Adapters):
//   (1) src/server/modules/**, src/server/platform/** y src/server/ports/** nunca
//       importan src/infra/**.
//   (2) src/client/** nunca importa src/server/** ni src/infra/**.
//
// Limitación conocida (documentada en README y en la spec): solo se resuelven
// especificadores relativos ("./", "../"). Alias de paquete (p.ej. "@app/infra")
// no se resuelven; si se introducen, esta regla debe extenderse (ver Open en la spec).

import { dirname, resolve, sep } from "node:path";

export interface LayerBoundary {
  /** Directorio (relativo a la raíz del árbol escaneado) cuyos archivos están sujetos a la regla. */
  guardedDir: string;
  /** Directorios (relativos a la raíz) que guardedDir no puede alcanzar. */
  forbiddenTargets: string[];
  description: string;
}

export const LAYER_BOUNDARIES: LayerBoundary[] = [
  {
    guardedDir: "src/server/modules",
    forbiddenTargets: ["src/infra"],
    description: "src/server/modules/** no puede importar src/infra/** (ADR-001 §11 regla 1)",
  },
  {
    guardedDir: "src/server/platform",
    forbiddenTargets: ["src/infra"],
    description: "src/server/platform/** no puede importar src/infra/** (ADR-001 §11 regla 1)",
  },
  {
    guardedDir: "src/server/ports",
    forbiddenTargets: ["src/infra"],
    description: "src/server/ports/** no puede importar src/infra/** (ADR-001 §11 regla 1)",
  },
  {
    guardedDir: "src/client",
    forbiddenTargets: ["src/server", "src/infra"],
    description: "src/client/** no puede importar src/server/** ni src/infra/** (ADR-001 §11)",
  },
];

function normalize(p: string): string {
  return p.split(sep).join("/");
}

/** true si `filePath` (relativo a root, con "/") está bajo `dirPath` (relativo a root, con "/"). */
export function isUnder(filePath: string, dirPath: string): boolean {
  return filePath === dirPath || filePath.startsWith(`${dirPath}/`);
}

/**
 * Resuelve un especificador relativo desde el archivo que lo contiene y devuelve la ruta
 * resultante relativa a `root`, normalizada con separadores "/". Devuelve null si el
 * especificador no es relativo.
 */
export function resolveRelativeSpecifier(root: string, fileAbsPath: string, specifier: string): string | null {
  if (!specifier.startsWith(".")) {
    return null;
  }
  const resolved = resolve(dirname(fileAbsPath), specifier);
  const rootNormalized = normalize(resolve(root));
  const resolvedNormalized = normalize(resolved);
  if (!resolvedNormalized.startsWith(rootNormalized)) {
    // Import relativo que escapa de la raíz escaneada: fuera de alcance de esta regla.
    return null;
  }
  const rel = resolvedNormalized.slice(rootNormalized.length).replace(/^\/+/, "");
  return rel;
}

export function findApplicableBoundaries(fileRelPath: string): LayerBoundary[] {
  return LAYER_BOUNDARIES.filter((boundary) => isUnder(fileRelPath, boundary.guardedDir));
}
