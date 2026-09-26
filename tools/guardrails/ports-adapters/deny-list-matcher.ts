// Gobierna: ADR-001 §11, CA-136 (H21).
// Coincidencia de especificadores de import/require contra la lista de denegación,
// incluyendo subpaths (p.ej. "aws-sdk/clients/s3") y scopes con wildcard (p.ej. "@aws-sdk/*").

export interface DenyListEntry {
  package: string;
  note?: string;
}

export interface DenyList {
  version: number;
  governedBy: string[];
  status: string;
  note?: string;
  entries: DenyListEntry[];
}

/**
 * Extrae el nombre de paquete npm de un especificador de módulo.
 * "aws-sdk/clients/s3" -> "aws-sdk"
 * "@aws-sdk/client-s3" -> "@aws-sdk/client-s3"
 * "@aws-sdk/client-s3/dist/foo" -> "@aws-sdk/client-s3"
 * "./local-module" -> null (import relativo, no es un paquete npm)
 * "node:fs" -> null (módulo built-in de Node)
 */
export function extractPackageName(specifier: string): string | null {
  if (specifier.startsWith(".") || specifier.startsWith("/")) {
    return null;
  }
  if (specifier.startsWith("node:")) {
    return null;
  }
  const segments = specifier.split("/");
  if (specifier.startsWith("@")) {
    if (segments.length < 2) {
      return null;
    }
    return `${segments[0]}/${segments[1]}`;
  }
  return segments[0] ?? null;
}

/**
 * Determina si un nombre de paquete (ya extraído, sin subpath) coincide con una entrada
 * de la lista de denegación. Soporta wildcard de scope completo: "@scope/*".
 */
export function packageMatchesEntry(packageName: string, entryPattern: string): boolean {
  if (entryPattern.endsWith("/*")) {
    const scope = entryPattern.slice(0, -1); // "@aws-sdk/"
    return packageName.startsWith(scope) && packageName.length > scope.length;
  }
  return packageName === entryPattern;
}

/**
 * Devuelve la entrada de la lista de denegación que coincide con el especificador dado,
 * o null si no hay coincidencia (incluye módulos relativos y built-ins de Node, que nunca
 * coinciden).
 */
export function findDenyListMatch(specifier: string, denyList: DenyList): DenyListEntry | null {
  const packageName = extractPackageName(specifier);
  if (packageName === null) {
    return null;
  }
  for (const entry of denyList.entries) {
    if (packageMatchesEntry(packageName, entry.package)) {
      return entry;
    }
  }
  return null;
}
