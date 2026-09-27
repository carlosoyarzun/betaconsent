// Gobierna: ADR-001 §11, CA-136 (H21), SEC-CNS-010 (P1-06).
// Coincidencia de especificadores de import/require contra la lista de denegación,
// incluyendo subpaths (p.ej. "aws-sdk/clients/s3"), scopes con wildcard (p.ej. "@aws-sdk/*")
// y normalización a minúsculas (npm es case-sensitive en el registry, pero un import con
// mayúsculas distintas puede resolver igual en sistemas de archivos case-insensitive; se
// normaliza para no depender de eso, SEC-CNS-010 P2).

export type DenyListMode = "adapters-only" | "forbidden";

export interface DenyListEntry {
  package: string;
  mode: DenyListMode;
  category?: string;
  note?: string;
}

export interface DenyList {
  version: number;
  status: string;
  governedBy: string[];
  modes?: Record<string, string>;
  note?: string;
  entries: DenyListEntry[];
}

function normalize(name: string): string {
  return name.toLowerCase();
}

/**
 * Extrae el nombre de paquete npm de un especificador de módulo (normalizado a minúsculas).
 * "aws-sdk/clients/s3" -> "aws-sdk"
 * "@aws-sdk/client-s3" -> "@aws-sdk/client-s3"
 * "@AWS-SDK/client-s3" -> "@aws-sdk/client-s3"
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
    return normalize(`${segments[0]}/${segments[1]}`);
  }
  return segments[0] !== undefined && segments[0].length > 0 ? normalize(segments[0]) : null;
}

/**
 * Determina si un nombre de paquete (ya extraído, sin subpath, ya normalizado) coincide con
 * una entrada de la lista de denegación. Soporta wildcard de scope completo: "@scope/*".
 */
export function packageMatchesEntry(packageName: string, entryPattern: string): boolean {
  const pattern = normalize(entryPattern);
  const name = normalize(packageName);
  if (pattern.endsWith("/*")) {
    const scope = pattern.slice(0, -1); // "@aws-sdk/"
    return name.startsWith(scope) && name.length > scope.length;
  }
  return name === pattern;
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
  return findDenyListMatchForPackageName(packageName, denyList);
}

/**
 * Igual que `findDenyListMatch`, pero recibe directamente un nombre de paquete ya resuelto
 * (p. ej. desde package.json o package-lock.json, donde no hay subpaths que extraer).
 */
export function findDenyListMatchForPackageName(packageName: string, denyList: DenyList): DenyListEntry | null {
  for (const entry of denyList.entries) {
    if (packageMatchesEntry(packageName, entry.package)) {
      return entry;
    }
  }
  return null;
}
