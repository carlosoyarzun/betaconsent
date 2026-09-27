// Gobierna: ADR-001 §5, ADR-001 §11 nota final; JIRA CA-118 (H03), openItem diferido
// de CA-136/SEC-CNS-010; SEC-CNS-011 P2-01 (revisión de seguridad pre-PR CA-118).
//
// Lógica PURA del guardrail de allowlist de dependencias (sin I/O de filesystem), para
// que tests/unit/framework/dependency-allowlist-check.test.ts pueda probarla con
// fixtures en memoria. tools/guardrails/dependency-allowlist-check.ts es el CLI que lee
// package.json / package-lock.json / dependency-allowlist.json del repo y llama a
// runDependencyAllowlistCheck.
//
// Alcance (SEC-CNS-011 P2-01): dependencies, devDependencies, optionalDependencies y
// peerDependencies DIRECTAS de package.json se tratan por igual. bundleDependencies y
// overrides son vías de evasión del allowlist que este checker todavía no resuelve: si
// aparecen, el checker falla explícitamente en vez de ignorarlos.

export type DepRecord = Record<string, string>;

export interface PackageJson {
  dependencies?: DepRecord;
  devDependencies?: DepRecord;
  optionalDependencies?: DepRecord;
  peerDependencies?: DepRecord;
  bundleDependencies?: string[] | boolean;
  overrides?: Record<string, unknown>;
}

export interface LockfileRootPackage {
  dependencies?: DepRecord;
  devDependencies?: DepRecord;
  optionalDependencies?: DepRecord;
  peerDependencies?: DepRecord;
}

export interface Lockfile {
  packages?: Record<string, LockfileRootPackage>;
}

export interface AllowlistEntry {
  name: string;
  version: string;
  owner?: string;
  [key: string]: unknown;
}

export interface Allowlist {
  entries: AllowlistEntry[];
}

const EXACT_VERSION_RE = /^\d+\.\d+\.\d+$/;

// Agentes IA de docs/agentic/model-routing.md: ninguno puede ser "owner" de una entrada
// del allowlist (ADR-001 §11: "ningún agente IA es owner ni code owner"). "proposedBy"
// sí puede ser un agente; este chequeo solo mira "owner".
const KNOWN_AI_AGENTS = new Set([
  "medina-scout",
  "medina-synth",
  "santos-product",
  "ravena-ux",
  "gaona-measure",
  "lampone-architect",
  "lampone-security",
  "lampone-dev",
  "lampone-qa",
  "auditor-contradictions",
  "scribe-sync",
]);

function directDeps(record: DepRecord | undefined): DepRecord {
  return record ?? {};
}

/** Valida las entradas del allowlist mismo (versión exacta, owner humano no vacío). */
export function validateAllowlistEntries(allowlist: Allowlist): string[] {
  const violations: string[] = [];
  for (const entry of allowlist.entries) {
    if (!EXACT_VERSION_RE.test(entry.version)) {
      violations.push(
        `El allowlist fija "${entry.name}" con version "${entry.version}", que no es una versión exacta ` +
          `(ADR-001 §5: sin "^"/"~"/rangos; formato "X.Y.Z").`,
      );
    }
    const owner = typeof entry.owner === "string" ? entry.owner.trim() : "";
    if (owner.length === 0) {
      violations.push(`La entrada "${entry.name}" del allowlist no tiene "owner" humano no vacío (ADR-001 §11).`);
    } else if (KNOWN_AI_AGENTS.has(owner)) {
      violations.push(
        `La entrada "${entry.name}" del allowlist tiene owner "${owner}", que es un agente IA. Ningún agente IA ` +
          `es owner (ADR-001 §11); el owner debe ser una persona humana.`,
      );
    }
  }
  return violations;
}

function collectDeclared(source: {
  dependencies?: DepRecord;
  devDependencies?: DepRecord;
  optionalDependencies?: DepRecord;
  peerDependencies?: DepRecord;
}): Map<string, string> {
  return new Map<string, string>([
    ...Object.entries(directDeps(source.dependencies)),
    ...Object.entries(directDeps(source.devDependencies)),
    ...Object.entries(directDeps(source.optionalDependencies)),
    ...Object.entries(directDeps(source.peerDependencies)),
  ]);
}

/** Corre el guardrail completo y devuelve la lista de violaciones (vacía = OK). */
export function runDependencyAllowlistCheck(input: {
  packageJson: PackageJson;
  lockfile: Lockfile;
  allowlist: Allowlist;
}): string[] {
  const { packageJson, lockfile, allowlist } = input;
  const violations = validateAllowlistEntries(allowlist);
  const allowed = new Map(allowlist.entries.map((e) => [e.name, e.version]));

  if (packageJson.bundleDependencies !== undefined) {
    violations.push(
      'package.json declara "bundleDependencies", que este guardrail no resuelve todavía (SEC-CNS-011 P2-01); ' +
        "retirarlo o extender el checker antes de aceptarlo.",
    );
  }
  if (packageJson.overrides !== undefined) {
    violations.push(
      'package.json declara "overrides", que puede fijar versiones fuera del allowlist sin pasar por ' +
        "dependencies/devDependencies (vía de evasión, SEC-CNS-011 P2-01); retirarlo o extender el checker " +
        "antes de aceptarlo.",
    );
  }

  const declared = collectDeclared(packageJson);
  for (const [name, version] of declared) {
    const allowedVersion = allowed.get(name);
    if (allowedVersion === undefined) {
      violations.push(
        `package.json declara "${name}@${version}", que no está en tools/guardrails/dependency-allowlist.json ` +
          `(ADR-001 §5). Agregar entrada con owner humano antes de mergear.`,
      );
      continue;
    }
    if (version !== allowedVersion) {
      violations.push(
        `"${name}" está en package.json como "${version}" pero el allowlist fija "${allowedVersion}" ` +
          `(ADR-001 §5: versiones exactas). Actualizar ambos a la vez.`,
      );
    }
  }

  const rootLockEntry = lockfile.packages?.[""] ?? {};
  const lockDeclared = collectDeclared(rootLockEntry);
  for (const [name, version] of lockDeclared) {
    const allowedVersion = allowed.get(name);
    if (allowedVersion === undefined) {
      violations.push(
        `package-lock.json (packages[""]) declara "${name}@${version}", que no está en el allowlist. ` +
          `¿package.json y package-lock.json están desincronizados?`,
      );
      continue;
    }
    if (version !== allowedVersion) {
      violations.push(
        `"${name}" en package-lock.json (packages[""]) es "${version}", distinto del allowlist ` +
          `("${allowedVersion}"). package.json y package-lock.json deben coincidir con el allowlist.`,
      );
    }
  }

  const declaredNames = [...declared.keys()];
  if (declared.size !== lockDeclared.size || declaredNames.some((n) => !lockDeclared.has(n))) {
    violations.push(
      'package.json y package-lock.json (packages[""]) no declaran exactamente las mismas dependencias directas. ' +
        "Ejecutar npm install para sincronizar el lockfile.",
    );
  }

  return violations;
}
