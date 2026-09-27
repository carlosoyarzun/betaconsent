#!/usr/bin/env node
// Gobierna: ADR-001 §5, ADR-001 §11 nota final; JIRA CA-118 (H03), openItem diferido
// de CA-136/SEC-CNS-010.
//
// Falla si package.json (dependencies/devDependencies directas) o la entrada de la
// raíz del lockfile (packages[""].dependencies/devDependencies) declaran un paquete
// que no está en tools/guardrails/dependency-allowlist.json, o cuya versión no
// coincide EXACTAMENTE con la fijada en el allowlist (ADR-001 §5: versiones exactas).
// No resuelve transitivos (eso es tools/guardrails/ports-adapters/manifest.ts para la
// deny-list "forbidden"); alcance = dependencias directas.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

type DepRecord = Record<string, string>;

interface PackageJson {
  dependencies?: DepRecord;
  devDependencies?: DepRecord;
}

interface LockfileRootPackage {
  dependencies?: DepRecord;
  devDependencies?: DepRecord;
}

interface Lockfile {
  packages?: Record<string, LockfileRootPackage>;
}

interface AllowlistEntry {
  name: string;
  version: string;
}

interface Allowlist {
  entries: AllowlistEntry[];
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function directDeps(record: DepRecord | undefined): DepRecord {
  return record ?? {};
}

function main(): void {
  const packageJson = readJson<PackageJson>(join(REPO_ROOT, "package.json"));
  const lockfile = readJson<Lockfile>(join(REPO_ROOT, "package-lock.json"));
  const allowlist = readJson<Allowlist>(join(REPO_ROOT, "tools", "guardrails", "dependency-allowlist.json"));

  const allowed = new Map(allowlist.entries.map((e) => [e.name, e.version]));

  const violations: string[] = [];

  const declared = new Map<string, string>([
    ...Object.entries(directDeps(packageJson.dependencies)),
    ...Object.entries(directDeps(packageJson.devDependencies)),
  ]);

  for (const [name, version] of declared) {
    const allowedVersion = allowed.get(name);
    if (allowedVersion === undefined) {
      violations.push(
        `package.json declara "${name}@${version}", que no está en tools/guardrails/dependency-allowlist.json (ADR-001 §5). Agregar entrada con owner humano antes de mergear.`,
      );
      continue;
    }
    if (version !== allowedVersion) {
      violations.push(
        `"${name}" está en package.json como "${version}" pero el allowlist fija "${allowedVersion}" (ADR-001 §5: versiones exactas). Actualizar ambos a la vez.`,
      );
    }
  }

  const rootLockEntry = lockfile.packages?.[""] ?? {};
  const lockDeclared = new Map<string, string>([
    ...Object.entries(directDeps(rootLockEntry.dependencies)),
    ...Object.entries(directDeps(rootLockEntry.devDependencies)),
  ]);

  for (const [name, version] of lockDeclared) {
    const allowedVersion = allowed.get(name);
    if (allowedVersion === undefined) {
      violations.push(
        `package-lock.json (packages[""]) declara "${name}@${version}", que no está en el allowlist. ¿package.json y package-lock.json están desincronizados?`,
      );
      continue;
    }
    if (version !== allowedVersion) {
      violations.push(
        `"${name}" en package-lock.json (packages[""]) es "${version}", distinto del allowlist ("${allowedVersion}"). package.json y package-lock.json deben coincidir con el allowlist.`,
      );
    }
  }

  const declaredNames = [...declared.keys()];
  if (declared.size !== lockDeclared.size || declaredNames.some((n) => !lockDeclared.has(n))) {
    violations.push(
      'package.json y package-lock.json (packages[""]) no declaran exactamente las mismas dependencias directas. Ejecutar npm install para sincronizar el lockfile.',
    );
  }

  if (violations.length > 0) {
    console.error(`[dependency-allowlist] FALLÓ — ${violations.length} violación(es) (ADR-001 §5):`);
    for (const v of violations) console.error(`  - ${v}`);
    process.exit(1);
  }

  console.log(
    `[dependency-allowlist] OK — ${declared.size} dependencia(s) directa(s), todas en el allowlist con la versión exacta esperada.`,
  );
}

main();
