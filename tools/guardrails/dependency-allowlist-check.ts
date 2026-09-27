#!/usr/bin/env node
// Gobierna: ADR-001 §5, ADR-001 §11 nota final; JIRA CA-118 (H03), openItem diferido
// de CA-136/SEC-CNS-010.
//
// CLI del guardrail de allowlist de dependencias. Uso:
// node tools/guardrails/dependency-allowlist-check.ts (siempre invocado directo en CI,
// no vía script de npm; SEC-CNS-011 P1-04). La lógica pura vive en
// ./dependency-allowlist.ts (probada con fixtures en memoria en
// tests/unit/framework/dependency-allowlist-check.test.ts); este archivo solo hace I/O
// y reporta el veredicto.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  runDependencyAllowlistCheck,
  type Allowlist,
  type Lockfile,
  type PackageJson,
} from "./dependency-allowlist.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function main(): void {
  const packageJson = readJson<PackageJson>(join(REPO_ROOT, "package.json"));
  const lockfile = readJson<Lockfile>(join(REPO_ROOT, "package-lock.json"));
  const allowlist = readJson<Allowlist>(join(REPO_ROOT, "tools", "guardrails", "dependency-allowlist.json"));

  const violations = runDependencyAllowlistCheck({ packageJson, lockfile, allowlist });

  if (violations.length > 0) {
    console.error(`[dependency-allowlist] FALLÓ — ${violations.length} violación(es) (ADR-001 §5):`);
    for (const v of violations) console.error(`  - ${v}`);
    process.exit(1);
  }

  const declaredCount = new Set([
    ...Object.keys(packageJson.dependencies ?? {}),
    ...Object.keys(packageJson.devDependencies ?? {}),
    ...Object.keys(packageJson.optionalDependencies ?? {}),
    ...Object.keys(packageJson.peerDependencies ?? {}),
  ]).size;

  console.log(
    `[dependency-allowlist] OK — ${declaredCount} dependencia(s) directa(s), todas en el allowlist con la ` +
      `versión exacta esperada.`,
  );
}

main();
