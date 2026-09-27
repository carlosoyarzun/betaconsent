#!/usr/bin/env node
// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), JIRA CA-118 (H03),
// DEC-BR-014 E5.
//
// Runner de una capa de tests (unit | integration | contract) con node --test nativo
// (ADR-001 §5: sin frameworks salvo justificación). Descubre los archivos *.test.ts
// bajo el directorio de la capa recorriendo el árbol con node:fs (no glob de shell:
// npm ejecuta los scripts con /bin/sh, que no soporta "**" de forma portable), corre
// node --test con el reporter "spec" en stdout y el reporter de evidencia
// (evidence-reporter.ts) hacia evidence/test-runs/<layer>-<runId>.jsonl, y termina con
// el código de salida de node --test.
//
// Uso: node tools/testing/run-tests.ts <layer> <rootDir...>

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getRunContext } from "./run-context.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const TEST_FILE_RE = /\.test\.(ts|mts|mjs|js)$/;

function findTestFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  const stack: string[] = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (entry.name === "fixtures" || entry.name === "node_modules") continue;
      const full = join(current, entry.name);
      if (entry.isSymbolicLink()) continue; // fail-closed: no se siguen symlinks
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile() && TEST_FILE_RE.test(entry.name)) {
        out.push(full);
      }
    }
  }
  return out.sort();
}

function main(): void {
  const [layer, ...roots] = process.argv.slice(2);
  if (!layer || roots.length === 0) {
    console.error("Uso: node tools/testing/run-tests.ts <layer> <rootDir...>");
    process.exit(2);
  }

  const files = roots.flatMap((r) => findTestFiles(resolve(REPO_ROOT, r)));
  if (files.length === 0) {
    console.log(`[run-tests] capa "${layer}": sin archivos *.test.ts bajo ${roots.join(", ")}; nada que correr.`);
    process.exit(0);
  }

  const { runId } = getRunContext();
  const evidenceDir = resolve(REPO_ROOT, "evidence", "test-runs");
  mkdirSync(evidenceDir, { recursive: true });
  const evidenceFile = join(evidenceDir, `${layer}-${runId}.jsonl`);

  console.log(`[run-tests] capa "${layer}": ${files.length} archivo(s); evidencia -> ${evidenceFile}`);

  const result = spawnSync(
    process.execPath,
    [
      "--test",
      "--test-reporter=spec",
      "--test-reporter-destination=stdout",
      `--test-reporter=${join(HERE, "evidence-reporter.ts")}`,
      `--test-reporter-destination=${evidenceFile}`,
      ...files,
    ],
    {
      stdio: "inherit",
      env: { ...process.env, TEST_LAYER: layer, EVIDENCE_REPO_ROOT: REPO_ROOT },
    },
  );

  if (result.error) {
    console.error(result.error);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}

main();
