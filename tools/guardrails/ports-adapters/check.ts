#!/usr/bin/env node
// Gobierna: ADR-001 §11, CA-136 (H21).
// CLI del guardrail Ports & Adapters. Uso: node tools/guardrails/ports-adapters/check.ts [root]
// `root` por defecto es el directorio de trabajo actual (la raíz del repo en CI).

import { runGuardrail } from "./guardrail.ts";

function main(): void {
  const root = process.argv[2] ?? process.cwd();
  const { violations, filesScanned } = runGuardrail(root);

  if (violations.length === 0) {
    console.log(
      `[guardrail:ports-adapters] OK — ${filesScanned} archivo(s) escaneados bajo src/, sin violaciones (ADR-001 §11).`,
    );
    process.exit(0);
  }

  console.error(`[guardrail:ports-adapters] FALLÓ — ${violations.length} violación(es) (ADR-001 §11):`);
  for (const v of violations) {
    console.error(`  - [${v.kind}] ${v.message}`);
  }
  process.exit(1);
}

main();
