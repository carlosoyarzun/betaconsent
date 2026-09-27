#!/usr/bin/env node
// Gobierna: JIRA CA-116 (H01/F-015). CLI del checker de máquinas de estado IT0.
// Uso: node tools/spec-checks/h01-sm-check.ts [specDir]
import { resolve } from "node:path";
import { checkSpecs, loadSpecs, SPEC_ORDER } from "./h01-sm-checker.ts";

function main(): void {
  const specDir = resolve(process.argv[2] ?? "specs/state-machines");
  let specs;
  try {
    specs = loadSpecs(specDir);
  } catch (e) {
    console.error(`[h01-sm-check] FALLÓ al cargar specs: ${(e as Error).message}`);
    process.exit(1);
    return;
  }
  const { errors, stats } = checkSpecs(specs);
  console.log(`[h01-sm-check] specs cargadas: ${SPEC_ORDER.join(", ")}`);
  for (const name of SPEC_ORDER) {
    const c = stats[name] ?? {};
    console.log(`  ${name}: ` + Object.entries(c).map(([k, v]) => `${k}=${v}`).join(" "));
  }
  if (errors.length > 0) {
    console.error(`[h01-sm-check] FALLÓ — ${errors.length} error(es):`);
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log("[h01-sm-check] PASS");
}

main();
