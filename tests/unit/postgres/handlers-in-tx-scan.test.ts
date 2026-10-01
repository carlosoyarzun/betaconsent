// Gobierna: CA-124 (PR-E), SEC-CNS-016 (lecturas fuera de tx), ADR-006 §1/§4-§6. TEST-CNS-870: chequeo
// estatico de los handlers HTTP (src/server/entrypoints/http/*.ts): todo acceso a un repo, al ledger, al
// outbox, al catalogo o a la idempotencia debe ocurrir DENTRO del callback de un `inTenant(...)`; un uso
// fuera de una tx falla este test. Sin Postgres.

import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const DIR = join(import.meta.dirname, "..", "..", "..", "src", "server", "entrypoints", "http");
const ACCESS = /\b(?:\w*Repo|repo|ledger|outbox|tenantCatalog|idempotency)\.(?:find\w*|save|consume|append|currentSequence|listByAggregate|enqueue|subjectBelongsToTenant|store)\s*\(/g;

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/\/\/[^\n]*/g, (m) => " ".repeat(m.length));
}

/** Rangos [inicio, fin) de los argumentos de cada `inTenant(` (parentesis balanceados). */
function inTenantRanges(src: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  for (const m of src.matchAll(/\binTenant\s*\(/g)) {
    let depth = 1;
    let i = (m.index ?? 0) + m[0].length;
    const start = i;
    while (i < src.length && depth > 0) {
      if (src[i] === "(") depth += 1;
      else if (src[i] === ")") depth -= 1;
      i += 1;
    }
    ranges.push([start, i]);
  }
  return ranges;
}

export function findOutsideTxAccesses(source: string): string[] {
  const src = stripComments(source);
  const ranges = inTenantRanges(src);
  const bad: string[] = [];
  for (const m of src.matchAll(ACCESS)) {
    const at = m.index ?? 0;
    if (!ranges.some(([a, b]) => at >= a && at < b)) bad.push(`${m[0]} @${src.slice(0, at).split("\n").length}`);
  }
  return bad;
}

test("TEST-CNS-870 los handlers HTTP no usan repos, ledger, outbox, catalogo ni idempotencia fuera de uow.inTenant", () => {
  const files = readdirSync(DIR).filter((f) => f.endsWith(".ts"));
  assert.ok(files.length > 5);
  for (const f of files) {
    assert.deepEqual(findOutsideTxAccesses(readFileSync(join(DIR, f), "utf8")), [], `${f}: acceso fuera de inTenant`);
  }
});

test("TEST-CNS-870 el detector atrapa un uso fuera de tx y acepta uno dentro", () => {
  assert.equal(findOutsideTxAccesses("await ports.invitationRepo.findByRef(t, r);").length, 1);
  assert.equal(findOutsideTxAccesses("await ports.uow.inTenant(t, (tx) => tx.invitationRepo.findByRef(t, r));").length, 0);
  assert.equal(findOutsideTxAccesses("// ports.ledger.append(x)\n/* repo.save(y) */").length, 0);
});
