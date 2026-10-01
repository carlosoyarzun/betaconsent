// Gobierna: DEC-BR-014 rev. 8 §3 (X3/X5/X6 con evidencia en evidence/); decision de Carlos 2026-10-01 "evidencia (a)".
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertCleanManifest, buildManifests, manifestPath, parseCsv, parseMatrix, parseRunRecords, scanManifest, statusOf,
  type Manifest, type MatrixRow,
} from "../../../scripts/evidence/manifest.ts";

const row = (id: string, file: string, governedBy: string, title = "t"): MatrixRow => ({ id, layer: "unit", file, title, governedBy, status: "ACTIVE" });
const base = { commit: "5a0e4ec1111111111111111111111111111111aa", branch: "main", runAt: "2026-10-01T12:00:00.000Z", environment: "LOCAL" as const, postgresDigest: null, exitCode: 0 };

test("TEST-CNS-990 parseCsv/parseMatrix: comillas, comas y '' escapado; cabecera inesperada falla", () => {
  assert.deepEqual(parseCsv('a,"b,c","d""e"\n1,2,3\n'), [["a", "b,c", 'd"e'], ["1", "2", "3"]]);
  const m = parseMatrix('test_id,layer,file,test_name,governed_by,status\nTEST-CNS-1,unit,f.ts,"x, y",X3;ADR-1,ACTIVE\n');
  assert.equal(m[0]?.title, "x, y");
  assert.throws(() => parseMatrix("a,b\n1,2\n"));
});

test("TEST-CNS-990 asignacion por condicion: token X3/X5/X6 exacto (no X30) y solo filas ACTIVE; estados pass/fail/skip desde los JSONL", () => {
  const matrix = [
    row("TEST-CNS-1", "a.ts", "X3;X5"), row("TEST-CNS-2", "b.ts", "X6"), row("TEST-CNS-3", "c.ts", "X30;REQ"),
    { ...row("TEST-CNS-4", "a.ts", "X3"), status: "DEPRECATED" }, row("TEST-CNS-1", "a.ts", "X3"),
  ];
  const records = parseRunRecords([
    { file: "a.ts", testName: "TEST-CNS-1 ok", result: "pass" }, { file: "b.ts", testName: "TEST-CNS-2 mal", result: "fail" },
  ].map((r) => JSON.stringify({ schema: "test-evidence/v1", ...r })).join("\n"));
  const [x3, x5, x6] = buildManifests({ matrix, records, ...base });
  assert.deepEqual(x3?.tests.map((t) => [t.id, t.status]), [["TEST-CNS-1", "pass"]]); // dedupe id+file
  assert.equal(x5?.tests.length, 1);
  assert.deepEqual(x6?.tests.map((t) => [t.id, t.status]), [["TEST-CNS-2", "fail"]]);
  assert.deepEqual(x6?.summary, { pass: 0, fail: 1, skip: 0 });
  assert.equal(statusOf(row("TEST-CNS-9", "z.ts", "X3"), records), "skip"); // sin registros
  assert.equal(manifestPath("out", x3 as Manifest), "out/X3/2026-10-01-5a0e4ec.json");
});

test("TEST-CNS-990 el manifiesto limpio pasa; un email plantado, un token, un JWT o un secreto lo rechazan sin eco del valor", () => {
  const [ok] = buildManifests({ matrix: [row("TEST-CNS-1", "a.ts", "X3", "titulo normal con __Host-* y dm: citados")], records: [], ...base, postgresDigest: `sha256:${"a1".repeat(32)}` });
  assert.ok(ok);
  assert.deepEqual(scanManifest(ok), []);
  assertCleanManifest(ok);
  const plant = (title: string): Manifest => ({ ...ok, tests: [{ ...(ok.tests[0] as Manifest["tests"][number]), title }] });
  for (const [title, kind] of [
    ["contacto ana.perez@gmail.com", "email-like"], ["contacto a@x.test", "email-like"],
    ["abc123def456ghi789jkl012mno345pqr678", "token-like"], ["eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0", "jwt-like"],
    ["password=hunter2hunter2", "secret-assignment"], ["postgres://u:pw1234@host/db", "url-credentials"],
  ] as const) {
    const m = plant(title);
    assert.ok(scanManifest(m).includes(kind), `${kind} no detectado`);
    assert.throws(() => assertCleanManifest(m), (e: Error) => !e.message.includes(title) && /rechazado/.test(e.message));
  }
  assert.ok(scanManifest({ ...ok, postgres: { imageDigest: "latest" } }).length > 0);
});
