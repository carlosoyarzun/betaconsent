// Gobierna: CA-124 (H09), ADR-006 §1/§4-§6, diseño de CA-124 P1-1 (escaneo de src/**).
// TEST-CNS-741 (propuesto TEST-CNS-711 en el diseño). Sin Postgres.
//
// El contexto de tenant solo se fija con `set_config('app.tenant_id', $1, true)` (local a la
// transacción) en src/infra/adapters/postgres/unit-of-work.ts. Prohíbe, en src/** y
// db/migrations/**: set_config('app.tenant_id', ..., false) o desde cualquier otro archivo,
// `SET [SESSION|LOCAL] app.tenant_id` y `ALTER ROLE|DATABASE|SYSTEM ... SET app.tenant_id`.

import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const ALLOWED_FILE = "src/infra/adapters/postgres/unit-of-work.ts";
const ALLOWED_SET_CONFIG = /set_config\(\s*'app\.tenant_id'\s*,\s*\$1\s*,\s*true\s*\)/g;

/**
 * ADR-010 rev. 5 PR-6d parte 2 (0069, requiere revision de Carlos: CODEOWNERS tests/unit): platform.require_case_actor / require_platform_actor / alert_case_apply_exhausted fijan app.tenant_id LOCAL a la tx
 * con el tenant que sale de la sesion CASE/PLATFORM validada EN LA BASE (o del caso real), nunca de la request. Solo ese archivo y solo esa forma exacta (v_tenant, local); el resto sigue prohibido.
 */
const ALLOWED_SQL_TENANT_FROM_SESSION: Readonly<Record<string, RegExp>> = {
  "db/migrations/0069_adr010_pr6d2_actor_from_session_rh2_cross.sql": /set_config\(\s*'app\.tenant_id'\s*,\s*v_tenant::pg_catalog\.text\s*,\s*true\s*\)/g,
};

const FORBIDDEN: Array<{ name: string; re: RegExp }> = [
  { name: "set_config('app.tenant_id', …) fuera de unit-of-work.ts", re: /set_config\s*\(\s*['"`]app\.tenant_id['"`]/gi },
  { name: "SET [SESSION|LOCAL] app.tenant_id", re: /\bSET\s+(SESSION\s+|LOCAL\s+)?app\.tenant_id\b/gi },
  { name: "ALTER ROLE|DATABASE|SYSTEM … SET app.tenant_id", re: /\bALTER\s+(ROLE|DATABASE|SYSTEM)\b[^;]*\bapp\.tenant_id\b/gi },
];

/** Quita comentarios (// y /* *\/ en .ts; -- en .sql): la documentación puede citar los patrones. */
function stripComments(relPath: string, text: string): string {
  if (relPath.endsWith(".sql")) return text.replace(/--[^\n]*/g, "");
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

export function scanText(relPath: string, rawText: string): string[] {
  let text = stripComments(relPath, rawText);
  const allowedSql = ALLOWED_SQL_TENANT_FROM_SESSION[relPath];
  if (allowedSql !== undefined) text = text.replace(allowedSql, "");
  const findings: string[] = [];
  if (relPath === ALLOWED_FILE) {
    const total = (text.match(/set_config\s*\(\s*['"`]app\.tenant_id['"`]/gi) ?? []).length;
    const local = (text.match(ALLOWED_SET_CONFIG) ?? []).length;
    if (total !== local) findings.push(`${relPath}: set_config('app.tenant_id') debe ser exactamente (…, $1, true)`);
    for (const f of FORBIDDEN.slice(1)) if (f.re.test(text)) findings.push(`${relPath}: ${f.name}`);
    for (const f of FORBIDDEN.slice(1)) f.re.lastIndex = 0;
    return findings;
  }
  for (const f of FORBIDDEN) {
    f.re.lastIndex = 0;
    if (f.re.test(text)) findings.push(`${relPath}: ${f.name}`);
    f.re.lastIndex = 0;
  }
  return findings;
}

function walk(dir: string, exts: string[]): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...walk(full, exts));
    else if (exts.some((e) => name.endsWith(e))) out.push(full);
  }
  return out;
}

test("TEST-CNS-741 src/** y db/migrations/** no fijan app.tenant_id a nivel de sesión", () => {
  const files = [...walk(join(ROOT, "src"), [".ts"]), ...walk(join(ROOT, "db", "migrations"), [".sql"])];
  assert.ok(files.length > 0);
  const findings = files.flatMap((f) => scanText(relative(ROOT, f).split(sep).join("/"), readFileSync(f, "utf-8")));
  assert.deepEqual(findings, []);
});

test("TEST-CNS-741 unit-of-work.ts es el único punto que llama a set_config('app.tenant_id') y lo hace local", () => {
  const text = stripComments(ALLOWED_FILE, readFileSync(join(ROOT, ALLOWED_FILE), "utf-8"));
  assert.equal((text.match(ALLOWED_SET_CONFIG) ?? []).length, 1);
  const others = walk(join(ROOT, "src"), [".ts"])
    .map((f) => relative(ROOT, f).split(sep).join("/"))
    .filter((p) => p !== ALLOWED_FILE)
    .filter((p) => /set_config\s*\(\s*['"`]app\.tenant_id/i.test(stripComments(p, readFileSync(join(ROOT, p), "utf-8"))));
  assert.deepEqual(others, []);
});

test("TEST-CNS-741 el escáner detecta las variantes prohibidas (control positivo)", () => {
  const bad = [
    "SELECT set_config('app.tenant_id', $1, false)",
    "SELECT set_config('app.tenant_id', $1, is_local)",
    'await c.query("SET app.tenant_id = \'x\'")',
    "SET SESSION app.tenant_id = 'x'",
    "SET LOCAL app.tenant_id = 'x'",
    "ALTER ROLE app_rw SET app.tenant_id = 'x'",
    "ALTER DATABASE d SET app.tenant_id TO 'x'",
  ];
  for (const sample of bad) {
    assert.notDeepEqual(scanText("src/infra/adapters/postgres/otro.ts", sample), [], `no detectó: ${sample}`);
  }
  assert.notDeepEqual(scanText(ALLOWED_FILE, "SELECT set_config('app.tenant_id', $1, false)"), []);
  assert.deepEqual(scanText(ALLOWED_FILE, "SELECT set_config('app.tenant_id', $1, true)"), []);
  assert.deepEqual(scanText("src/x.ts", "SELECT current_setting('app.tenant_id', true)"), []);
});
