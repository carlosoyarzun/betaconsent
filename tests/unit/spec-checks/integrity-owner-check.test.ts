// Gobierna: JIRA CA-142 (C3 de PR #60; migraciones 0026/0027; residual P1 aceptado para IT0 sintetico, cierre CA-144).
// Prueba tools/spec-checks/integrity-owner-checker.ts: PASS sobre el repo real y casos positivos sinteticos (fixtures).
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkIntegrityOwnerUsage,
  checkSecurityEventOwnerUsage,
  findSecurityEventOwnerUsages,
  findUsages,
  INTEGRITY_OWNER_ALLOWLIST,
  SCANNED_EXT_RE,
  SECURITY_EVENT_OWNER_ALLOWLIST,
} from "../../../tools/spec-checks/integrity-owner-checker.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SKIP_DIRS = new Set(["node_modules", ".git", ".claude", "docs", "design-system", "evidence", "dist", "build", "coverage"]);

function collect(dir: string, out: { path: string; text: string }[]): void {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) collect(full, out);
    else if (SCANNED_EXT_RE.test(name)) out.push({ path: relative(ROOT, full).split(sep).join("/"), text: readFileSync(full, "utf-8") });
  }
}

test("TEST-CNS-1234 integrity-owner-check: solo la allowlist usa SET ROLE integrity_owner o concede su membresia (repo real)", () => {
  const files: { path: string; text: string }[] = [];
  collect(ROOT, files);
  assert.ok(files.some((f) => f.path === "db/migrations/0027_ledger_integrity_owner.sql"), "el escaneo debe alcanzar db/migrations");
  assert.deepEqual(checkIntegrityOwnerUsage(files), []);
});

test("TEST-CNS-1235 integrity-owner-check: detecta SET [LOCAL|SESSION] ROLE integrity_owner y set_config fuera de la allowlist", () => {
  const variants = [
    "SET LOCAL ROLE integrity_owner;",
    "set role integrity_owner;",
    "SET   SESSION\n  ROLE \"integrity_owner\";",
    "await c.query(`SET ROLE integrity_owner`);",
    "SELECT set_config('role', 'integrity_owner', true);",
  ];
  for (const v of variants) {
    const path = v.includes("await") ? "src/infra/x.ts" : "db/migrations/0099_x.sql";
    const errs = checkIntegrityOwnerUsage([{ path, text: v }]);
    assert.ok(errs.some((e) => e.includes(path) && e.includes("set-role")), `no detecto: ${v}`);
  }
  // el mismo SET ROLE en un archivo de la allowlist pasa; en otro archivo (p.ej. una migracion nueva) falla
  const real = "db/migrations/0027_ledger_integrity_owner.sql";
  const base = [{ path: real, text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0026_integrity_owner_role.sql", text: "GRANT integrity_owner TO consent_owner;" }, { path: "tests/integration/postgres/ledger-chain.test.ts", text: "SET ROLE integrity_owner" }];
  assert.deepEqual(checkIntegrityOwnerUsage(base), []);
  assert.equal(checkIntegrityOwnerUsage([...base, { path: "db/migrations/0028_otra.sql", text: "SET LOCAL ROLE integrity_owner;" }]).filter((e) => e.includes("0028")).length, 1);
});

test("TEST-CNS-1236 integrity-owner-check: detecta GRANT de integrity_owner a otros roles, pero no GRANT hacia integrity_owner ni comentarios", () => {
  const bad = [
    "GRANT integrity_owner TO app_rw;",
    "GRANT integrity_owner TO app_rw WITH INHERIT TRUE, SET TRUE;",
    "grant consent_reader, \"integrity_owner\" to worker;",
  ];
  for (const v of bad) {
    assert.ok(findUsages("db/migrations/0099_x.sql", v).some((u) => u.kind === "grant-membership"), `no detecto: ${v}`);
    assert.equal(checkIntegrityOwnerUsage([{ path: "db/migrations/0099_x.sql", text: v }]).filter((e) => !e.includes("obsoleta")).length, 1);
  }
  const ok = [
    "GRANT USAGE, CREATE ON SCHEMA integrity TO integrity_owner;",
    "ALTER TABLE integrity.audit_event OWNER TO integrity_owner;",
    "-- SET ROLE integrity_owner; GRANT integrity_owner TO app_rw;",
    "/* SET LOCAL ROLE integrity_owner; */",
    "SET LOCAL ROLE integrity_owner_x;",
  ];
  for (const v of ok) assert.deepEqual(findUsages("db/migrations/0099_x.sql", v), [], `falso positivo: ${v}`);
  assert.deepEqual(findUsages("src/a.ts", "// SET ROLE integrity_owner\nconst a = 1;"), []);
});

test("TEST-CNS-1237 integrity-owner-check: marca allowlist obsoleta (archivo ausente o sin el uso declarado)", () => {
  assert.ok(checkIntegrityOwnerUsage([]).some((e) => e.includes("no existe")));
  const stale = Object.entries(INTEGRITY_OWNER_ALLOWLIST).map(([path]) => ({ path, text: "SELECT 1;" }));
  const errs = checkIntegrityOwnerUsage(stale);
  assert.equal(errs.length, Object.keys(INTEGRITY_OWNER_ALLOWLIST).length);
  assert.ok(errs.every((e) => e.includes("obsoleta")));
});

// SEC-CNS-021 PR-1 (CA-146, INV-21-06): el mismo control para security_event_owner (migraciones 0028/0029).
test("TEST-CNS-1325 security-event-owner-check: solo la allowlist usa SET ROLE security_event_owner o concede su membresia (repo real); detecta usos fuera de ella y no confunde integrity_owner", () => {
  const files: { path: string; text: string }[] = [];
  collect(ROOT, files);
  assert.ok(files.some((f) => f.path === "db/migrations/0029_security_event_otp_family.sql"), "el escaneo debe alcanzar db/migrations");
  assert.deepEqual(checkSecurityEventOwnerUsage(files), []);

  const variants = [
    "SET LOCAL ROLE security_event_owner;",
    "set role security_event_owner;",
    "SET   SESSION\n  ROLE \"security_event_owner\";",
    "await c.query(`SET ROLE security_event_owner`);",
    "SELECT set_config('role', 'security_event_owner', true);",
  ];
  for (const v of variants) {
    const path = v.includes("await") ? "src/infra/x.ts" : "db/migrations/0099_x.sql";
    const errs = checkSecurityEventOwnerUsage([{ path, text: v }]);
    assert.ok(errs.some((e) => e.includes(path) && e.includes("set-role")), `no detecto: ${v}`);
  }
  assert.ok(findSecurityEventOwnerUsages("db/migrations/0099_x.sql", "GRANT security_event_owner TO app_rw;").some((u) => u.kind === "grant-membership"));
  // Falsos positivos: GRANT hacia el rol, comentarios, otro rol con prefijo igual, y el rol del ledger.
  for (const ok of ["GRANT USAGE, CREATE ON SCHEMA ops TO security_event_owner;", "-- SET ROLE security_event_owner;", "SET LOCAL ROLE security_event_owner_x;", "SET LOCAL ROLE integrity_owner;"]) {
    assert.deepEqual(findSecurityEventOwnerUsages("db/migrations/0099_x.sql", ok), [], `falso positivo: ${ok}`);
  }
  // Una migracion nueva con el SET ROLE falla; la allowlist real pasa y una entrada obsoleta se marca.
  const real = Object.entries(SECURITY_EVENT_OWNER_ALLOWLIST).map(([path, kinds]) => ({ path, text: kinds.map((k) => (k === "set-role" ? "SET LOCAL ROLE security_event_owner;" : "GRANT security_event_owner TO consent_owner;")).join("\n") }));
  assert.deepEqual(checkSecurityEventOwnerUsage(real), []);
  assert.equal(checkSecurityEventOwnerUsage([...real, { path: "db/migrations/0099_otra.sql", text: "SET LOCAL ROLE security_event_owner;" }]).filter((e) => e.includes("0099")).length, 1);
  assert.ok(checkSecurityEventOwnerUsage(real.map((f) => ({ ...f, text: "SELECT 1;" }))).every((e) => e.includes("obsoleta")));
  // El checker de integrity_owner no se altera por security_event_owner.
  assert.deepEqual(findUsages("db/migrations/0099_x.sql", "SET LOCAL ROLE security_event_owner;"), []);
});
