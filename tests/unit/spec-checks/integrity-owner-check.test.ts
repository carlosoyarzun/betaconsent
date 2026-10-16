// Gobierna: JIRA CA-142 (C3 de PR #60; migraciones 0026/0027; residual P1 aceptado para IT0 sintetico, cierre CA-144).
// Prueba tools/spec-checks/integrity-owner-checker.ts: PASS sobre el repo real y casos positivos sinteticos (fixtures).
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ADR010_OWNER_ROLES,
  checkAdr010OwnerUsage,
  checkIntegrityOwnerUsage,
  findAdr010OwnerUsages,
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
  const base = [{ path: real, text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0030_ledger_drop_transitional_security_events.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0037_adr010_case_state_revocation.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0038_adr010_case_state_rights_case.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0039_adr010_ledger_allowlist_close_case_d6.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0041_adr010_ledger_allowlist_19_dedupe_estricto.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0042_adr010_worker_downstream_only.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0047_adr010_ledger_gen_enrollment_dmv.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0048_adr010_ledger_gen_invitation.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0049_adr010_ledger_gen_decision_seed_close_insert.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0057_adr010_pr6e_reconciler_ledger_select.sql", text: "SET LOCAL ROLE integrity_owner;" }, { path: "db/migrations/0026_integrity_owner_role.sql", text: "GRANT integrity_owner TO consent_owner;" }, { path: "tests/integration/postgres/ledger-chain.test.ts", text: "SET ROLE integrity_owner" }];
  assert.deepEqual(checkIntegrityOwnerUsage(base), []);
  assert.equal(checkIntegrityOwnerUsage([...base, { path: "db/migrations/0031_otra.sql", text: "SET LOCAL ROLE integrity_owner;" }]).filter((e) => e.includes("0031")).length, 1);
  // SEC-CNS-021 PR-2: SOLO 0030 se agrega a la allowlist; ADR-010 PR-5a agrega 0037 (GRANT/policies de transition_owner); cualquier otra migracion nueva (incluida una 0028-like) falla
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

// ADR-010 PR-2 (INV-DBR-03): el mismo control para los owners nuevos de cluster (solo 0034 concede su membresia; nadie hace SET ROLE).
test("TEST-CNS-1347 adr010-owner-check: ningun uso de SET ROLE de un owner nuevo ni GRANT de su membresia fuera de 0034/0035 (repo real); detecta variantes y no da falsos positivos", () => {
  const files: { path: string; text: string }[] = [];
  collect(ROOT, files);
  assert.ok(files.some((f) => f.path === "db/migrations/0034_adr010_cluster_roles.sql"), "el escaneo debe alcanzar 0034");
  assert.deepEqual(checkAdr010OwnerUsage(files), []);

  for (const role of ADR010_OWNER_ROLES) {
    const variants = [`SET LOCAL ROLE ${role};`, `set role ${role};`, `SET SESSION ROLE "${role}";`, "await c.query(`SET ROLE " + role + "`);", `SELECT set_config('role', '${role}', true);`];
    for (const v of variants) {
      const path = v.includes("await") ? "src/infra/x.ts" : "db/migrations/0099_x.sql";
      assert.ok(checkAdr010OwnerUsage([{ path, text: v }]).some((e) => e.includes(path) && e.includes("set-role") && e.includes(role)), `no detecto: ${v}`);
    }
    assert.ok(findAdr010OwnerUsages(role, "db/migrations/0099_x.sql", `GRANT ${role} TO app_rw;`).some((u) => u.kind === "grant-membership"));
    for (const ok of [`GRANT USAGE ON SCHEMA platform TO ${role};`, `-- SET ROLE ${role};`, `SET LOCAL ROLE ${role}_x;`, `REVOKE ${role} FROM app_rw;`]) {
      assert.deepEqual(findAdr010OwnerUsages(role, "db/migrations/0099_x.sql", ok), [], `falso positivo: ${ok}`);
    }
  }
  // 0034 pasa con su GRANT y 0035 (ADR-010 PR-3) con el SET LOCAL ROLE de sus tres owners; una entrada obsoleta se marca; otra migracion con SET ROLE falla.
  const real = ADR010_OWNER_ROLES.filter((r) => r !== "ledger_gen_owner" && r !== "ledger_writer" && r !== "rights_case_lookup_owner").map((r) => `GRANT ${r} TO consent_owner WITH INHERIT FALSE, SET TRUE;`).join("\n");
  // ADR-010 rev. 5 PR-b: 0046 (cluster) concede ledger_gen_owner y ledger_writer; 0047/0048/0049 los asumen con SET LOCAL ROLE (esquema ledger_gen y funciones de ledger_writer).
  const m0046 = "db/migrations/0046_adr010_ledger_roles.sql";
  const real46 = ["ledger_gen_owner", "ledger_writer"].map((r) => `GRANT ${r} TO consent_owner WITH INHERIT FALSE, SET TRUE;`).join("\n");
  const m0047 = "db/migrations/0047_adr010_ledger_gen_enrollment_dmv.sql";
  const setLedger = ["ledger_gen_owner", "ledger_writer"].map((r) => `SET LOCAL ROLE ${r};`).join("\n");
  const pb = [{ path: m0046, text: real46 }, { path: m0047, text: setLedger }, { path: "db/migrations/0048_adr010_ledger_gen_invitation.sql", text: setLedger }, { path: "db/migrations/0049_adr010_ledger_gen_decision_seed_close_insert.sql", text: `${setLedger}\nSET LOCAL ROLE transition_owner;` }];
  const pbObsolete = pb.map((f) => ({ path: f.path, text: "SELECT 1;" }));
  const m0034 = "db/migrations/0034_adr010_cluster_roles.sql";
  const m0035 = "db/migrations/0035_adr010_platform_schema.sql";
  const set35 = ["platform_schema_owner", "membership_owner", "grant_owner"].map((r) => `SET LOCAL ROLE ${r};`).join("\n");
  // 0036 (PR-4) asume los mismos tres owners y platform_schema_owner; el fixture LOCAL del bootstrap PLATFORM (patron TEST-CNS-879) asume membership_owner.
  const m0036 = "db/migrations/0036_adr010_verifier_assertions.sql";
  const fixPlatform = "db/fixtures/local/0002_platform_bootstrap.sql";
  // 0037 (PR-5a): case_state_owner y transition_owner (esquema case_state y funciones de transicion).
  const m0037 = "db/migrations/0037_adr010_case_state_revocation.sql";
  const m0038 = "db/migrations/0038_adr010_case_state_rights_case.sql"; // PR-5b: mismos dos owners que 0037
  const m0039 = "db/migrations/0039_adr010_ledger_allowlist_close_case_d6.sql"; // PR-5b D5/D6: mismos dos owners
  const m0040 = "db/migrations/0040_adr010_record_assertion_fresh_auth.sql"; // PR-6-0: platform_schema_owner (CREATE temporal) y grant_owner (record_assertion v2)
  const m0042 = "db/migrations/0042_adr010_worker_downstream_only.sql"; // PR-6a: transition_owner (REVOKE EXECUTE de R5-R7 a app_rw)
  const set40 = ["platform_schema_owner", "grant_owner"].map((r) => `SET LOCAL ROLE ${r};`).join("\n");
  const m0044 = "db/migrations/0044_invitation_cancel_subject_mismatch_fn.sql"; // I9 por funcion case_state: mismos dos owners que 0037
  const m0041 = "db/migrations/0041_adr010_ledger_allowlist_19_dedupe_estricto.sql"; // F-A10-30: mismos dos owners que 0037
  const tpra = "tests/integration/postgres/adr010-ledger-pr-a.test.ts"; // PR-a: transition_owner
  const tprb = "tests/integration/postgres/adr010-ledger-pr-b-invitation.test.ts"; // PR-b: transition_owner
  const tprb2 = "tests/integration/postgres/adr010-ledger-pr-b-decision.test.ts"; // PR-b: transition_owner
  const tprb3 = "tests/integration/postgres/adr010-ledger-pr-b-hardening.test.ts"; // PR-b: transition_owner y ledger_writer
  const t5b = "tests/integration/postgres/adr010-pr5b-rights-case.test.ts";
  const set37 = ["case_state_owner", "transition_owner"].map((r) => `SET LOCAL ROLE ${r};`).join("\n");
  // PR-6b (0050/0051): mismos owners que 0036 (0050 con los tres; 0051 sin membership_owner).
  const m0050 = "db/migrations/0050_adr010_pr6b_oidc_login_schema.sql";
  const m0051 = "db/migrations/0051_adr010_pr6b_oidc_login_functions.sql";
  // PR-6c (0052-0054): mismos owners que 0051 (platform_schema_owner y grant_owner).
  const m6c = ["db/migrations/0052_adr010_pr6c_session_schema.sql", "db/migrations/0053_adr010_pr6c_session_functions.sql", "db/migrations/0054_adr010_pr6c_begin_login_case_session.sql",
    // PR-6d parte 1 (0059-0063): mismos owners (platform_schema_owner y grant_owner).
    "db/migrations/0059_adr010_pr6d1_grants_schema.sql", "db/migrations/0060_adr010_pr6d1_step_up_session_principal.sql", "db/migrations/0061_adr010_pr6d1_step_up_nonce_functions.sql", "db/migrations/0062_adr010_pr6d1_request_approve_grant.sql", "db/migrations/0063_adr010_pr6d1_validate_case_tenant.sql"];
  const t5a = "tests/integration/postgres/adr010-pr5a-case-state.test.ts";
  const base = [{ path: m0034, text: real }, { path: m0035, text: set35 }, { path: m0036, text: set35 }, { path: m0037, text: set37 }, { path: m0038, text: set37 }, { path: m0039, text: set37 }, { path: m0041, text: set37 }, { path: m0044, text: set37 }, { path: tpra, text: "SET LOCAL ROLE transition_owner;" }, { path: m0040, text: set40 }, { path: m0050, text: set35 }, { path: m0051, text: set40 }, ...m6c.map((path) => ({ path, text: path.includes("0059_") ? `${set40}\nSET LOCAL ROLE rights_case_lookup_owner;` : set40 })), { path: "db/migrations/0064_adr010_pr6d1_rights_case_lookup_role.sql", text: "GRANT rights_case_lookup_owner TO consent_owner WITH INHERIT FALSE, SET TRUE;" }, { path: m0042, text: "SET LOCAL ROLE transition_owner;" }, { path: t5a, text: "SET LOCAL ROLE transition_owner;" }, { path: t5b, text: "SET LOCAL ROLE transition_owner;\nSET LOCAL ROLE ledger_writer;" }, { path: tprb, text: "SET LOCAL ROLE transition_owner;" }, { path: tprb2, text: "SET LOCAL ROLE transition_owner;" }, { path: tprb3, text: "SET LOCAL ROLE transition_owner;\nSET LOCAL ROLE ledger_writer;" }, { path: fixPlatform, text: "SET LOCAL ROLE membership_owner;" }, ...pb];
  assert.deepEqual(checkAdr010OwnerUsage(base), []);
  assert.ok(checkAdr010OwnerUsage([{ path: m0034, text: "SELECT 1;" }, { path: m0035, text: "SELECT 1;" }, { path: m0036, text: "SELECT 1;" }, { path: m0037, text: "SELECT 1;" }, { path: m0038, text: "SELECT 1;" }, { path: m0039, text: "SELECT 1;" }, { path: m0041, text: "SELECT 1;" }, { path: tpra, text: "SELECT 1;" }, { path: m0040, text: "SELECT 1;" }, { path: m0050, text: "SELECT 1;" }, { path: m0051, text: "SELECT 1;" }, ...m6c.map((path) => ({ path, text: "SELECT 1;" })), { path: m0042, text: "SELECT 1;" }, { path: t5a, text: "SELECT 1;" }, { path: t5b, text: "SELECT 1;" }, { path: tprb, text: "SELECT 1;" }, { path: tprb2, text: "SELECT 1;" }, { path: tprb3, text: "SELECT 1;" }, { path: fixPlatform, text: "SELECT 1;" }, ...pbObsolete]).every((e) => e.includes("obsoleta")));
  assert.equal(checkAdr010OwnerUsage([...base, { path: "db/migrations/0038_otra.sql", text: "SET LOCAL ROLE transition_owner;" }]).length, 1);
  // 0035 solo puede asumir sus tres owners: case_state_owner y transition_owner son de 0037 (PR-5a).
  const over = checkAdr010OwnerUsage([{ path: m0034, text: real }, { path: m0035, text: `${set35}\nSET LOCAL ROLE transition_owner;` }, { path: m0036, text: set35 }, { path: m0037, text: set37 }, { path: m0038, text: set37 }, { path: m0039, text: set37 }, { path: m0041, text: set37 }, { path: tpra, text: "SET LOCAL ROLE transition_owner;" }, { path: m0040, text: set40 }, { path: m0042, text: "SET LOCAL ROLE transition_owner;" }, { path: t5a, text: "SET LOCAL ROLE transition_owner;" }, { path: t5b, text: "SET LOCAL ROLE transition_owner;\nSET LOCAL ROLE ledger_writer;" }, { path: tprb, text: "SET LOCAL ROLE transition_owner;" }, { path: tprb2, text: "SET LOCAL ROLE transition_owner;" }, { path: tprb3, text: "SET LOCAL ROLE transition_owner;\nSET LOCAL ROLE ledger_writer;" }, { path: fixPlatform, text: "SET LOCAL ROLE membership_owner;" }, ...pb]);
  assert.equal(over.filter((e) => e.includes("fuera de la allowlist") && e.includes("transition_owner")).length, 1);
});
