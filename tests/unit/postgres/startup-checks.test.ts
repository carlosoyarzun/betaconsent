// Gobierna: CA-124 (H09), common.spec.yaml GRD-CM-11 (ERR-CM-11), diseño de CA-124 (P2 de CI).
// TEST-CNS-747 (propuesto TEST-CNS-724 en el diseño). Sin Postgres: dobles del catálogo.
// API-CNS-116 (SEC-CNS-018 rev. 2 R2/F-7): TEST-CNS-1087 (roles del roster) y TEST-CNS-1088 (reloj BD vs proceso).

import test from "node:test";
import assert from "node:assert/strict";
import { assertStartupChecks, runStartupChecks, StartupCheckError } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { FakeClient } from "./fakes.ts";

interface Scenario {
  rolsuper?: boolean;
  rolbypassrls?: boolean;
  memberOf?: string[];
  createOn?: string[];
  canSetReplicationRole?: boolean;
  catalog?: Array<{ data_class: string; environment: string }> | "error";
  // API-CNS-116 (R2/F-7)
  runtimeRole?: string;
  readerMembership?: Array<{ inherit_option: boolean; set_option: boolean }>;
  readerExtraGrants?: string[];
  readerSelectOnView?: boolean;
  runtimeSelectOnView?: boolean;
  schemaCreate?: boolean;
  rosterRolesError?: boolean;
  dbClockOffsetMs?: number | "nan";
}

function db(s: Scenario = {}): FakeClient {
  return new FakeClient((text) => {
    if (text.includes("FROM pg_catalog.pg_auth_members")) {
      if (s.rosterRolesError) return new Error("boom");
      return { rows: s.readerMembership ?? [{ inherit_option: false, set_option: true }] };
    }
    if (text.includes("has_table_privilege('staff_roster_reader', c.oid")) return { rows: (s.readerExtraGrants ?? []).map((rel) => ({ rel })) };
    if (text.includes("reader_select")) {
      return { rows: [{ reader_select: s.readerSelectOnView ?? true, runtime_select: s.runtimeSelectOnView ?? false, schema_create: s.schemaCreate ?? false }] };
    }
    if (text.includes("clock_timestamp")) {
      const offset = s.dbClockOffsetMs ?? 0;
      return { rows: [{ db_ms: offset === "nan" ? "x" : String(Date.now() + offset) }] };
    }
    if (text.includes("FROM pg_catalog.pg_roles WHERE rolname = current_user")) {
      return { rows: [{ rolname: s.runtimeRole ?? "app_rw", rolsuper: s.rolsuper ?? false, rolbypassrls: s.rolbypassrls ?? false }] };
    }
    if (text.includes("pg_has_role")) {
      const member = new Set(s.memberOf ?? []);
      return { rows: ["consent_owner", "tenant_resolve_owner", "staff_roster_owner", "integrity_owner"].map((owner) => ({ owner, member: member.has(owner) })) };
    }
    if (text.includes("has_schema_privilege")) return { rows: (s.createOn ?? []).map((nspname) => ({ nspname })) };
    if (text.includes("has_parameter_privilege")) return { rows: [{ can_set: s.canSetReplicationRole ?? false }] };
    if (text.includes("ops.db_catalog")) {
      if (s.catalog === "error") return new Error("relation does not exist");
      return { rows: s.catalog ?? [{ data_class: "SYNTHETIC", environment: "LOCAL" }] };
    }
    return undefined;
  });
}

test("TEST-CNS-747 un rol de runtime sano y un catálogo SYNTHETIC/LOCAL arrancan", async () => {
  const result = await runStartupChecks(db(), { expectedEnvironment: "LOCAL" });
  assert.deepEqual(result, { ok: true, failures: [] });
  await assertStartupChecks(db());
});

test("TEST-CNS-747 no arranca: superusuario, BYPASSRLS, miembro de owner, CREATE en esquema, session_replication_role", async () => {
  const cases: Array<[Scenario, RegExp]> = [
    [{ rolsuper: true }, /superusuario/],
    [{ rolbypassrls: true }, /BYPASSRLS/],
    [{ memberOf: ["consent_owner"] }, /miembro de consent_owner/],
    [{ memberOf: ["tenant_resolve_owner"] }, /miembro de tenant_resolve_owner/],
    [{ memberOf: ["staff_roster_owner"] }, /miembro de staff_roster_owner/],
    [{ memberOf: ["integrity_owner"] }, /miembro de integrity_owner/],
    [{ createOn: ["public"] }, /CREATE en el esquema public/],
    [{ canSetReplicationRole: true }, /session_replication_role/],
  ];
  for (const [scenario, expected] of cases) {
    const result = await runStartupChecks(db(scenario));
    assert.equal(result.ok, false);
    assert.ok(result.failures.some((f) => expected.test(f)), `${JSON.stringify(scenario)} -> ${result.failures.join("|")}`);
  }
});

test("TEST-CNS-747 no arranca: catálogo no SYNTHETIC, environment no permitido, sin fila, ilegible o distinto del configurado", async () => {
  const cases: Array<[Scenario, string | undefined, RegExp]> = [
    [{ catalog: [{ data_class: "REAL", environment: "LOCAL" }] }, undefined, /no es SYNTHETIC/],
    [{ catalog: [{ data_class: "SYNTHETIC", environment: "PRODUCTION" }] }, undefined, /no es LOCAL, DEV ni STAGING/],
    [{ catalog: [] }, undefined, /exactamente una fila/],
    [{ catalog: "error" }, undefined, /no se pudo leer ops\.db_catalog/],
    [{}, "DEV", /difiere del catálogo/],
  ];
  for (const [scenario, expectedEnvironment, expected] of cases) {
    const options = expectedEnvironment === "DEV" ? { expectedEnvironment: "DEV" as const } : {};
    const result = await runStartupChecks(db(scenario), options);
    assert.equal(result.ok, false);
    assert.ok(result.failures.some((f) => expected.test(f)), result.failures.join("|"));
  }
});

test("TEST-CNS-747 assertStartupChecks lanza StartupCheckError con ERR-CM-11", async () => {
  await assert.rejects(
    () => assertStartupChecks(db({ rolsuper: true })),
    (error: unknown) => error instanceof StartupCheckError && /ERR-CM-11/.test(error.message),
  );
});

test("TEST-CNS-1087 R2: no arranca si app_rw es miembro de staff_roster_owner, si la membresía del lector no es INHERIT FALSE/SET TRUE o si el lector tiene más que SELECT sobre la vista", async () => {
  const cases: Array<[Scenario, RegExp]> = [
    [{ memberOf: ["staff_roster_owner"] }, /miembro de staff_roster_owner/],
    [{ readerMembership: [] }, /INHERIT FALSE, SET TRUE/],
    [{ readerMembership: [{ inherit_option: true, set_option: true }] }, /INHERIT FALSE, SET TRUE/],
    [{ readerMembership: [{ inherit_option: false, set_option: false }] }, /INHERIT FALSE, SET TRUE/],
    [{ runtimeRole: "worker", readerMembership: [{ inherit_option: false, set_option: true }] }, /solo app_rw puede ser miembro/],
    [{ readerExtraGrants: ["app.invitation"] }, /privilegios indebidos sobre app\.invitation/],
    [{ readerSelectOnView: false }, /no tiene SELECT sobre la vista/],
    [{ runtimeSelectOnView: true }, /sin SET ROLE/],
    [{ schemaCreate: true }, /CREATE en algún esquema/],
    [{ rosterRolesError: true }, /no se pudieron verificar los roles del roster/],
  ];
  for (const [scenario, expected] of cases) {
    const result = await runStartupChecks(db(scenario));
    assert.equal(result.ok, false, JSON.stringify(scenario));
    assert.ok(result.failures.some((f) => expected.test(f)), `${JSON.stringify(scenario)} -> ${result.failures.join("|")}`);
  }
  // El caso sano pasa y worker/platform_rw sin membresía pasan.
  assert.equal((await runStartupChecks(db())).ok, true);
  assert.equal((await runStartupChecks(db({ runtimeRole: "worker", readerMembership: [] }))).ok, true);
});

test("TEST-CNS-1088 F-7: no arranca si |reloj BD - Date.now()| > 2 s o si el reloj de la BD no se lee; tolera hasta 2 s", async () => {
  for (const offset of [2500, -2500, 60_000]) {
    const result = await runStartupChecks(db({ dbClockOffsetMs: offset }));
    assert.equal(result.ok, false, `offset ${offset}`);
    assert.ok(result.failures.some((f) => /reloj de la base/.test(f)), result.failures.join("|"));
  }
  const unreadable = await runStartupChecks(db({ dbClockOffsetMs: "nan" }));
  assert.ok(unreadable.failures.some((f) => /reloj de la base/.test(f)));
  assert.equal((await runStartupChecks(db({ dbClockOffsetMs: 1500 }))).ok, true);
  assert.equal((await runStartupChecks(db({ dbClockOffsetMs: -1500 }))).ok, true);
  // El reloj del proceso es inyectable: un proceso adelantado 5 s respecto de la BD falla.
  const skewed = await runStartupChecks(db(), { nowMs: () => Date.now() + 5000 });
  assert.equal(skewed.ok, false);
});
