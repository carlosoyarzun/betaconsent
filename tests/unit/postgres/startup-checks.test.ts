// Gobierna: CA-124 (H09), common.spec.yaml GRD-CM-11 (ERR-CM-11), diseño de CA-124 (P2 de CI).
// TEST-CNS-747 (propuesto TEST-CNS-724 en el diseño). Sin Postgres: dobles del catálogo.

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
}

function db(s: Scenario = {}): FakeClient {
  return new FakeClient((text) => {
    if (text.includes("FROM pg_catalog.pg_roles WHERE rolname = current_user")) {
      return { rows: [{ rolname: "app_rw", rolsuper: s.rolsuper ?? false, rolbypassrls: s.rolbypassrls ?? false }] };
    }
    if (text.includes("pg_has_role")) {
      const member = new Set(s.memberOf ?? []);
      return { rows: ["consent_owner", "tenant_resolve_owner"].map((owner) => ({ owner, member: member.has(owner) })) };
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
