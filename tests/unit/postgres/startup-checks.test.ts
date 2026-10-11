// Gobierna: CA-124 (H09), common.spec.yaml GRD-CM-11 (ERR-CM-11), diseño de CA-124 (P2 de CI).
// TEST-CNS-747 (propuesto TEST-CNS-724 en el diseño). Sin Postgres: dobles del catálogo.
// API-CNS-116 (SEC-CNS-018 rev. 2 R2/F-7): TEST-CNS-1087 (roles del roster) y TEST-CNS-1088 (reloj BD vs proceso).

import test from "node:test";
import assert from "node:assert/strict";
import { assertStartupChecks, runStartupChecks, StartupCheckError } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { EXPECTED_MEMBERSHIPS, OWNER_ROLES } from "../../../src/infra/adapters/postgres/role-membership.ts";
import type { DbRoleMode, MembershipEdge } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { applyClusterScope, parseMigration } from "../../../src/infra/adapters/postgres/migrate.ts";
import { FakeClient } from "./fakes.ts";

// ADR-010 PR-2: el modo de roles lo declara el deploy; fuera de LOCAL/DEV es obligatorio. Los dobles de abajo asumen el modo vigente (IT0B).
process.env.CNS_DB_ROLE_MODE ??= "IT0B_SYNTHETIC";

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
  // ADR-010 PR-2 (INV-DBR-03): filas de pg_auth_members de los roles gobernados (por defecto, la lista exacta de IT0B_SYNTHETIC).
  memberships?: MembershipEdge[];
  membershipsError?: boolean;
  ownersPresent?: string[];
  readerSelectOnView?: boolean;
  runtimeSelectOnView?: boolean;
  schemaCreate?: boolean;
  rosterRolesError?: boolean;
  dbClockOffsetMs?: number | "nan";
  // ADR-010 PR-3: privilegios del rol de conexion sobre el esquema platform (por defecto, los declarados para app_rw).
  platformExposure?: Array<{ kind: string; name: string }> | "error";
}

function db(s: Scenario = {}): FakeClient {
  return new FakeClient((text) => {
    if (text.includes("u.rolname AS member")) {
      if (s.membershipsError) return new Error("boom");
      return { rows: (s.memberships ?? EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC).map((e) => ({ member: e.member, role: e.role, inherit_option: e.inherit, set_option: e.set, admin_option: e.admin })) };
    }
    if (text.includes("FROM pg_catalog.pg_auth_members")) {
      if (s.rosterRolesError) return new Error("boom");
      return { rows: s.readerMembership ?? [{ inherit_option: false, set_option: true }] };
    }
    if (text.includes("n.nspname = 'platform'")) {
      if (s.platformExposure === "error") return new Error("boom");
      return { rows: s.platformExposure ?? ((s.runtimeRole ?? "app_rw") === "app_rw" ? [{ kind: "function", name: "request_membership" }] : []) };
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
      return { rows: (s.ownersPresent ?? [...OWNER_ROLES]).map((owner) => ({ owner, member: member.has(owner) })) };
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
    [{ memberOf: ["security_event_owner"] }, /miembro de security_event_owner/], // SEC-CNS-021 PR-1, INV-21-06
    // ADR-010 PR-2 (Q-19, INV-DBR-01): owners nuevos y outbox_claimer
    [{ memberOf: ["outbox_claimer"] }, /miembro de outbox_claimer/],
    [{ memberOf: ["platform_schema_owner"] }, /miembro de platform_schema_owner/],
    [{ memberOf: ["grant_owner"] }, /miembro de grant_owner/],
    [{ memberOf: ["membership_owner"] }, /miembro de membership_owner/],
    [{ memberOf: ["case_state_owner"] }, /miembro de case_state_owner/],
    [{ memberOf: ["transition_owner"] }, /miembro de transition_owner/],
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

const setOf = (edges: readonly MembershipEdge[]): MembershipEdge[] => [...edges];
const edge = (member: string, role: string, inherit: boolean, set: boolean, admin = false): MembershipEdge => ({ member, role, inherit, set, admin });

test("TEST-CNS-1344 ADR-010 PR-2 INV-DBR-03: no arranca si la membresia de los roles gobernados no coincide EXACTAMENTE con el modo (fila extra, faltante, opciones distintas, error de lectura, modo no activado)", async () => {
  const base = setOf(EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC);
  assert.deepEqual(await runStartupChecks(db({ memberships: base }), { expectedEnvironment: "LOCAL" }), { ok: true, failures: [] });
  const cases: Array<[Scenario, RegExp]> = [
    [{ memberships: [...base, edge("app_rw", "transition_owner", false, true)] }, /no esperada.*app_rw -> transition_owner/],
    [{ memberships: [...base, edge("worker", "outbox_claimer", false, true)] }, /no esperada.*worker -> outbox_claimer/],
    [{ memberships: [...base, edge("integrity_verifier", "consent_owner", true, true)] }, /no esperada.*integrity_verifier -> consent_owner/],
    [{ memberships: [...base, edge("platform_rw", "rights_operator", false, true)] }, /no esperada.*platform_rw -> rights_operator/], // llega en PR-5
    [{ memberships: [...base, edge("ddl_breakglass", "grant_owner", false, true)] }, /no esperada.*ddl_breakglass/], // llega en PR-7
    [{ memberships: base.filter((e) => !(e.member === "consent_owner" && e.role === "security_event_owner")) }, /falta la membresía.*consent_owner -> security_event_owner/],
    [{ memberships: base.filter((e) => e.role !== "outbox_claimer") }, /falta la membresía.*consent_migrator -> outbox_claimer/],
    [{ memberships: base.map((e) => (e.role === "tenant_resolve_owner" ? edge(e.member, e.role, true, true) : e)) }, /no esperada.*tenant_resolve_owner \{inherit: true/],
    [{ memberships: base.map((e) => (e.role === "grant_owner" ? edge(e.member, e.role, e.inherit, e.set, true) : e)) }, /no esperada.*consent_owner -> grant_owner \{inherit: false, set: true, admin: true/], // P1-1: ADMIN OPTION
    [{ memberships: [...base, base[0] as MembershipEdge] }, /duplicada.*consent_migrator -> consent_owner/], // P2-4: multiconjunto
    [{ membershipsError: true }, /no se pudo verificar la membresía de los roles/],
    [{ ownersPresent: ["consent_owner"] }, /faltan los roles owner/],
  ];
  for (const [scenario, pattern] of cases) {
    const result = await runStartupChecks(db(scenario), { expectedEnvironment: "LOCAL" });
    assert.equal(result.ok, false, String(pattern));
    assert.ok(result.failures.some((f) => pattern.test(f)), `${pattern} :: ${result.failures.join(" | ")}`);
  }
  // REAL_DATA esta definido pero no activado hasta PR-7: falla cerrado en vez de aceptar o saltarse la aserción.
  const real = await runStartupChecks(db(), { expectedEnvironment: "LOCAL", roleMode: "REAL_DATA" satisfies DbRoleMode });
  assert.equal(real.ok, false);
  assert.ok(real.failures.some((f) => /REAL_DATA no está activado/.test(f)));
});

test("TEST-CNS-1351 ADR-010 PR-2 P1-2/P1-3: runner y startup-checks reciben el MISMO modo declarado (CNS_DB_ROLE_MODE); vacio solo vale en LOCAL/DEV; el runner fija el GUC cns.db_role_mode", async () => {
  const migrations = [parseMigration("0000_roles.sql", "-- scope: cluster\nSELECT 1;\n")];
  const rows = EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC.map((e) => ({ member: e.member, role: e.role, inherit_option: e.inherit, set_option: e.set, admin_option: e.admin }));
  const runner = (): FakeClient => new FakeClient((text) => (text.includes("u.rolname AS member") ? { rows } : undefined));
  const saved = process.env.CNS_DB_ROLE_MODE;
  const outcomes = async (environment: "LOCAL" | "STAGING"): Promise<{ runner: boolean; startup: boolean }> => {
    const r = runner();
    const runnerOk = await applyClusterScope(r, migrations, { environment }).then(() => true, () => false);
    // STAGING exige ademas retencion configurada (otro chequeo): aqui solo importa la parte de modo/membresia (INV-DBR-03).
    const result = await runStartupChecks(db({ catalog: [{ data_class: "SYNTHETIC", environment }] }), { expectedEnvironment: environment });
    const startupOk = !result.failures.some((f) => /INV-DBR-03/.test(f));
    return { runner: runnerOk, startup: startupOk };
  };
  try {
    delete process.env.CNS_DB_ROLE_MODE;
    assert.deepEqual(await outcomes("LOCAL"), { runner: true, startup: true });
    assert.deepEqual(await outcomes("STAGING"), { runner: false, startup: false }, "sin modo declarado fuera de LOCAL/DEV ninguno de los dos arranca");
    process.env.CNS_DB_ROLE_MODE = "IT0B_SYNTHETIC";
    assert.deepEqual(await outcomes("STAGING"), { runner: true, startup: true });
    process.env.CNS_DB_ROLE_MODE = "REAL_DATA";
    assert.deepEqual(await outcomes("LOCAL"), { runner: false, startup: false }, "REAL_DATA no esta activado: ambos fallan cerrado");
    // El GUC lo fija el runner ANTES del SQL de cluster y se limpia despues.
    process.env.CNS_DB_ROLE_MODE = "IT0B_SYNTHETIC";
    const r = runner();
    await applyClusterScope(r, migrations, { environment: "STAGING" });
    const texts = r.queries.map((q) => q.text);
    const iSet = texts.findIndex((t) => t.includes("set_config('cns.db_role_mode', $1"));
    const iSql = texts.indexOf("-- scope: cluster\nSELECT 1;\n");
    const iClear = texts.findIndex((t) => t.includes("set_config('cns.db_role_mode', ''"));
    assert.ok(iSet >= 0 && iSql > iSet && iClear > iSql, texts.join(" | "));
    assert.deepEqual(r.queries[iSet]?.values, ["IT0B_SYNTHETIC"]);
  } finally {
    if (saved === undefined) delete process.env.CNS_DB_ROLE_MODE;
    else process.env.CNS_DB_ROLE_MODE = saved;
  }
});

test("TEST-CNS-1352 ADR-010 PR-3: no arranca si el rol de runtime tiene privilegios sobre una tabla de platform o ejecuta una funcion de platform que no le corresponde; fail-closed si no se puede verificar", async () => {
  // app_rw solo solicita membership (Q4 + Q-17); platform_rw ejecuta las seis funciones declaradas; worker no ejecuta ninguna.
  const ok = [
    { runtimeRole: "app_rw", platformExposure: [{ kind: "function", name: "request_membership" }] },
    { runtimeRole: "platform_rw", platformExposure: ["request_membership", "approve_membership", "request_role_assignment", "approve_role_assignment", "authorize", "issue_action_nonce"].map((name) => ({ kind: "function", name })) },
    { runtimeRole: "worker", platformExposure: [] },
  ] satisfies Scenario[];
  for (const s of ok) {
    const result = await runStartupChecks(db(s), { expectedEnvironment: "LOCAL" });
    assert.ok(!result.failures.some((f) => /esquema platform|tabla platform|ejecutar platform\./.test(f)), `${s.runtimeRole}: ${result.failures.join("; ")}`);
  }
  const cases: Array<[Scenario, RegExp]> = [
    [{ runtimeRole: "app_rw", platformExposure: [{ kind: "table", name: "tenant_membership" }] }, /privilegios sobre la tabla platform\.tenant_membership/],
    [{ runtimeRole: "platform_rw", platformExposure: [{ kind: "table", name: "action_nonce" }] }, /privilegios sobre la tabla platform\.action_nonce/],
    [{ runtimeRole: "app_rw", platformExposure: [{ kind: "function", name: "approve_membership" }] }, /ejecutar platform\.approve_membership\(\)/],
    [{ runtimeRole: "app_rw", platformExposure: [{ kind: "function", name: "authorize_target" }] }, /ejecutar platform\.authorize_target\(\)/],
    [{ runtimeRole: "worker", platformExposure: [{ kind: "function", name: "request_membership" }] }, /ejecutar platform\.request_membership\(\)/],
    [{ runtimeRole: "integrity_verifier", platformExposure: [{ kind: "function", name: "authorize" }] }, /ejecutar platform\.authorize\(\)/],
    [{ runtimeRole: "app_rw", platformExposure: "error" }, /no se pudo verificar la exposición del esquema platform/],
  ];
  for (const [scenario, pattern] of cases) {
    const result = await runStartupChecks(db(scenario), { expectedEnvironment: "LOCAL" });
    assert.equal(result.ok, false);
    assert.ok(result.failures.some((f) => pattern.test(f)), `${JSON.stringify(scenario)} -> ${result.failures.join("; ")}`);
  }
});
