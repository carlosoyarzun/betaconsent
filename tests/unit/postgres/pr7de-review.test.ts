// Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7d/7e), correcciones de la revision de seguridad del PR #109 (F-PR7D-01..07; P1-1, P1-2, P1-3 y P2). Sin Postgres. SYNTHETIC ONLY.
// TEST-CNS-1865 (runner: precondiciones antes de la fase cluster, diferimiento solo con migraciones pendientes, REAL_DATA sin diferir, aserción despues del COMMIT, transaccion de solo-REVOKE ante un fallo de la fase posterior,
// lock con tope de espera), 1866 (SQL: sin concesion transitoria a consent_owner, breakglass en cluster-post con SET LOCAL ROLE, ceremonias con \getenv y cierre con sesiones terminadas despues del COMMIT),
// 1867 (checkBreakglassState y checkDbRoleSettings: hechos exactos y desvios sobre dobles).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { BREAKGLASS_EXPECTED_FACTS, checkBreakglassState, checkDatabaseLevel, checkDbRoleSettings } from "../../../src/infra/adapters/postgres/database-level.ts";
import { applyClusterPostScope, applyClusterScope, parseMigration, withClusterRoleLock } from "../../../src/infra/adapters/postgres/migrate.ts";
import { EXPECTED_MEMBERSHIPS } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { databaseLevelRows, FakeClient } from "./fakes.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");
const noComments = (s: string): string => s.replace(/--[^\n]*/g, "");
const MEMBERS = EXPECTED_MEMBERSHIPS.IT0B_SYNTHETIC.map((e) => ({ member: e.member, role: e.role, inherit_option: e.inherit, set_option: e.set, admin_option: e.admin }));

interface Scenario {
  applied?: string[];
  canLogin?: boolean;
  failOn?: string;
  failsafeFails?: boolean;
}

/** Superusuario simulado: base al dia (0001 aplicada) salvo que `applied` diga otra cosa. `failOn`: texto de SQL que falla. */
function superuser(s: Scenario = {}): FakeClient {
  return new FakeClient((text) => {
    if (s.failOn !== undefined && text.includes(s.failOn)) return new Error("fallo inyectado");
    if (s.failsafeFails === true && text.startsWith("SELECT pg_catalog.format('REVOKE %I FROM %I'")) return new Error("fallo del solo-REVOKE");
    if (text.includes("AS can_login")) return { rows: [{ can_login: s.canLogin ?? false, ceremony_table: false }] };
    if (text.includes("to_regclass('ops.schema_migration')")) return { rows: [{ present: s.applied !== undefined }] };
    if (text.includes("FROM ops.schema_migration")) return { rows: (s.applied ?? []).map((version) => ({ version })) };
    if (text.includes("u.rolname AS member")) return { rows: MEMBERS };
    return databaseLevelRows(text);
  });
}

const MIGS = [
  parseMigration("0000_roles.sql", "-- scope: cluster\nSELECT 'cluster-sql';\n"),
  parseMigration("0001_db.sql", "-- scope: database\nSELECT 'db-sql';\n"),
  parseMigration("0002_post.sql", "-- scope: cluster-post\nSELECT 'post-sql';\n"),
];
const texts = (c: FakeClient): string[] => c.queries.map((q) => q.text);
const idx = (c: FakeClient, needle: string): number => texts(c).findIndex((t) => t.includes(needle));

test("TEST-CNS-1865 runner (P1-1/P1-3): precondiciones antes de la fase cluster; diferimiento solo con migraciones pendientes; REAL_DATA no difiere si ops.schema_migration existe; aserción despues del COMMIT", async () => {
  // Sin ops.schema_migration (base nueva): todas las migraciones de base estan pendientes => se difiere (sin archivos cluster-post ni aserción).
  const fresh = superuser();
  assert.deepEqual(await applyClusterScope(fresh, MIGS, { mode: "IT0B_SYNTHETIC" }), ["0000"]);
  assert.ok(idx(fresh, "post-sql") < 0 && idx(fresh, "u.rolname AS member") < 0, "base nueva: cluster-post y aserción se difieren");
  // Con una migracion de base pendiente (tabla existe, 0001 no aplicada): tambien se difiere.
  const pending = superuser({ applied: [] });
  assert.deepEqual(await applyClusterScope(pending, MIGS, { mode: "IT0B_SYNTHETIC" }), ["0000"]);
  // Sin pendientes: cluster + cluster-post en UNA transaccion y la aserción DESPUES del COMMIT (fuera de la transaccion que confirma el REVOKE).
  const done = superuser({ applied: ["0001"] });
  assert.deepEqual(await applyClusterScope(done, MIGS, { mode: "IT0B_SYNTHETIC" }), ["0000", "0002"]);
  assert.equal(texts(done).filter((t) => t === "BEGIN").length, 1);
  assert.ok(idx(done, "cluster-sql") < idx(done, "post-sql") && idx(done, "post-sql") < texts(done).indexOf("COMMIT") && texts(done).indexOf("COMMIT") < idx(done, "u.rolname AS member"));
  // REAL_DATA con la tabla presente y migraciones pendientes: NO se difiere (una base viva no deja el SET abierto).
  const real = superuser({ applied: [] });
  await applyClusterScope(real, MIGS, { mode: "REAL_DATA" }).catch(() => undefined);
  assert.ok(idx(real, "post-sql") >= 0, "REAL_DATA con ops.schema_migration: la fase posterior corre en la misma transaccion");
  // REAL_DATA sin la tabla (base nueva): si se difiere.
  const realFresh = superuser();
  await applyClusterScope(realFresh, MIGS, { mode: "REAL_DATA" });
  assert.ok(idx(realFresh, "post-sql") < 0);
  // Precondiciones: ceremonia abierta (LOGIN) => falla ANTES de cualquier BEGIN o SQL de cluster.
  const open = superuser({ canLogin: true });
  await assert.rejects(() => applyClusterScope(open, MIGS, { mode: "IT0B_SYNTHETIC" }), /Precondición del deploy no cumplida \(nada se aplicó\)/);
  assert.ok(idx(open, "BEGIN") < 0 && idx(open, "cluster-sql") < 0);
  // El lock se libera siempre.
  assert.ok(idx(open, "pg_advisory_unlock") >= 0);
});

test("TEST-CNS-1865 runner (P1-1): si la fase posterior falla (diferida o en la transaccion unica) una transaccion PROPIA ejecuta solo REVOKE tras el ROLLBACK; si el solo-REVOKE tambien falla se informa; el error original se relanza", async () => {
  // Fase posterior diferida: 0002 falla => ROLLBACK, luego BEGIN + solo-REVOKE + COMMIT.
  const failing = superuser({ applied: ["0001"], failOn: "post-sql" });
  await assert.rejects(() => applyClusterPostScope(failing, MIGS, { mode: "IT0B_SYNTHETIC" }), /fallo inyectado/);
  const t = texts(failing);
  const iRollback = t.indexOf("ROLLBACK");
  const iFailsafe = t.findIndex((x) => x.startsWith("SELECT pg_catalog.format('REVOKE %I FROM %I'"));
  assert.ok(iRollback >= 0 && iFailsafe > iRollback, "el solo-REVOKE va DESPUES del ROLLBACK");
  assert.equal(t[iFailsafe - 1], "BEGIN");
  assert.equal(t[t.indexOf("COMMIT", iFailsafe)], "COMMIT", "y se confirma en su propia transaccion");
  const params = failing.queries[iFailsafe]?.values as unknown[];
  assert.deepEqual(params[0], ["integrity_owner", "breakglass_log_owner"], "IT0B: integrity_owner y breakglass_log_owner");
  assert.equal(params[1], false);
  // REAL_DATA: todo SET de consent_owner sobre los 17 owners y consent_migrator -> outbox_claimer.
  const realFail = superuser({ applied: ["0001"], failOn: "post-sql" });
  await assert.rejects(() => applyClusterPostScope(realFail, MIGS, { mode: "REAL_DATA" }), /fallo inyectado/);
  const rp = realFail.queries.find((q) => q.text.startsWith("SELECT pg_catalog.format('REVOKE %I FROM %I'"))?.values as unknown[];
  assert.equal((rp[0] as string[]).length, 18);
  assert.equal(rp[1], true);
  // Fase unica (sin pendientes): un fallo tambien dispara el solo-REVOKE.
  const single = superuser({ applied: ["0001"], failOn: "post-sql" });
  await assert.rejects(() => applyClusterScope(single, MIGS, { mode: "IT0B_SYNTHETIC" }), /fallo inyectado/);
  assert.ok(idx(single, "SELECT pg_catalog.format('REVOKE %I FROM %I'") > idx(single, "ROLLBACK"));
  // Si el solo-REVOKE falla: error mayor que incluye el original.
  const both = superuser({ applied: ["0001"], failOn: "post-sql", failsafeFails: true });
  await assert.rejects(() => applyClusterPostScope(both, MIGS, { mode: "IT0B_SYNTHETIC" }), /solo-REVOKE también.*fallo del solo-REVOKE.*Error original: fallo inyectado/s);
  // Una precondicion incumplida en la fase posterior tambien deja el REVOKE (el SET pudo quedar re-otorgado por la fase cluster).
  const preOpen = superuser({ applied: ["0001"], canLogin: true });
  await assert.rejects(() => applyClusterPostScope(preOpen, MIGS, { mode: "IT0B_SYNTHETIC" }), /Precondición/);
  assert.ok(idx(preOpen, "SELECT pg_catalog.format('REVOKE %I FROM %I'") >= 0);
});

test("TEST-CNS-1865 runner (P1-3): el lock de roles espera con pg_try_advisory_lock hasta un tope y falla con MigrationError; no se queda esperando para siempre", async () => {
  const held = new FakeClient((text) => (text.includes("pg_try_advisory_lock") ? { rows: [{ locked: false }] } : undefined));
  const started = Date.now();
  await assert.rejects(() => withClusterRoleLock(held, async () => "no", 250), /No se obtuvo el lock del runner de migraciones en 250 ms/);
  assert.ok(Date.now() - started < 5_000);
  assert.ok(!held.queries.some((q) => q.text.includes("pg_advisory_unlock")), "no se libera un lock que no se tomo");
  assert.ok(!held.queries.some((q) => /pg_advisory_lock\(/.test(q.text)), "ya no hay pg_advisory_lock bloqueante");
  // Se toma en el segundo intento.
  let n = 0;
  const later = new FakeClient((text) => (text.includes("pg_try_advisory_lock") ? { rows: [{ locked: ++n >= 2 }] } : undefined));
  assert.equal(await withClusterRoleLock(later, async () => "ok", 5_000), "ok");
  assert.ok(later.queries.some((q) => q.text.includes("pg_advisory_unlock")));
  const src = read("src/infra/adapters/postgres/migrate.ts");
  assert.doesNotMatch(src, /"SELECT pg_advisory_lock\(\$1\)"/);
});

test("TEST-CNS-1866 SQL (P1-2, P2): 0084 sin concesion transitoria a consent_owner; 0085 es cluster-post con SET LOCAL ROLE breakglass_log_owner y sin consent_owner; 0086 sin bloque de aserciones; open.sql lee el verificador con \\getenv y track_utility=off; close.sql termina sesiones despues del COMMIT y verifica 0", () => {
  const sql84 = noComments(read("db/migrations/0084_adr010_pr7d_cluster_roles.sql"));
  assert.doesNotMatch(sql84, /GRANT breakglass_log_owner TO/i, "ninguna concesion de breakglass_log_owner (ni transitoria)");
  assert.match(sql84, /r\.rolname = 'breakglass_log_owner'\) LOOP/, "revoca cualquier membresia previa de breakglass_log_owner");
  const raw85 = read("db/migrations/0085_adr010_pr7d_breakglass_ceremony.sql");
  assert.match(raw85, /^-- scope: cluster-post/);
  const sql85 = noComments(raw85);
  assert.match(sql85, /CREATE SCHEMA IF NOT EXISTS breakglass AUTHORIZATION breakglass_log_owner;\s+SET LOCAL ROLE breakglass_log_owner;/);
  assert.doesNotMatch(sql85, /consent_owner/, "0085 no involucra a consent_owner");
  assert.match(sql85, /ENABLE ALWAYS TRIGGER ceremony_guard/);
  assert.match(sql85, /FORCE ROW LEVEL SECURITY/);
  assert.match(sql85, /RESET ROLE;\s*$/);
  const sql86 = noComments(read("db/migrations/0086_adr010_pr7d_revoke_and_database_level.sql"));
  assert.doesNotMatch(sql86, /RAISE EXCEPTION/, "las aserciones las hace el runner, en otra transaccion (F-PR7D-01)");
  const open = read("db/ceremonies/open.sql");
  assert.match(open, /\\getenv verifier CNS_CEREMONY_VERIFIER/);
  assert.match(open, /SET pg_stat_statements\.track_utility = off;/);
  assert.doesNotMatch(noComments(open), /-v verifier|:verifier\b(?!_)/, "el verificador no entra por argv");
  const close = noComments(read("db/ceremonies/close.sql"));
  assert.match(close, /SET pg_stat_statements\.track_utility = off;/);
  const iCommit = close.indexOf("COMMIT;");
  assert.ok(iCommit > 0 && close.indexOf("pg_terminate_backend") > iCommit, "las sesiones se terminan DESPUES del COMMIT de NOLOGIN");
  assert.match(close, /no_sessions[\s\S]*\\if :no_sessions[\s\S]*RAISE EXCEPTION 'close\.sql: ddl_breakglass sigue con sesiones/);
});

test("TEST-CNS-1867 checkBreakglassState / checkDbRoleSettings (P1-2, P2): hechos exactos del esquema breakglass; cualquier hecho de mas o de menos es diferencia; pg_db_role_setting de un rol gobernado en esta base es diferencia", async () => {
  const facts = (rows: readonly string[]): FakeClient => new FakeClient((text) => (text.includes("'schema|owner='") ? { rows: rows.map((fact) => ({ fact })) } : undefined));
  assert.deepEqual(await checkBreakglassState(facts(BREAKGLASS_EXPECTED_FACTS)), []);
  assert.match((await checkBreakglassState(facts([])))[0] ?? "", /falta el esquema breakglass/);
  const drifts: Array<[string, readonly string[], RegExp]> = [
    ["trigger deshabilitado", BREAKGLASS_EXPECTED_FACTS.map((f) => f.replace("trigger|ceremony_guard|A|", "trigger|ceremony_guard|D|")), /falta trigger\|ceremony_guard\|A/],
    ["trigger origin (no ALWAYS)", BREAKGLASS_EXPECTED_FACTS.map((f) => f.replace("trigger|ceremony_no_truncate|A|", "trigger|ceremony_no_truncate|O|")), /sobra trigger\|ceremony_no_truncate\|O/],
    ["FORCE RLS apagada", BREAKGLASS_EXPECTED_FACTS.map((f) => f.replace("force=true", "force=false")), /falta rel\|ceremony\|r/],
    ["segunda policy", [...BREAKGLASS_EXPECTED_FACTS, "policy|otra|a|true|consent_owner|true|"], /sobra policy\|otra/],
    ["otro dueño de la tabla", BREAKGLASS_EXPECTED_FACTS.map((f) => f.replace("rel|ceremony|r|breakglass_log_owner", "rel|ceremony|r|consent_owner")), /sobra rel\|ceremony\|r\|consent_owner/],
    ["INSERT concedido al migrador", BREAKGLASS_EXPECTED_FACTS.map((f) => (f.startsWith("rel|ceremony|r|") ? `${f},consent_owner:breakglass_log_owner:INSERT:false` : f)), /sobra rel\|ceremony\|r/],
    ["ACL de columna ampliada", [...BREAKGLASS_EXPECTED_FACTS, "col_acl|reason_code|integrity_chain_verifier:breakglass_log_owner:SELECT:false"], /sobra col_acl\|reason_code/],
    ["ACL del esquema ampliada", BREAKGLASS_EXPECTED_FACTS.map((f) => (f.startsWith("schema|") ? `${f},consent_owner:breakglass_log_owner:CREATE:false` : f)), /sobra schema\|/],
    ["objeto ajeno en el esquema", [...BREAKGLASS_EXPECTED_FACTS, "rel|intruso|r|consent_owner|rls=false|force=false|"], /sobra rel\|intruso/],
    ["funcion alterada (SECURITY DEFINER)", BREAKGLASS_EXPECTED_FACTS.map((f) => f.replace("ceremony_guard()|breakglass_log_owner|false|", "ceremony_guard()|breakglass_log_owner|true|")), /falta fn\|breakglass\.ceremony_guard/],
  ];
  for (const [why, rows, pattern] of drifts) assert.ok((await checkBreakglassState(facts(rows))).some((p) => pattern.test(p)), why);
  // Fail-closed si no se puede leer.
  assert.match((await checkBreakglassState(new FakeClient((text) => (text.includes("'schema|owner='") ? new Error("boom") : undefined))))[0] ?? "", /no se pudo verificar el estado exacto/);
  // checkDatabaseLevel incluye ambos chequeos (deploy, startup, vigilancia).
  const healthy = new FakeClient((text) => databaseLevelRows(text));
  assert.deepEqual(await checkDatabaseLevel(healthy, "IT0B_SYNTHETIC", { breakglassMustBeClosed: true }), []);
  const drifted = new FakeClient((text) => (text.includes("'schema|owner='") ? { rows: [] } : databaseLevelRows(text)));
  assert.ok((await checkDatabaseLevel(drifted, "IT0B_SYNTHETIC")).some((p) => /falta el esquema breakglass/.test(p)));
  const dbSetting = new FakeClient((text) => (text.includes("FROM pg_catalog.pg_db_role_setting s") && text.includes("for_role") ? { rows: [{ scope: "ddl_breakglass", setting: "log_statement", for_role: true }] } : databaseLevelRows(text)));
  assert.match((await checkDbRoleSettings(dbSetting))[0] ?? "", /fija log_statement para ddl_breakglass en esta base/);
  assert.ok((await checkDatabaseLevel(dbSetting, "IT0B_SYNTHETIC")).some((p) => /pg_db_role_setting fija log_statement para ddl_breakglass/.test(p)));
});
