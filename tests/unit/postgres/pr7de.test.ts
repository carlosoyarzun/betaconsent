// Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7d/7e), decisiones de Carlos del 2026-10-16 (C-1, C-4, C-5, C-9), F-PR7-03/06/07/12, F-PR7C-08. Sin Postgres. SYNTHETIC ONLY.
// TEST-CNS-1850 (vigilancia de break-glass: evaluacion pura), 1851 (verificador SCRAM: vector RFC 7677 y formato), 1852 (coherencia de los archivos SQL: lista derivada de owners, ceremonias solo DDL y sin contrasena en texto plano),
// 1853 (inventario de consent_owner por modo, por dueño independiente del SET y por version mayor de PostgreSQL, F-PR7C-08, F-PR7D-06).

import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { evaluateBreakglass } from "../../../src/infra/adapters/postgres/breakglass-watch-reader.ts";
import type { BreakglassSnapshot } from "../../../src/infra/adapters/postgres/breakglass-watch-reader.ts";
import { CONSENT_OWNER_INVENTORY_SQL, checkConsentOwnerInventory, checkInventoryServerVersion, inventoryAllowlistFor } from "../../../src/infra/adapters/postgres/consent-owner-inventory.ts";
import { CONSENT_OWNER_INVENTORY_ALLOWLIST, CONSENT_OWNER_INVENTORY_VERIFIED_PG_MAJORS } from "../../../src/infra/adapters/postgres/consent-owner-inventory.allowlist.ts";
import { DDL_BREAKGLASS_SETTINGS } from "../../../src/infra/adapters/postgres/database-level.ts";
import { BREAKGLASS_OWNER_ROLES, CONSENT_OWNER_SET_ROLES, OWNER_ROLES } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { runStartupChecks } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { formatBreakglassFindings } from "../../../src/server/entrypoints/chain-verifier/breakglass-watch.ts";
import { scramVerifier } from "../../../tools/ceremony/scram-verifier.ts";
import { FakeClient } from "./fakes.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");
const NOW = 1_800_000_000_000;
const snap = (s: Partial<BreakglassSnapshot>): BreakglassSnapshot => ({ nowMs: NOW, canLogin: false, sessions: 0, openCeremonies: [], ...s });
const window = (validUntilMs: number, ref = "CER-20261017-01") => ({ ceremonyRef: ref, openedAtMs: NOW - 600_000, validUntilMs });

test("TEST-CNS-1850 breakglass-watch: LOGIN o sesion de ddl_breakglass sin ceremonia vigente, y ceremonia vencida sin cerrar, son hallazgos (exit 2); con ceremonia vigente no", () => {
  assert.deepEqual(evaluateBreakglass(snap({})), [], "cerrado y sin ceremonia: ok");
  assert.deepEqual(evaluateBreakglass(snap({ canLogin: true, sessions: 1, openCeremonies: [window(NOW + 60_000)] })), [], "ceremonia vigente: LOGIN y sesion esperados");
  assert.deepEqual(evaluateBreakglass(snap({ canLogin: true })).map((f) => f.code), ["LOGIN_WITHOUT_CEREMONY"]);
  assert.deepEqual(evaluateBreakglass(snap({ sessions: 2 })).map((f) => f.code), ["SESSION_WITHOUT_CEREMONY"]);
  assert.deepEqual(evaluateBreakglass(snap({ canLogin: true, sessions: 1 })).map((f) => f.code), ["LOGIN_WITHOUT_CEREMONY", "SESSION_WITHOUT_CEREMONY"]);
  const overdue = evaluateBreakglass(snap({ canLogin: false, openCeremonies: [window(NOW - 1)] }));
  assert.deepEqual(overdue, [{ code: "CEREMONY_OVERDUE", ceremonyRef: "CER-20261017-01" }]);
  // vencida y con LOGIN: ambos hallazgos (nada la ampara)
  assert.deepEqual(evaluateBreakglass(snap({ canLogin: true, openCeremonies: [window(NOW - 1)] })).map((f) => f.code), ["LOGIN_WITHOUT_CEREMONY", "CEREMONY_OVERDUE"]);
  assert.deepEqual(evaluateBreakglass(snap({ canLogin: null })).map((f) => f.code), ["ROLE_NOT_FOUND"]);
  assert.throws(() => evaluateBreakglass(snap({ nowMs: Number.NaN })));
  // El log solo lleva codigos y la referencia opaca (sin PII ni secretos).
  const lines = formatBreakglassFindings(overdue);
  assert.deepEqual(lines, ["breakglass-watch: HALLAZGO CEREMONY_OVERDUE ceremonia=CER-20261017-01"]);
  assert.match(formatBreakglassFindings([])[0] ?? "", /ok/);
});

test("TEST-CNS-1851 scram-verifier: vector RFC 7677 (pencil) y formato SCRAM-SHA-256 de PostgreSQL; la contrasena no aparece en el verificador", () => {
  const salt = Buffer.from("W22ZaJ0SNY7soEsUEjb6gQ==", "base64");
  const v = scramVerifier("pencil", salt, 4096);
  const m = /^SCRAM-SHA-256\$4096:([A-Za-z0-9+/]+=*)\$([A-Za-z0-9+/]+=*):([A-Za-z0-9+/]+=*)$/.exec(v);
  assert.ok(m !== null, v);
  assert.equal(m[1], "W22ZaJ0SNY7soEsUEjb6gQ==");
  const storedKey = Buffer.from(m[2] as string, "base64");
  const serverKey = Buffer.from(m[3] as string, "base64");
  const authMessage = "n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
  const clientSignature = createHmac("sha256", storedKey).update(authMessage).digest();
  // ClientProof = ClientKey XOR ClientSignature => ClientKey = proof XOR signature; SHA-256(ClientKey) debe ser StoredKey.
  const proof = Buffer.from("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", "base64");
  const clientKey = Buffer.from(proof.map((b, i) => b ^ (clientSignature[i] as number)));
  assert.equal(createHash("sha256").update(clientKey).digest("base64"), storedKey.toString("base64"));
  assert.equal(createHmac("sha256", serverKey).update(authMessage).digest("base64"), "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
  assert.ok(!v.includes("pencil"));
  assert.throws(() => scramVerifier("con espacio"));
  assert.notEqual(scramVerifier("pencil"), scramVerifier("pencil"), "sal aleatoria");
});

test("TEST-CNS-1852 SQL de PR-7d/7e: la lista de 17 owners de 0084/0086 es la derivada de OWNER_ROLES; ceremonias sin contrasena en texto plano; settings de ddl_breakglass coinciden con database-level.ts", () => {
  const listOf = (sql: string): string[] => {
    const all = [...sql.matchAll(/ARRAY\[\s*((?:'[a-z_]+',?\s*)+)\]/g)].map((m) => [...(m[1] as string).matchAll(/'([a-z_]+)'/g)].map((x) => x[1] as string));
    return all.find((l) => l.length === 17) ?? [];
  };
  const derived = [...BREAKGLASS_OWNER_ROLES].sort();
  assert.equal(derived.length, 17);
  assert.deepEqual([...OWNER_ROLES.filter((r) => r !== "consent_owner")].sort(), derived);
  assert.deepEqual([...listOf(read("db/migrations/0086_adr010_pr7d_revoke_and_database_level.sql"))].sort(), derived, "0086 concede y asevera los 17 owners derivados");
  const sql84 = read("db/migrations/0084_adr010_pr7d_cluster_roles.sql");
  for (const s of DDL_BREAKGLASS_SETTINGS) {
    const [k, v] = s.split("=") as [string, string];
    assert.match(sql84, new RegExp(`SET ${k} = ('?)${v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\1;`), s);
  }
  assert.ok(!sql84.replace(/--[^\n]*/g, "").includes("'all'"), "log_statement='all' escribiria datos en logs (F-PR7-07)");
  // 0086: revoke de integrity_owner en ambos modos; REVOKE explicito en REAL_DATA de los 17 y de consent_migrator -> outbox_claimer; ALTER DATABASE; CREATE por modo.
  const sql86 = read("db/migrations/0086_adr010_pr7d_revoke_and_database_level.sql");
  assert.match(sql86, /^-- scope: cluster-post/);
  assert.match(sql86, /REVOKE integrity_owner FROM consent_owner;/);
  assert.match(sql86, /REVOKE outbox_claimer FROM consent_migrator;/);
  assert.match(sql86, /ALTER DATABASE %I OWNER TO db_owner_nologin/);
  assert.match(sql86, /REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC/);
  // Ceremonias: verificador SCRAM por variable (nunca contrasena en texto plano), log_statement none en la sesion de superusuario, solo DDL en el ensayo.
  const open = read("db/ceremonies/open.sql");
  assert.match(open, /PASSWORD %L VALID UNTIL %L/);
  assert.match(open, /:'verifier'/);
  assert.doesNotMatch(open, /:'password'|:password/i);
  assert.match(open, /SET log_statement = 'none'/);
  const noComments = (s: string): string => s.replace(/--[^\n]*/g, "");
  const rehearsal = noComments(read("db/ceremonies/rehearsal-ddl.sql"));
  assert.doesNotMatch(rehearsal, /\b(INSERT|UPDATE|DELETE|COPY|SELECT)\b/i, "el DDL del ensayo no lleva DML");
  const close = noComments(read("db/ceremonies/close.sql"));
  assert.match(close, /NOLOGIN PASSWORD NULL VALID UNTIL/);
  assert.match(close, /pg_terminate_backend/);
});

test("TEST-CNS-1853 inventario de consent_owner: allowlist por modo (REAL_DATA sin filas V2|fn de roles con SET) y version mayor de PostgreSQL verificada con mensaje explicito (F-PR7C-08)", async () => {
  const it0b = inventoryAllowlistFor("IT0B_SYNTHETIC");
  const real = inventoryAllowlistFor("REAL_DATA");
  assert.equal(it0b, CONSENT_OWNER_INVENTORY_ALLOWLIST);
  // F-PR7D-06: allowlist POR DUEÑO, independiente del SET: integrity_owner (8) y breakglass_log_owner (1) estan en AMBOS modos aunque consent_owner no pueda asumirlos.
  const fnRows = (list: readonly string[], owner: string): string[] => list.filter((l) => l.startsWith(`V2|fn|${owner}|`));
  assert.equal(fnRows(it0b, "integrity_owner").length, 8, "las 8 filas del ledger se reponen");
  assert.equal(fnRows(it0b, "breakglass_log_owner").length, 1);
  assert.ok(it0b.some((l) => l.startsWith("V2|fn|transition_owner|")), "IT0B conserva las filas de los owners con SET");
  assert.deepEqual(fnRows(real, "integrity_owner"), fnRows(it0b, "integrity_owner"), "REAL_DATA tambien: es por dueño, no por SET");
  assert.deepEqual(fnRows(real, "breakglass_log_owner"), fnRows(it0b, "breakglass_log_owner"));
  assert.deepEqual(real.filter((l) => l.startsWith("V2|fn|") && !/^V2\|fn\|(integrity_owner|breakglass_log_owner)\|/.test(l)), [], "REAL_DATA: sin SET no hay funciones de OTROS owners en el alcance de consent_owner");
  assert.equal(real.length, it0b.filter((l) => !l.startsWith("V2|fn|") || /^V2\|fn\|(integrity_owner|breakglass_log_owner)\|/.test(l)).length);
  // Cada fila V2|fn de IT0B es de un owner con SET o de uno de los dos duenos independientes del SET (cierra la derivacion de la lista por modo).
  const owners = new Set(it0b.filter((l) => l.startsWith("V2|fn|")).map((l) => l.split("|")[2] as string));
  for (const o of owners) assert.ok(CONSENT_OWNER_SET_ROLES.includes(o) || o === "integrity_owner" || o === "breakglass_log_owner", o);
  assert.match(CONSENT_OWNER_INVENTORY_SQL, /IN \('integrity_owner', 'breakglass_log_owner'\)/, "la consulta lee las funciones de esos duenos aunque no haya SET");
  assert.ok(CONSENT_OWNER_INVENTORY_VERIFIED_PG_MAJORS.includes(16) && CONSENT_OWNER_INVENTORY_VERIFIED_PG_MAJORS.includes(18));
  const version = (num: string): FakeClient => new FakeClient((text) => (text.includes("server_version_num") ? { rows: [{ server_version_num: num }] } : { rows: [] }));
  assert.deepEqual(await checkInventoryServerVersion(version("160015")), []);
  assert.deepEqual(await checkInventoryServerVersion(version("180003")), []);
  const bad = await checkInventoryServerVersion(version("190000"));
  assert.equal(bad.length, 1);
  assert.match(bad[0] ?? "", /PostgreSQL 16, 18 y el servidor es 19/);
  // Con una version no verificada el chequeo devuelve SOLO ese mensaje (no cientos de diferencias de md5).
  assert.deepEqual(await checkConsentOwnerInventory(version("190000"), "IT0B_SYNTHETIC"), bad);
});

test("TEST-CNS-1861 retencion NOT_APPLICABLE (F-PR7a-03): el chequeo mira current_user y todo rol alcanzable con SET (pg_has_role SET) y el criterio es consume o purga retencion", async () => {
  const seen: string[] = [];
  const db = new FakeClient((text) => {
    if (text.includes("p.proname IN ('retention_status', 'purge_p34')")) {
      seen.push(text);
      return { rows: [{ name: "retention_status", via: "platform_rw" }, { name: "purge_p34", via: "security_event_owner" }] };
    }
    return undefined;
  });
  const result = await runStartupChecks(db, { expectedEnvironment: "LOCAL", retentionProfile: "NOT_APPLICABLE" });
  assert.match(seen[0] ?? "", /pg_has_role\(current_user, x\.oid, 'SET'\)/);
  assert.ok(result.failures.some((f) => /ops\.retention_status/.test(f) && /no consume ni purga retención/.test(f)));
  assert.ok(result.failures.some((f) => /puede asumir security_event_owner, que ejecuta ops\.purge_p34/.test(f) && /F-PR7a-03/.test(f)));
  const src = readFileSync(join(ROOT, "src/infra/adapters/postgres/runtime-process.ts"), "utf8") + readFileSync(join(ROOT, "src/infra/adapters/postgres/startup-checks.ts"), "utf8");
  assert.ok(!/el proceso no purga ni escribe datos con retencion/.test(src), "la justificacion falsa (platform no escribe datos con retencion) ya no esta");
  assert.match(src, /platform SI escribe ops\.security_event/);
});

test("TEST-CNS-1862 startup-checks: el estado a nivel de base (INV-DBR-09) es estricto con REAL_DATA o assertDatabaseLevel; en LOCAL/IT0B no se exige; REAL_DATA sigue bloqueado por F-PR7-01 (F-PR7-12)", async () => {
  const seenDb: string[] = [];
  const mk = (): FakeClient => new FakeClient((text) => {
    if (text.includes("AS datdba_name")) {
      seenDb.push(text);
      return { rows: [{ datdba_name: "consent_owner", public_privileges: ["CONNECT"], owner_create: true, missing_connect: ["app_rw"] }] };
    }
    return undefined;
  });
  const lax = await runStartupChecks(mk(), { expectedEnvironment: "LOCAL" });
  assert.equal(seenDb.length, 0, "IT0B en LOCAL: no se consulta el nivel de base");
  assert.ok(!lax.failures.some((f) => /INV-DBR-09/.test(f)));
  const strict = await runStartupChecks(mk(), { expectedEnvironment: "STAGING", roleMode: "IT0B_SYNTHETIC", assertDatabaseLevel: true });
  assert.ok(strict.failures.some((f) => /dueño de la base es consent_owner/.test(f)));
  assert.ok(strict.failures.some((f) => /PUBLIC tiene CONNECT/.test(f)));
  const real = await runStartupChecks(mk(), { expectedEnvironment: "LOCAL", roleMode: "REAL_DATA" });
  assert.ok(real.failures.some((f) => /REAL_DATA está bloqueado.*F-PR7-01/.test(f)), "REAL_DATA verificable no es autorizacion de datos reales");
  assert.ok(real.failures.some((f) => /dueño de la base es consent_owner/.test(f)));
});
