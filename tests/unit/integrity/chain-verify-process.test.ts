// Gobierna: ADR-010 rev. 6 §1 (chain-verifier = integrity_chain_verifier; env propio CNS_CHAIN_VERIFIER_*; falla si hay CNS_VERIFIER_*), §2 (C7 ALLOW_EMPTY solo LOCAL; C11 sin imports OIDC; SQL solo con parametros), §3 fila PR-6f,
// F-PR6E-06, SEC-06-1, SEC-06-6, INV-DBR-02. SYNTHETIC ONLY. Sin Postgres.
// TEST-CNS-1738 (el proceso solo arranca con integrity_chain_verifier y la config es fail-closed), TEST-CNS-1754 (tenant_id e inputs del lector solo como parametros $n), TEST-CNS-1755 (el grafo de imports no toca
// el verifier OIDC, step-up, IdP ni adaptadores de platform; y falla si hay CNS_VERIFIER_* en el entorno).

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { expectedRoleFor, ProcessRoleError, readProcessDatabaseUrl, RUNTIME_PROCESS_ROLES } from "../../../src/infra/adapters/postgres/runtime-process.ts";
import { RUNTIME_ROLES } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { PLATFORM_RUNTIME_EXECUTE } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { CHAIN_COLUMNS } from "../../../src/infra/adapters/postgres/chain-verifier-reader.ts";
import {
  ChainVerifierConfigError,
  DEFAULT_BATCH,
  MAX_BATCH,
  MIN_BATCH,
  parseChainVerifierConfig,
  startChainVerifierProcess,
} from "../../../src/server/entrypoints/chain-verifier/chain-verify-process.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const urlFor = (role: string): string => `postgresql://${role}:s3cr3t-pw@127.0.0.1:1/db`;
const WRONG_ROLES = ["app_rw", "platform_rw", "worker", "integrity_verifier", "integrity_reconciler", "ledger_writer", "consent_owner", "consent_migrator", "integrity_owner", "postgres"];

test("TEST-CNS-1738 chain-verifier = integrity_chain_verifier: rol de runtime gobernado, distinto del verifier OIDC y del reconciler, sin EXECUTE de platform", () => {
  assert.equal(RUNTIME_PROCESS_ROLES["chain-verifier"], "integrity_chain_verifier");
  assert.equal(expectedRoleFor("chain-verifier"), "integrity_chain_verifier");
  assert.ok(RUNTIME_ROLES.includes("integrity_chain_verifier"));
  assert.deepEqual(PLATFORM_RUNTIME_EXECUTE.integrity_chain_verifier, []);
  assert.deepEqual(PLATFORM_RUNTIME_EXECUTE.integrity_verifier, ["claim_oidc_exchange", "record_assertion", "record_login_assertion"], "el verifier OIDC no cambia");
  assert.notEqual(RUNTIME_PROCESS_ROLES["chain-verifier"], RUNTIME_PROCESS_ROLES.verifier, "SEC-06-1: el chain-verifier NO usa el rol del verifier OIDC");
  assert.notEqual(RUNTIME_PROCESS_ROLES["chain-verifier"], RUNTIME_PROCESS_ROLES.reconciler);
  assert.equal(CHAIN_COLUMNS.length, 17);
  assert.equal(new Set(CHAIN_COLUMNS).size, 17);
  for (const forbidden of ["event_id", "evidentiary", "data_class"]) assert.ok(!CHAIN_COLUMNS.includes(forbidden), forbidden);
});

test("TEST-CNS-1738 solo acepta su rol: otro rol de runtime (incluidos integrity_verifier e integrity_reconciler), el migrador, un owner y el superusuario fallan cerrado sin filtrar la credencial; los demas procesos tampoco aceptan su rol", async () => {
  for (const role of WRONG_ROLES) {
    assert.throws(
      () => readProcessDatabaseUrl("chain-verifier", { CNS_DATABASE_URL: urlFor(role) }),
      (e: unknown) => e instanceof ProcessRoleError && e.code === "PROCESS_ROLE_MISMATCH" && !String(e.message).includes("s3cr3t-pw") && !String(e.message).includes("postgresql://"),
      role,
    );
    await assert.rejects(() => startChainVerifierProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: urlFor(role) } }), ProcessRoleError, `chain-verifier con ${role}`);
  }
  for (const p of ["web", "platform", "worker", "verifier", "reconciler"] as const) {
    assert.throws(() => readProcessDatabaseUrl(p, { CNS_DATABASE_URL: urlFor("integrity_chain_verifier") }), ProcessRoleError, p);
  }
  const base = urlFor("integrity_chain_verifier");
  for (const url of [`${base}?user=consent_owner`, `${base}?options=-c%20role%3Dintegrity_chain_verifier`, `${base}?password=otra`, `${base}?host=otro-host`, "http://integrity_chain_verifier:x@h/db"]) {
    await assert.rejects(() => startChainVerifierProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: url } }), ProcessRoleError, url);
  }
  for (const env of [undefined, "", "PRODUCTION", "local"]) {
    await assert.rejects(() => startChainVerifierProcess({ env: { ...(env === undefined ? {} : { CNS_ENVIRONMENT: env }), CNS_DATABASE_URL: base } }), ProcessRoleError, String(env));
  }
});

test("TEST-CNS-1738 CNS_CHAIN_VERIFIER_BATCH: entero 100..5000 (default 500); fuera de rango o no numerico = el proceso no arranca (sin eco del valor)", async () => {
  assert.deepEqual(parseChainVerifierConfig({ CNS_ENVIRONMENT: "LOCAL" }), { batchSize: DEFAULT_BATCH, allowEmpty: false, stateDir: undefined });
  assert.equal(DEFAULT_BATCH, 500);
  for (const ok of [String(MIN_BATCH), "500", String(MAX_BATCH)]) assert.equal(parseChainVerifierConfig({ CNS_CHAIN_VERIFIER_BATCH: ok }).batchSize, Number(ok));
  for (const bad of ["99", "5001", "0", "-1", "abc", "1e3", "500.5", " 500", "", "999999"]) {
    assert.throws(() => parseChainVerifierConfig({ CNS_CHAIN_VERIFIER_BATCH: bad }), (e: unknown) => e instanceof ChainVerifierConfigError && !String(e.message).includes(`"${bad}"`), `BATCH=${JSON.stringify(bad)}`);
    await assert.rejects(() => startChainVerifierProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: urlFor("integrity_chain_verifier"), CNS_CHAIN_VERIFIER_BATCH: bad } }), ChainVerifierConfigError, `BATCH=${JSON.stringify(bad)}`);
  }
  assert.throws(() => parseChainVerifierConfig({ CNS_CHAIN_VERIFIER_BATCHSIZE: "500" }), ChainVerifierConfigError, "un CNS_CHAIN_VERIFIER_* desconocido (typo) no se ignora en silencio");
});

test("TEST-CNS-1738 CNS_CHAIN_VERIFIER_ALLOW_EMPTY solo existe en LOCAL (C7): con otro CNS_ENVIRONMENT, o con un valor distinto de true/false, el proceso no arranca", async () => {
  assert.equal(parseChainVerifierConfig({ CNS_ENVIRONMENT: "LOCAL", CNS_CHAIN_VERIFIER_ALLOW_EMPTY: "true" }).allowEmpty, true);
  assert.equal(parseChainVerifierConfig({ CNS_ENVIRONMENT: "LOCAL", CNS_CHAIN_VERIFIER_ALLOW_EMPTY: "false" }).allowEmpty, false);
  for (const environment of ["DEV", "STAGING", "PRODUCTION", undefined, ""]) {
    assert.throws(() => parseChainVerifierConfig({ ...(environment === undefined ? {} : { CNS_ENVIRONMENT: environment }), CNS_CHAIN_VERIFIER_ALLOW_EMPTY: "true" }), ChainVerifierConfigError, String(environment));
    await assert.rejects(
      () => startChainVerifierProcess({ env: { CNS_ENVIRONMENT: environment ?? "", CNS_DATABASE_URL: urlFor("integrity_chain_verifier"), CNS_CHAIN_VERIFIER_ALLOW_EMPTY: "true" } }),
      ChainVerifierConfigError,
      String(environment),
    );
  }
  for (const bad of ["1", "yes", "TRUE", ""]) assert.throws(() => parseChainVerifierConfig({ CNS_ENVIRONMENT: "LOCAL", CNS_CHAIN_VERIFIER_ALLOW_EMPTY: bad }), ChainVerifierConfigError, bad);
});

test("TEST-CNS-1755 el proceso falla cerrado si existe cualquier CNS_VERIFIER_* (inyectado o del entorno real), aun con valor vacio, antes de conectar", async () => {
  for (const name of ["CNS_VERIFIER_SUB_HMAC_KEY_HEX", "CNS_VERIFIER_ISSUER", "CNS_VERIFIER_AUDIENCE", "CNS_VERIFIER_P48_MAX_FAILURES", "CNS_VERIFIER_X"]) {
    for (const value of ["valor", ""]) {
      const env = { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: urlFor("integrity_chain_verifier"), [name]: value };
      assert.throws(() => parseChainVerifierConfig(env), (e: unknown) => e instanceof ChainVerifierConfigError && !String(e.message).includes("valor"), name);
      await assert.rejects(() => startChainVerifierProcess({ env }), ChainVerifierConfigError, name);
    }
  }
  process.env.CNS_VERIFIER_SUB_HMAC_KEY_HEX = "ab".repeat(32);
  try {
    assert.throws(() => parseChainVerifierConfig({ CNS_ENVIRONMENT: "LOCAL" }), ChainVerifierConfigError, "CNS_VERIFIER_* en el entorno real del proceso");
  } finally {
    delete process.env.CNS_VERIFIER_SUB_HMAC_KEY_HEX;
  }
});

/** Cierre transitivo de imports relativos (estaticos y dinamicos) de un archivo .ts del repo. */
function importGraph(entry: string): string[] {
  const seen = new Set<string>();
  const visit = (file: string): void => {
    if (seen.has(file)) return;
    seen.add(file);
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(/(?:from\s+|import\s*\(\s*|import\s+)"(\.{1,2}\/[^"]+)"/g)) {
      const target = resolve(dirname(file), m[1]!);
      if (existsSync(target)) visit(target);
    }
  };
  visit(entry);
  return [...seen].map((f) => relative(ROOT, f)).sort();
}

test("TEST-CNS-1755 grafo de imports de main.ts: no importa el verifier OIDC, step-up, IdP, K_sub, platform ni el CLI del ledger; solo pool/runtime-process/startup-checks y el oraculo de la cadena", () => {
  const graph = importGraph(join(ROOT, "src/server/entrypoints/chain-verifier/main.ts"));
  assert.ok(graph.includes("src/server/modules/common/ledger-chain.ts"), "reutiliza el oraculo unico");
  assert.ok(graph.includes("src/infra/adapters/postgres/chain-verifier-reader.ts"));
  const forbidden = [/entrypoints\/verifier\//, /entrypoints\/platform\//, /entrypoints\/reconciler\//, /modules\/step-up\//, /oidc/i, /idp/i, /sub-?hmac|k_sub|ksub/i, /ledger-verify-cli/, /unit-of-work/, /ledger\.adapter/, /platform/i];
  for (const file of graph) {
    for (const re of forbidden) assert.ok(!re.test(file), `${file} (importado por el chain-verifier) coincide con ${re}`);
  }
  // Y el codigo del proceso no menciona CNS_VERIFIER_ mas que para rechazarlo.
  const procText = readFileSync(join(ROOT, "src/server/entrypoints/chain-verifier/chain-verify-process.ts"), "utf8");
  const reads = [...procText.matchAll(/env\.(CNS_[A-Z0-9_]+)/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(reads)].sort(), ["CNS_CHAIN_VERIFIER_ALLOW_EMPTY", "CNS_CHAIN_VERIFIER_BATCH", "CNS_CHAIN_VERIFIER_STATE_DIR", "CNS_ENVIRONMENT"]);
});

test("TEST-CNS-1754 el lector usa solo parametros $n: ningun SQL se arma con interpolacion de datos (tenant_id, cursor, lote) ni concatenacion de entradas", () => {
  const text = readFileSync(join(ROOT, "src/infra/adapters/postgres/chain-verifier-reader.ts"), "utf8");
  // Toda llamada query(...) recibe una constante de SQL o UN literal sin `${}` ni concatenacion posterior.
  let count = 0;
  for (const m of text.matchAll(/\.query(?:<[^>]*(?:<[^>]*>)?[^>]*>)?\(\s*/g)) {
    count += 1;
    const rest = text.slice(m.index! + m[0].length);
    const constant = /^(EVENT_SELECT|TENANTS_SQL|UNCHAINED_SQL|UNCHAINED_STRICT_SQL|LOCK_SQL|LOCK_CHECKPOINT_SQL|CHECKPOINT_HEADS_SQL|HASH_AT_SQL)\s*[,)]/.exec(rest);
    if (constant !== null) continue;
    const quote = rest[0];
    assert.ok(quote === '"' || quote === "`", `query con argumento no constante: ${rest.slice(0, 40)}`);
    let i = 1;
    while (i < rest.length && rest[i] !== quote) i += rest[i] === "\\" ? 2 : 1;
    const literal = rest.slice(1, i);
    assert.ok(!literal.includes("${"), `literal de SQL con interpolacion: ${literal.slice(0, 60)}`);
    assert.match(rest.slice(i + 1), /^\s*[,)]/, `concatenacion tras el literal: ${literal.slice(0, 60)}`);
  }
  assert.ok(count >= 8, `se esperaban >= 8 llamadas a query y hay ${count}`);
  for (const [name, sql] of [["EVENT_SELECT", text.match(/const EVENT_SELECT =([\s\S]*?);\n/)?.[1]], ["UNCHAINED_SQL", text.match(/const UNCHAINED_SQL =([\s\S]*?);\n/)?.[1]]] as const) {
    assert.ok(sql !== undefined, name);
    assert.ok(!sql!.includes("${"), `${name}: sin interpolacion`);
    assert.match(sql!, /\$1/, `${name}: tenant_id como $1`);
  }
  assert.match(text, /chain_seq > \$2::bigint ORDER BY chain_seq LIMIT \$3::int/, "cursor y lote como parametros");
  assert.ok(!/\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bTRUNCATE\b|\bCREATE\b|\bALTER\b|\bDROP\b|SET ROLE|set_config/i.test(text.replace(/\/\/.*$/gm, "").replace(/"[^"]*READ ONLY[^"]*"/g, "")), "sin DML ni DDL");
});
