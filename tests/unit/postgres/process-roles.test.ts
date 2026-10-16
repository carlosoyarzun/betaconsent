// Gobierna: ADR-010 rev. 4 §7 fila PR-6 (6a: "Entrypoints web/platform/worker/verifier; ... pools por rol"), specs/db-roles.spec.yaml INV-DBR-02.
// TEST-CNS-1396: contrato de rol por proceso SIN Postgres: mapa proceso -> rol exacto, el usuario de CNS_DATABASE_URL debe ser el rol del proceso (cualquier otro, incluido otro rol de
// runtime, falla cerrado), nunca la credencial del migrador, CNS_ENVIRONMENT es un enum cerrado, y los entrypoints platform/worker/verifier rechazan el rol equivocado ANTES de conectar.

import test from "node:test";
import assert from "node:assert/strict";

import {
  expectedRoleFor,
  parseRuntimeEnvironment,
  ProcessRoleError,
  readProcessDatabaseUrl,
  RUNTIME_PROCESS_ROLES,
} from "../../../src/infra/adapters/postgres/runtime-process.ts";
import type { RuntimeProcess } from "../../../src/infra/adapters/postgres/runtime-process.ts";
import { readRuntimeDatabaseUrl } from "../../../src/infra/adapters/postgres/store.ts";
import { startPlatformProcess } from "../../../src/server/entrypoints/platform/platform-process.ts";
import { startVerifierProcess } from "../../../src/server/entrypoints/verifier/verifier-process.ts";
import { startWorkerProcess } from "../../../src/server/entrypoints/worker/worker-process.ts";

const PROCESSES = Object.keys(RUNTIME_PROCESS_ROLES) as RuntimeProcess[];
const urlFor = (role: string): string => `postgresql://${role}:s3cr3t-pw@127.0.0.1:1/db`;

test("TEST-CNS-1396 INV-DBR-02: web=app_rw, platform=platform_rw, worker=worker, verifier=integrity_verifier, reconciler=integrity_reconciler, chain-verifier=integrity_chain_verifier (un rol por proceso, sin repetidos)", () => {
  assert.deepEqual({ ...RUNTIME_PROCESS_ROLES }, { web: "app_rw", platform: "platform_rw", worker: "worker", verifier: "integrity_verifier", reconciler: "integrity_reconciler", "chain-verifier": "integrity_chain_verifier" });
  assert.equal(new Set(Object.values(RUNTIME_PROCESS_ROLES)).size, 6);
  for (const p of PROCESSES) assert.equal(expectedRoleFor(p), RUNTIME_PROCESS_ROLES[p]);
});

test("TEST-CNS-1396 readProcessDatabaseUrl: solo el rol exacto del proceso; cualquier otro rol (de runtime, migrador, owner, superusuario) falla cerrado sin filtrar la credencial", () => {
  const roles = [...Object.values(RUNTIME_PROCESS_ROLES), "consent_migrator", "consent_owner", "postgres"];
  for (const p of PROCESSES) {
    for (const role of roles) {
      if (role === RUNTIME_PROCESS_ROLES[p]) {
        assert.equal(readProcessDatabaseUrl(p, { CNS_DATABASE_URL: urlFor(role) }), urlFor(role));
      } else {
        assert.throws(
          () => readProcessDatabaseUrl(p, { CNS_DATABASE_URL: urlFor(role) }),
          (e: unknown) => e instanceof ProcessRoleError && e.code === "PROCESS_ROLE_MISMATCH" && !String(e.message).includes("s3cr3t-pw") && !String(e.message).includes("postgresql://"),
          `${p} con ${role}`,
        );
      }
    }
    assert.throws(() => readProcessDatabaseUrl(p, {}), /CNS_DATABASE_URL/);
    assert.throws(() => readProcessDatabaseUrl(p, { CNS_DATABASE_URL: "no es url" }), /no es una URL/);
    assert.throws(() => readProcessDatabaseUrl(p, { CNS_DATABASE_URL: urlFor(RUNTIME_PROCESS_ROLES[p]), TEST_MIGRATOR_DB_PASSWORD: "m" }), /migrador/);
  }
});

test("TEST-CNS-1396 parseRuntimeEnvironment: enum cerrado LOCAL|DEV|STAGING (F-PR6-08); vacio, ausente u otro valor (incluido PRODUCTION) abortan", () => {
  for (const ok of ["LOCAL", "DEV", "STAGING"] as const) assert.equal(parseRuntimeEnvironment(ok), ok);
  for (const bad of [undefined, "", "local", "PRODUCTION", "PROD", " LOCAL"]) assert.throws(() => parseRuntimeEnvironment(bad), ProcessRoleError, String(bad));
});

test("TEST-CNS-1396 cada entrypoint rechaza el rol equivocado antes de conectar (platform, worker, verifier): ProcessRoleError, sin pool ni socket", async () => {
  const wrong = (role: string) => ({ CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: urlFor(role) });
  // platform solo acepta platform_rw
  for (const role of ["app_rw", "worker", "integrity_verifier", "consent_migrator"]) {
    await assert.rejects(() => startPlatformProcess({ env: wrong(role), port: 0 }), ProcessRoleError, `platform con ${role}`);
  }
  // worker solo acepta worker
  for (const role of ["app_rw", "platform_rw", "integrity_verifier", "consent_migrator"]) {
    await assert.rejects(() => startWorkerProcess({ env: wrong(role) }), ProcessRoleError, `worker con ${role}`);
  }
  // verifier solo acepta integrity_verifier (config valida para llegar hasta la apertura del pool)
  const verifierEnv = (role: string) => ({
    ...wrong(role),
    CNS_VERIFIER_ISSUER: "https://idp.synthetic.invalid",
    CNS_VERIFIER_AUDIENCE: "consent-app-synthetic",
    CNS_VERIFIER_MAX_AUTH_AGE_SECONDS: "300",
    CNS_VERIFIER_SUB_HMAC_KEY_HEX: "ab".repeat(32),
  });
  for (const role of ["app_rw", "platform_rw", "worker", "consent_migrator"]) {
    await assert.rejects(() => startVerifierProcess({ env: verifierEnv(role) }), ProcessRoleError, `verifier con ${role}`);
  }
  // environment fuera del enum: ninguno arranca
  await assert.rejects(() => startPlatformProcess({ env: { CNS_ENVIRONMENT: "PRODUCTION", CNS_DATABASE_URL: urlFor("platform_rw") }, port: 0 }), ProcessRoleError);
  await assert.rejects(() => startWorkerProcess({ env: { CNS_ENVIRONMENT: "", CNS_DATABASE_URL: urlFor("worker") } }), ProcessRoleError);
});

test("TEST-CNS-1396 INV-DBR-02 (P1-1 de la revision de #92): ?user=, ?password=, options, host por query, protocolo ajeno y PGOPTIONS/PGUSER/PGPASSWORD/PGSERVICE en el entorno fallan cerrado", () => {
  const base = "postgresql://worker:s3cr3t-pw@127.0.0.1:1/db";
  const bad = [
    `${base}?user=consent_owner`,
    `${base}?options=-c%20role%3Dworker`,
    `${base}?password=otra`,
    `${base}?host=otro-host`,
    `${base}?sslmode=require&user=consent_owner`,
    "http://worker:x@h/db",
    "mysql://worker:x@h/db",
  ];
  for (const url of bad) {
    assert.throws(() => readProcessDatabaseUrl("worker", { CNS_DATABASE_URL: url }), (e: unknown) => e instanceof ProcessRoleError && !String(e.message).includes("s3cr3t-pw"), url);
  }
  // Allowlist: sslmode, sslrootcert, connect_timeout.
  const ok = `${base}?sslmode=require&connect_timeout=5`;
  assert.equal(readProcessDatabaseUrl("worker", { CNS_DATABASE_URL: ok }), ok);
  for (const name of ["PGOPTIONS", "PGUSER", "PGPASSWORD", "PGSERVICE"]) {
    assert.throws(() => readProcessDatabaseUrl("worker", { CNS_DATABASE_URL: base, [name]: "x" }), (e: unknown) => e instanceof ProcessRoleError && e.message.includes(name), name);
    process.env[name] = "-c role=consent_owner";
    try {
      assert.throws(() => readProcessDatabaseUrl("worker", { CNS_DATABASE_URL: base }), (e: unknown) => e instanceof ProcessRoleError && e.message.includes(name), `process.env ${name}`);
    } finally {
      delete process.env[name];
    }
  }
  // El mismo saneamiento rige para el proceso web (store.ts).
  assert.throws(() => readRuntimeDatabaseUrl({ CNS_DATABASE_URL: "postgresql://app_rw:x@h/db?user=consent_owner" }), /query|parametro/);
  assert.throws(() => readRuntimeDatabaseUrl({ CNS_DATABASE_URL: "postgresql://app_rw:x@h/db", PGOPTIONS: "-c role=app_rw" }), /PGOPTIONS/);
});
