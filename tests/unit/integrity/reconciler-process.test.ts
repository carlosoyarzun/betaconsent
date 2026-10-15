// Gobierna: ADR-010 rev. 5 §2 (proceso `reconciler` = rol `integrity_reconciler`, G-9, F-PR6-29), INV-DBR-02 (cada proceso arranca solo con su rol exacto), §4.2.c.
// TEST-CNS-1607: el entrypoint reconciler rechaza el rol equivocado, el migrador, el superusuario, la URL con query de identidad y PGOPTIONS ANTES de conectar (ProcessRoleError, sin pool ni socket),
// y el contrato del mapa proceso -> rol. Sin Postgres. SYNTHETIC ONLY.

import test from "node:test";
import assert from "node:assert/strict";

import { expectedRoleFor, ProcessRoleError, readProcessDatabaseUrl, RUNTIME_PROCESS_ROLES } from "../../../src/infra/adapters/postgres/runtime-process.ts";
import { RUNTIME_ROLES } from "../../../src/infra/adapters/postgres/role-membership.ts";
import { PLATFORM_RUNTIME_EXECUTE } from "../../../src/infra/adapters/postgres/startup-checks.ts";
import { startReconcilerProcess } from "../../../src/server/entrypoints/reconciler/reconciler-process.ts";

const urlFor = (role: string): string => `postgresql://${role}:s3cr3t-pw@127.0.0.1:1/db`;

test("TEST-CNS-1607 reconciler = integrity_reconciler y es un rol de runtime gobernado (membresias y EXECUTE de platform vacio)", () => {
  assert.equal(RUNTIME_PROCESS_ROLES.reconciler, "integrity_reconciler");
  assert.equal(expectedRoleFor("reconciler"), "integrity_reconciler");
  assert.ok(RUNTIME_ROLES.includes("integrity_reconciler"));
  assert.deepEqual(PLATFORM_RUNTIME_EXECUTE.integrity_reconciler, []);
  assert.notEqual(RUNTIME_PROCESS_ROLES.reconciler, RUNTIME_PROCESS_ROLES.verifier, "el reconciler NO usa el rol del verifier (P2(e))");
});

test("TEST-CNS-1607 el reconciler solo acepta su rol: otro rol de runtime (incluido integrity_verifier), el migrador, un owner y el superusuario fallan cerrado sin filtrar la credencial", async () => {
  for (const role of ["app_rw", "platform_rw", "worker", "integrity_verifier", "consent_migrator", "consent_owner", "ledger_writer", "postgres"]) {
    assert.throws(
      () => readProcessDatabaseUrl("reconciler", { CNS_DATABASE_URL: urlFor(role) }),
      (e: unknown) => e instanceof ProcessRoleError && e.code === "PROCESS_ROLE_MISMATCH" && !String(e.message).includes("s3cr3t-pw") && !String(e.message).includes("postgresql://"),
      role,
    );
    await assert.rejects(() => startReconcilerProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: urlFor(role) } }), ProcessRoleError, `reconciler con ${role}`);
  }
  // Los demas procesos tampoco aceptan el rol del reconciler.
  for (const p of ["web", "platform", "worker", "verifier"] as const) {
    assert.throws(() => readProcessDatabaseUrl(p, { CNS_DATABASE_URL: urlFor("integrity_reconciler") }), ProcessRoleError, p);
  }
});

test("TEST-CNS-1607 URL con query de identidad (?user=, ?options=, ?host=), PGOPTIONS/PGUSER en el entorno, variables del migrador y CNS_ENVIRONMENT invalido abortan el arranque del reconciler antes de conectar", async () => {
  const base = urlFor("integrity_reconciler");
  for (const url of [`${base}?user=consent_owner`, `${base}?options=-c%20role%3Dintegrity_reconciler`, `${base}?password=otra`, `${base}?host=otro-host`, "http://integrity_reconciler:x@h/db"]) {
    await assert.rejects(() => startReconcilerProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: url } }), ProcessRoleError, url);
  }
  for (const extra of [{ PGOPTIONS: "-c app.tenant_id=x" }, { PGUSER: "postgres" }, { PGPASSWORD: "x" }, { CNS_MIGRATOR_DATABASE_URL: "postgresql://consent_migrator:x@h/db" }]) {
    await assert.rejects(() => startReconcilerProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: base, ...extra } }), ProcessRoleError, Object.keys(extra)[0]);
  }
  for (const env of [undefined, "", "PRODUCTION", "local"]) {
    await assert.rejects(() => startReconcilerProcess({ env: { ...(env === undefined ? {} : { CNS_ENVIRONMENT: env }), CNS_DATABASE_URL: base } }), ProcessRoleError, String(env));
  }
  await assert.rejects(() => startReconcilerProcess({ env: { CNS_ENVIRONMENT: "LOCAL" } }), ProcessRoleError, "sin CNS_DATABASE_URL");
});
