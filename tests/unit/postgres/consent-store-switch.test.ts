// Gobierna: CA-124 (PR-E), postgres-design.md rev. 2 §7 y §4 (arranque), SEC-CNS-016, ADR-001 §11.
// TEST-CNS-871: CONSENT_STORE fail-closed (ausente/invalido fuera de LOCAL no arranca; LOCAL -> memory);
// credencial solo por entorno y nunca la del migrador; los puertos "fuera de tx" de Postgres rechazan.
// Sin Postgres.

import test from "node:test";
import assert from "node:assert/strict";

import { resolveConsentStoreMode } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { createForbiddenOutsideTxPorts, OutsideTransactionError, readRuntimeDatabaseUrl } from "../../../src/infra/adapters/postgres/store.ts";

test("TEST-CNS-871 resolveConsentStoreMode: LOCAL sin valor = memory; fuera de LOCAL sin valor o invalido lanza; memory|postgres validos", () => {
  assert.equal(resolveConsentStoreMode(undefined, "LOCAL"), "memory");
  assert.equal(resolveConsentStoreMode("", "LOCAL"), "memory");
  assert.equal(resolveConsentStoreMode("postgres", "LOCAL"), "postgres");
  assert.throws(() => resolveConsentStoreMode("memory", "STAGING"), /solo se admite en LOCAL/);
  assert.throws(() => resolveConsentStoreMode("memory", undefined), /solo se admite en LOCAL/);
  assert.equal(resolveConsentStoreMode("postgres", "STAGING"), "postgres");
  assert.throws(() => resolveConsentStoreMode(undefined, "STAGING"), /obligatorio/);
  assert.throws(() => resolveConsentStoreMode(undefined, undefined), /obligatorio/);
  assert.throws(() => resolveConsentStoreMode("", "PRODUCTION"), /obligatorio/);
  assert.throws(() => resolveConsentStoreMode("sqlite", "LOCAL"), /inválido/);
  assert.throws(() => resolveConsentStoreMode("Postgres", "LOCAL"), /inválido/);
});

test("TEST-CNS-871 readRuntimeDatabaseUrl: exige CNS_DATABASE_URL, rechaza el rol migrador/superusuario/owner y variables *MIGRATOR*; nunca devuelve la credencial en el mensaje", () => {
  assert.throws(() => readRuntimeDatabaseUrl({}), /CNS_DATABASE_URL/);
  assert.throws(() => readRuntimeDatabaseUrl({ CNS_DATABASE_URL: "no es url" }), /no es una URL/);
  for (const role of ["consent_migrator", "postgres", "consent_owner"]) {
    assert.throws(() => readRuntimeDatabaseUrl({ CNS_DATABASE_URL: `postgresql://${role}:s3cr3t-pw@h/db` }), (e: unknown) => /rol de runtime/.test(String(e)) && !String(e).includes("s3cr3t-pw"));
  }
  assert.throws(() => readRuntimeDatabaseUrl({ CNS_DATABASE_URL: "postgresql://app_rw:x@h/db", TEST_MIGRATOR_DB_PASSWORD: "m" }), /migrador/);
  assert.equal(readRuntimeDatabaseUrl({ CNS_DATABASE_URL: "postgresql://app_rw:x@h/db" }), "postgresql://app_rw:x@h/db");
});

test("TEST-CNS-871 los puertos fuera de tx de Postgres rechazan todo acceso (OutsideTransactionError)", async () => {
  const o = createForbiddenOutsideTxPorts();
  await assert.rejects(() => o.invitationRepo.findByRef("t", "r"), OutsideTransactionError);
  await assert.rejects(() => o.ledger.append({} as never), OutsideTransactionError);
  await assert.rejects(() => o.tenantCatalog.subjectBelongsToTenant("t", "s"), OutsideTransactionError);
  await assert.rejects(() => o.idempotency.find("t", "h"), OutsideTransactionError);
});
