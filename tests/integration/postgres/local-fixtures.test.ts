// Gobierna: CA-124 (H09), SEC-CNS-017 finding (c), DEC-BR-014 §4. TEST-CNS-879: el paso de fixtures LOCAL-only
// (db/fixtures/local, fuera de db/migrations) corre como consent_migrator (no superusuario), es idempotente,
// aborta si ops.db_catalog no es LOCAL/SYNTHETIC o CNS_ENVIRONMENT != LOCAL, y siembra el catalogo de dev.

import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { applyLocalFixtures, loadLocalFixtures, LocalFixtureError } from "../../../src/infra/adapters/postgres/local-fixtures.ts";
import {
  LOCAL_ONLY_DEV_OTHER_TENANT_ID,
  LOCAL_ONLY_DEV_PARTICIPATION_REF,
  LOCAL_ONLY_DEV_STAFF_SUBJECT_REF,
  LOCAL_ONLY_DEV_SUBJECT_REF,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { pgTest } from "./harness.ts";
import { MIGRATIONS_DIR } from "./harness.ts";

export const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "db", "fixtures", "local");

pgTest("TEST-CNS-879 pg: fixtures locales como consent_migrator siembran el catalogo de dev (idempotente) y restauran FORCE RLS", async (ctx) => {
  assert.notEqual(MIGRATIONS_DIR, FIXTURES_DIR, "las fixtures no viven en db/migrations");
  const fixtures = loadLocalFixtures(FIXTURES_DIR);
  assert.ok(fixtures.length >= 1);
  const migrator = await ctx.connectAs("consent_migrator");
  assert.deepEqual(await applyLocalFixtures(migrator, fixtures, { environment: "LOCAL" }), fixtures.map((f) => f.name));
  await applyLocalFixtures(migrator, fixtures, { environment: "LOCAL" }); // idempotente

  const admin = await ctx.connectAsSuperuser();
  const subjects = (await admin.query<{ tenant_id: string; subject_ref: string }>("SELECT tenant_id, subject_ref FROM app.subject")).rows;
  assert.equal(subjects.length, 3);
  const pairs = new Set(subjects.map((s) => `${s.tenant_id}/${s.subject_ref}`));
  for (const p of [
    `${LOCAL_ONLY_DEV_TENANT_ID}/${LOCAL_ONLY_DEV_SUBJECT_REF}`,
    `${LOCAL_ONLY_DEV_TENANT_ID}/${LOCAL_ONLY_DEV_STAFF_SUBJECT_REF}`,
    `${LOCAL_ONLY_DEV_OTHER_TENANT_ID}/${LOCAL_ONLY_DEV_STAFF_SUBJECT_REF}`,
  ]) assert.ok(pairs.has(p), p);
  const parts = (await admin.query<{ tenant_id: string; participation_ref: string; context_ref: string; product_ref: string; status: string }>("SELECT * FROM app.school_participation")).rows;
  assert.equal(parts.length, 2);
  for (const r of parts) {
    assert.equal(r.participation_ref, LOCAL_ONLY_DEV_PARTICIPATION_REF);
    assert.equal(r.context_ref, LECTORPRO_BETA_CONFIG.contextRef);
    assert.equal(r.product_ref, LECTORPRO_BETA_CONFIG.productRef);
    assert.equal(r.status, "ACTIVE");
  }
  const forced = (await admin.query<{ relname: string; relforcerowsecurity: boolean }>(
    "SELECT relname, relforcerowsecurity FROM pg_class WHERE oid IN ('app.subject'::regclass, 'app.school_participation'::regclass)",
  )).rows;
  assert.equal(forced.length, 2);
  for (const r of forced) assert.equal(r.relforcerowsecurity, true, `${r.relname} debe conservar FORCE RLS`);

  // app_rw sigue sin poder escribir el catalogo (el proceso web nunca lo siembra).
  const app = await ctx.connectAs("app_rw");
  await assert.rejects(() => app.query("INSERT INTO app.subject (tenant_id, subject_ref) VALUES ($1, 'x')", [LOCAL_ONLY_DEV_TENANT_ID]), (e: unknown) => (e as { code?: string }).code === "42501");
});

pgTest("TEST-CNS-879 pg: fail-closed fuera de LOCAL, como superusuario, o con ops.db_catalog que no es LOCAL", async (ctx) => {
  const fixtures = loadLocalFixtures(FIXTURES_DIR);
  const migrator = await ctx.connectAs("consent_migrator");
  const admin = await ctx.connectAsSuperuser();
  const before = (await admin.query("SELECT 1 FROM app.subject")).rows.length; // la base se comparte con el test anterior
  for (const environment of ["DEV", "STAGING", "PRODUCTION", ""]) {
    await assert.rejects(() => applyLocalFixtures(migrator, fixtures, { environment }), LocalFixtureError, `environment=${environment}`);
  }
  await assert.rejects(() => applyLocalFixtures(admin, fixtures, { environment: "LOCAL" }), LocalFixtureError, "superusuario");
  const app = await ctx.connectAs("app_rw");
  await assert.rejects(() => applyLocalFixtures(app, fixtures, { environment: "LOCAL" }), LocalFixtureError, "app_rw");
  assert.equal((await admin.query("SELECT 1 FROM app.subject")).rows.length, before, "nada sembrado");

  // El propio SQL aborta si el catalogo no es LOCAL (base de este archivo; el catalogo es inmutable salvo trigger).
  await admin.query("ALTER TABLE ops.db_catalog DISABLE TRIGGER USER");
  await admin.query("UPDATE ops.db_catalog SET environment = 'DEV'");
  await assert.rejects(() => applyLocalFixtures(migrator, fixtures, { environment: "LOCAL" }), (e: unknown) => /LOCAL\/SYNTHETIC/.test((e as Error).message));
  assert.equal((await admin.query("SELECT 1 FROM app.subject")).rows.length, before, "rollback completo");
});

pgTest("TEST-CNS-887 pg: las fixtures abortan si ops.db_catalog tiene 2 filas aunque una sea LOCAL/SYNTHETIC (count(*) = 1, no EXISTS)", async (ctx) => {
  const fixtures = loadLocalFixtures(FIXTURES_DIR);
  const migrator = await ctx.connectAs("consent_migrator");
  const admin = await ctx.connectAsSuperuser();
  // Base propia de este archivo: se rompe la restriccion de fila unica solo para fabricar el caso negativo.
  await admin.query("ALTER TABLE ops.db_catalog DISABLE TRIGGER USER");
  await admin.query("UPDATE ops.db_catalog SET environment = 'LOCAL'");
  await admin.query("ALTER TABLE ops.db_catalog DROP CONSTRAINT db_catalog_single_row");
  await admin.query("ALTER TABLE ops.db_catalog DROP CONSTRAINT db_catalog_pkey");
  await admin.query("INSERT INTO ops.db_catalog (environment) VALUES ('LOCAL')");
  const before = (await admin.query("SELECT 1 FROM app.subject")).rows.length;
  await assert.rejects(() => applyLocalFixtures(migrator, fixtures, { environment: "LOCAL" }), (e: unknown) => /exactamente una fila/.test((e as Error).message));
  assert.equal((await admin.query("SELECT 1 FROM app.subject")).rows.length, before, "rollback completo");
});
