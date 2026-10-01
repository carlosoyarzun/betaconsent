// Gobierna: CA-124 (H09), ADR-006 §1/§4-§6, diseño de CA-124 P1-1.
// TEST-CNS-740 (adquisición limpia) y TEST-CNS-742 (rollback/retry/release) con dobles de pg;
// propuestos TEST-CNS-710/712 en el diseño. Sin Postgres.

import test from "node:test";
import assert from "node:assert/strict";
import { acquireCleanClient, TenantContextLeakError } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { FakeClient, fakePool, sqlError } from "./fakes.ts";

const TENANT = "11111111-1111-4111-8111-111111111111";

test("TEST-CNS-740 acquireCleanClient devuelve la conexión si app.tenant_id está vacío o NULL", async () => {
  for (const value of [null, ""]) {
    const client = new FakeClient();
    client.tenantSetting = value;
    const got = await acquireCleanClient(fakePool([client]));
    assert.equal(got, client.asPoolClient());
    assert.deepEqual(client.releases, []);
  }
});

test("TEST-CNS-740 acquireCleanClient destruye la conexión con app.tenant_id residual y falla cerrado", async () => {
  const client = new FakeClient();
  client.tenantSetting = TENANT;
  await assert.rejects(() => acquireCleanClient(fakePool([client])), TenantContextLeakError);
  assert.deepEqual(client.releases, [true]);
});

test("TEST-CNS-740 acquireCleanClient destruye la conexión si la verificación misma falla", async () => {
  const client = new FakeClient();
  client.query = () => Promise.reject(new Error("conexión rota"));
  await assert.rejects(() => acquireCleanClient(fakePool([client])), /conexión rota/);
  assert.deepEqual(client.releases, [true]);
});

test("TEST-CNS-742 inTenant: BEGIN, set_config local como primer statement, trabajo, COMMIT, release(false)", async () => {
  const client = new FakeClient();
  const uow = new PgUnitOfWork(fakePool([client]));
  const result = await uow.withTenantTx(TENANT, async (tx) => {
    await tx.query("SELECT 1");
    return "ok";
  });
  assert.equal(result, "ok");
  const texts = client.queries.map((q) => q.text);
  assert.equal(texts[0]?.includes("current_setting('app.tenant_id'"), true);
  assert.deepEqual(texts.slice(1), ["BEGIN", "SELECT set_config('app.tenant_id', $1, true)", "SELECT 1", "COMMIT"]);
  assert.deepEqual(client.queries[2]?.values, [TENANT]);
  assert.deepEqual(client.releases, [false]);
});

test("TEST-CNS-742 inTenant: error del trabajo hace ROLLBACK, propaga y devuelve la conexión", async () => {
  const client = new FakeClient();
  const uow = new PgUnitOfWork(fakePool([client]));
  await assert.rejects(
    () => uow.withTenantTx(TENANT, () => Promise.reject(new Error("boom"))),
    /boom/,
  );
  assert.equal(client.queries.at(-1)?.text, "ROLLBACK");
  assert.deepEqual(client.releases, [false]);
});

test("TEST-CNS-742 inTenant: si el ROLLBACK falla la conexión se destruye (release(true))", async () => {
  const client = new FakeClient((text) => (text === "ROLLBACK" ? new Error("conexión perdida") : undefined));
  const uow = new PgUnitOfWork(fakePool([client]));
  await assert.rejects(
    () => uow.withTenantTx(TENANT, () => Promise.reject(new Error("boom"))),
    /boom/,
  );
  assert.deepEqual(client.releases, [true]);
});

test("TEST-CNS-742 inTenant: si el COMMIT falla se hace ROLLBACK y, si también falla, release(true)", async () => {
  const client = new FakeClient((text) => (text === "COMMIT" || text === "ROLLBACK" ? new Error("caída") : undefined));
  const uow = new PgUnitOfWork(fakePool([client]));
  await assert.rejects(() => uow.withTenantTx(TENANT, async () => 1), /caída/);
  assert.deepEqual(client.releases, [true]);
});

test("TEST-CNS-742 inTenant reintenta 40001/40P01 hasta 3 intentos y luego propaga", async () => {
  const clients = [new FakeClient(), new FakeClient(), new FakeClient(), new FakeClient()];
  const pool = fakePool(clients);
  let calls = 0;
  const uow = new PgUnitOfWork(pool);
  const result = await uow.withTenantTx(TENANT, async () => {
    calls += 1;
    if (calls === 1) throw sqlError("40001");
    if (calls === 2) throw sqlError("40P01");
    return "tercer intento";
  });
  assert.equal(result, "tercer intento");
  assert.equal(calls, 3);

  calls = 0;
  const failing = new PgUnitOfWork(fakePool([new FakeClient()]));
  await assert.rejects(
    () =>
      failing.withTenantTx(TENANT, async () => {
        calls += 1;
        throw sqlError("40001");
      }),
    (error: unknown) => (error as { code?: string }).code === "40001",
  );
  assert.equal(calls, 3);
});

test("TEST-CNS-742 inTenant no reintenta errores no serializables", async () => {
  let calls = 0;
  const uow = new PgUnitOfWork(fakePool([new FakeClient()]));
  await assert.rejects(() =>
    uow.withTenantTx(TENANT, async () => {
      calls += 1;
      throw sqlError("23505");
    }),
  );
  assert.equal(calls, 1);
});

test("TEST-CNS-742 inTenant rechaza un tenantId que no es UUID sin tocar la conexión", async () => {
  const pool = fakePool([new FakeClient()]);
  const uow = new PgUnitOfWork(pool);
  await assert.rejects(() => uow.withTenantTx("no-es-uuid'; DROP", async () => 1), TypeError);
  assert.equal(pool.connects, 0);
});

test("TEST-CNS-742 la tx entregada al trabajo deja de funcionar al terminar", async () => {
  const uow = new PgUnitOfWork(fakePool([new FakeClient()]));
  const leaked = await uow.withTenantTx(TENANT, async (tx) => tx);
  await assert.rejects(() => leaked.query("SELECT 1"), /ya terminó/);
});
