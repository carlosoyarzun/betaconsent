// Gobierna: CA-124 (H09), SEC-CNS-017 P2 (condicion antes de salir de LOCAL). TEST-CNS-888: pg-pool quita el listener
// de 'error' del cliente al prestarlo; si Postgres mata la sesion con el cliente prestado y sin query en curso, el
// 'error' sin listener tumbaba el proceso. guardBorrowedClient registra un listener propio, marca el cliente roto,
// lo destruye al liberar y no acumula listeners en conexiones reusadas. Requiere Postgres real (harness.ts).

import assert from "node:assert/strict";

import { acquireCleanClient, createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY, LOCAL_ONLY_DEV_TENANT_ID } from "../../../src/server/entrypoints/dev-local-config.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { pgTest } from "./harness.ts";

const T = LOCAL_ONLY_DEV_TENANT_ID;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

pgTest("TEST-CNS-888 pg: sesion matada con el cliente prestado (sin query en curso) no tumba el proceso; la unidad falla y la siguiente tx funciona", async (ctx) => {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  const admin = await ctx.connectAsSuperuser();
  const realConsoleError = console.error;
  const logged: string[] = [];
  console.error = (...args: unknown[]) => void logged.push(args.map(String).join(" "));
  try {
    const uow = new PgUnitOfWork(pool, { maxAttempts: 1, idempotencyPolicy: loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY) });
    await assert.rejects(() =>
      uow.withTenantTx(T, async (tx) => {
        const pid = (await tx.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]?.pid;
        await admin.query("SELECT pg_terminate_backend($1)", [pid]);
        await sleep(300); // 'error' llega con el cliente prestado y sin query en curso
        return tx.query("SELECT 1");
      }),
    );
    assert.ok(logged.some((l) => l.startsWith("pg_borrowed_client_error name=")), "se registro el error (solo name/code)");
    assert.ok(logged.every((l) => !/terminat|administrator/i.test(l)), "el log no incluye el mensaje del servidor");
    // La conexion rota se destruyo: la siguiente tx obtiene una sana y funciona.
    assert.equal(await uow.withTenantTx(T, async (tx) => (await tx.query<{ one: number }>("SELECT 1 AS one")).rows[0]?.one), 1);
  } finally {
    console.error = realConsoleError;
    await pool.end();
  }
});

pgTest("TEST-CNS-888 pg: el listener de error se quita al liberar (sin acumulacion en la misma conexion fisica)", async (ctx) => {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
  try {
    const counts: number[] = [];
    for (let i = 0; i < 3; i++) {
      const client = await acquireCleanClient(pool);
      counts.push((client as unknown as { listenerCount(e: string): number }).listenerCount("error"));
      client.release();
    }
    assert.deepEqual(counts, [counts[0], counts[0], counts[0]]);
    assert.ok((counts[0] ?? 0) >= 1, "hay un listener propio mientras esta prestado");
  } finally {
    await pool.end();
  }
});
