// Gobierna: SEC-CNS-017 F8. TEST-CNS-885: runOnce fija lock_timeout/statement_timeout; el advisory lock de
// idempotencia no espera indefinidamente (la segunda unidad falla con 55P03 en ~lockTimeoutMs).

import assert from "node:assert/strict";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY, LOCAL_ONLY_DEV_TENANT_ID } from "../../../src/server/entrypoints/dev-local-config.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { pgTest } from "./harness.ts";

const T = LOCAL_ONLY_DEV_TENANT_ID;

pgTest("TEST-CNS-885 pg: SET LOCAL lock_timeout/statement_timeout activos en la tx y el advisory lock de idempotencia no espera indefinidamente", async (ctx) => {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
  try {
    const uow = new PgUnitOfWork(pool, { lockTimeoutMs: 300, statementTimeoutMs: 1500, maxAttempts: 1, idempotencyPolicy: loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY) });
    const settings = await uow.withTenantTx(T, async (tx) => (await tx.query<{ lt: string; st: string }>("SELECT current_setting('lock_timeout') AS lt, current_setting('statement_timeout') AS st")).rows[0]);
    assert.deepEqual(settings, { lt: "300ms", st: "1500ms" });

    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let locked!: () => void;
    const hasLock = new Promise<void>((r) => (locked = r));
    const holder = uow.inTenant(T, async (tx) => {
      await tx.idempotency.find(T, "scope-885-hash");
      locked();
      await held;
    });
    await hasLock;
    const started = Date.now();
    await assert.rejects(
      () => uow.inTenant(T, (tx) => tx.idempotency.find(T, "scope-885-hash")),
      (e: unknown) => (e as { code?: string }).code === "55P03",
    );
    assert.ok(Date.now() - started < 3000, "no espera indefinidamente");
    release();
    await holder;
  } finally {
    await pool.end();
  }
});
