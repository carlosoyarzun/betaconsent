// Gobierna: ADR-010 rev. 6 §2 (C7: tenants=0 o events=0 dan exit 1 salvo el flag solo-LOCAL; una base vacia nunca da verde), §3 fila PR-6f, SEC-06-3, F-PR6E-06. SYNTHETIC ONLY.
// TEST-CNS-1759: en una base SIN eventos el entrypoint sale con exit 1 (name/code solamente); con CNS_CHAIN_VERIFIER_ALLOW_EMPTY=true y LOCAL sale con exit 0; el flag con otro CNS_ENVIRONMENT no arranca (exit 1).
// Archivo propio: el harness crea una base por archivo y el resto de los tests de PR-6f siembran el ledger. Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ChainVerifierEmptyLedgerError, startChainVerifierProcess } from "../../../src/server/entrypoints/chain-verifier/chain-verify-process.ts";
import { pgTest, type PgTestContext } from "./harness.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

function runMain(ctx: PgTestContext, extra: Record<string, string> = {}): { status: number | null; stdout: string; stderr: string } {
  const env = { PATH: process.env.PATH ?? "", CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: ctx.urlFor("integrity_chain_verifier"), ...extra };
  const r = spawnSync(process.execPath, [join(ROOT, "src/server/entrypoints/chain-verifier/main.ts")], { env, encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

pgTest("TEST-CNS-1759 pg: tenants=0/events=0 = exit 1 (no verde falso); ALLOW_EMPTY=true solo en LOCAL da exit 0; el flag fuera de LOCAL no arranca", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  assert.equal((await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM integrity.audit_event")).rows[0]?.n, 0, "base sin eventos");
  const url = ctx.urlFor("integrity_chain_verifier");
  const proc = await startChainVerifierProcess({ env: { CNS_ENVIRONMENT: "LOCAL", CNS_DATABASE_URL: url } });
  try {
    await assert.rejects(() => proc.run(), ChainVerifierEmptyLedgerError);
  } finally {
    await proc.stop();
  }
  const empty = runMain(ctx);
  assert.equal(empty.status, 1);
  assert.equal(empty.stdout, "");
  assert.equal(empty.stderr.trim(), "chain-verifier: no verifica (name=ChainVerifierEmptyLedgerError code=EMPTY_LEDGER)");

  const allowed = runMain(ctx, { CNS_CHAIN_VERIFIER_ALLOW_EMPTY: "true" });
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(allowed.stdout.trim(), "chain_verify_run ok=true tenants=0 events=0 broken=0 unchained=0");

  for (const environment of ["DEV", "STAGING"]) {
    const r = runMain(ctx, { CNS_CHAIN_VERIFIER_ALLOW_EMPTY: "true", CNS_ENVIRONMENT: environment });
    assert.equal(r.status, 1, environment);
    assert.equal(r.stderr.trim(), "chain-verifier: no verifica (name=ChainVerifierConfigError code=CHAIN_VERIFIER_CONFIG)");
  }
  // Sin eventos pero con tenants=0 por una policy que filtra todo: ya lo cubre TEST-CNS-1750 (la policy alterada es exit 1 antes de contar).
});
