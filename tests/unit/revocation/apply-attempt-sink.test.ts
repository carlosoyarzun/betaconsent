// Gobierna: DEC-BR-017 (ninguna via termina en denegacion; escala a humano), DEC-BR-006 (acuse != aplicada), REQ-CNS-033, ADR-010 rev. 5 §4.2.a (G-3), diseño F-PR6-25-2B-R9 rev. 2 §2 y correcciones C3/C6 de su revision de seguridad.
// 2B: sink de registro durable del intento no aplicado (src/server/modules/revocation/apply-guard.ts, adapter assertWebApplyGuard). Sin DB (el DDL queda pendiente: F-2B-DDL). TEST-CNS-1870..1873. SYNTHETIC ONLY.

import assert from "node:assert/strict";
import test from "node:test";

import { createApplyGuardConfig, assertWebApplyGuard } from "../../../src/infra/adapters/postgres/apply-guard.adapter.ts";
import { RevocationApplyUnavailableError, runBoundedApply } from "../../../src/server/modules/revocation/apply-guard.ts";
import type { ApplyAttemptInput, ApplyAttemptSink } from "../../../src/server/modules/revocation/apply-guard.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const T = fixtureUuid("t1870");
const REF = fixtureUuid("r1870");
const RECOVERY = fixtureUuid("rec1870");
const ATT = fixtureUuid("att1870");
const transient = (): Error => Object.assign(new Error("x"), { code: "40001" });
const TOKEN_HASH = "a".repeat(64);

function setup(opts: { sink?: ApplyAttemptSink; alert?: () => Promise<void> } = {}) {
  const order: string[] = [];
  const attempts: ApplyAttemptInput[] = [];
  const logs: string[] = [];
  const sink: ApplyAttemptSink = opts.sink ?? (async (i) => { order.push("attempt"); attempts.push(i); return "RECORDED"; });
  const cfg = createApplyGuardConfig(async () => { order.push("alert"); await opts.alert?.(); }, { maxAttempts: 3, sleep: async () => {}, log: (l) => logs.push(l), attemptSink: sink });
  return { cfg, order, attempts, logs };
}

test("TEST-CNS-1870 agotamiento: alerta y luego registro 2B en llamada separada, con el mismo attemptId, tries = maxAttempts y el error uniforme (nunca acuse)", async () => {
  const { cfg, order, attempts } = setup();
  await assert.rejects(
    runBoundedApply(cfg, { tenantId: T, revocationRef: () => REF, recoveryRef: () => RECOVERY, attemptId: ATT }, async () => { throw transient(); }, async () => null),
    RevocationApplyUnavailableError,
  );
  assert.deepEqual(order, ["alert", "attempt"]);
  assert.deepEqual(attempts, [{ tenantId: T, attemptId: ATT, attemptRef: REF, recoveryRef: RECOVERY, reason: "R4_RETRIES_EXHAUSTED", tries: 3 }]);
});

test("TEST-CNS-1871 independencia: alerta fallida no impide el registro; registro fallido no cambia el error y deja log sin PII con attempt_id, attempt_ref y recovery_ref (nunca el hash del token); un guard de dominio no registra; XX000 registra R4_APPLY_FAILED", async () => {
  const a = setup({ alert: async () => { throw new Error("alerta caida"); } });
  await assert.rejects(runBoundedApply(a.cfg, { tenantId: T, revocationRef: () => REF }, async () => { throw transient(); }, async () => null), RevocationApplyUnavailableError);
  assert.equal(a.attempts.length, 1, "el registro no depende de la alerta");

  const b = setup({ sink: async () => { throw new Error(`detalle con ${TOKEN_HASH}`); } });
  await assert.rejects(
    runBoundedApply(b.cfg, { tenantId: T, revocationRef: () => REF, recoveryRef: () => TOKEN_HASH, attemptId: ATT }, async () => { throw transient(); }, async () => null),
    RevocationApplyUnavailableError,
  );
  const line = b.logs.find((l) => l.startsWith("revocation_apply_attempt_unrecorded"));
  assert.ok(line !== undefined && line.includes(`attempt_id=${ATT}`) && line.includes(`attempt_ref=${REF}`) && line.includes("recovery_ref=invalid-ref"));
  assert.ok(!b.logs.join("\n").includes(TOKEN_HASH) && !b.logs.join("\n").includes("detalle"));

  const c = setup();
  const guard = new DomainError("ERR-RV-05", "x");
  await assert.rejects(runBoundedApply(c.cfg, { tenantId: T, revocationRef: () => REF }, async () => { throw guard; }, async () => null), (e) => e === guard);
  assert.equal(c.attempts.length, 0);

  const d = setup();
  const boom = Object.assign(new Error("x"), { code: "XX000" });
  await assert.rejects(runBoundedApply(d.cfg, { tenantId: T, revocationRef: () => REF }, async () => { throw boom; }, async () => null), (e) => e === boom);
  assert.deepEqual(d.attempts.map((x) => [x.reason, x.tries]), [["R4_APPLY_FAILED", 1]]);
});

test("TEST-CNS-1872 C3: un attemptId distinto por llamada a runBoundedApply (un POST = una fila) y commit ambiguo aplicado = sin registro", async () => {
  const { cfg, attempts } = setup();
  for (let i = 0; i < 2; i += 1) {
    await assert.rejects(runBoundedApply(cfg, { tenantId: T, revocationRef: () => REF }, async () => { throw transient(); }, async () => null), RevocationApplyUnavailableError);
  }
  assert.equal(attempts.length, 2);
  assert.notEqual(attempts[0]!.attemptId, attempts[1]!.attemptId);
  assert.match(attempts[0]!.attemptId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

  const applied = setup();
  const out = await runBoundedApply(applied.cfg, { tenantId: T, revocationRef: () => REF }, async () => { throw transient(); }, async () => "APPLIED");
  assert.equal(out, "APPLIED");
  assert.equal(applied.attempts.length, 0);
});

test("TEST-CNS-1873 C6: el web no arranca con la guardia sin ApplyAttemptSink; con sink pasa; platform (sin sink) no registra ni falla", async () => {
  const noSink = createApplyGuardConfig(async () => {});
  assert.throws(() => assertWebApplyGuard(noSink), /ApplyAttemptSink/);
  assert.equal(assertWebApplyGuard(setup().cfg).maxAttempts, 3);
  await assert.rejects(runBoundedApply({ ...noSink, sleep: async () => {} }, { tenantId: T, revocationRef: () => REF }, async () => { throw transient(); }, async () => null), RevocationApplyUnavailableError);
});
