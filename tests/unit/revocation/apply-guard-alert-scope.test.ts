// Gobierna: ADR-010 rev. 5 (enmienda rev. c) §4.2.a puntos 4 y 5 (G-3); decision de Carlos 2026-10-16 (alcance, opcion A): alerta ante cualquier fallo que NO sea un guard de dominio al aplicar una revocacion, no solo al
// agotar reintentos; sin acuse de exito y sin PII; si la tx de alerta falla, log del proceso sin PII. src/server/modules/revocation/apply-guard.ts. TEST-CNS-1733. SYNTHETIC ONLY.

import assert from "node:assert/strict";
import test from "node:test";

import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { raiseApplyAlert, runBoundedApply } from "../../../src/server/modules/revocation/apply-guard.ts";
import type { ApplyAlertInput, ApplyGuardConfig } from "../../../src/server/modules/revocation/apply-guard.ts";
import { isDomainGuardError } from "../../../src/infra/adapters/postgres/apply-guard.adapter.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const REF = fixtureUuid("1733-ref");
const TENANT = fixtureUuid("t1733");
const pgError = (code: string, message: string): Error => Object.assign(new Error(message), { code });

function config(over: Partial<ApplyGuardConfig> = {}): { cfg: ApplyGuardConfig; alerts: ApplyAlertInput[]; logs: string[] } {
  const alerts: ApplyAlertInput[] = [];
  const logs: string[] = [];
  const cfg: ApplyGuardConfig = {
    maxAttempts: 3,
    backoffMs: () => 0,
    sleep: async () => {},
    isTransient: (e) => (e as { code?: string }).code === "40001",
    isDomainGuard: isDomainGuardError,
    alert: async (i) => {
      alerts.push(i);
    },
    log: (l) => logs.push(l),
    now: () => new Date("2026-10-16T00:00:00Z"),
    ...over,
  };
  return { cfg, alerts, logs };
}

test("TEST-CNS-1733 un fallo NO transitorio y NO guard (XX000) alerta R4_APPLY_FAILED una vez, sin reintentar, y propaga el error original (sin acuse)", async () => {
  const { cfg, alerts } = config();
  let calls = 0;
  const boom = pgError("XX000", "detalle con datos sensibles");
  await assert.rejects(
    runBoundedApply(cfg, { tenantId: TENANT, revocationRef: () => REF }, async () => { calls += 1; throw boom; }, async () => null),
    (e: unknown) => e === boom,
  );
  assert.equal(calls, 1);
  assert.deepEqual(alerts, [{ tenantId: TENANT, revocationRef: REF, reason: "R4_APPLY_FAILED" }]);
});

test("TEST-CNS-1733 un guard de dominio (DomainError o SQLSTATE RVxxx/RCxxx) NO alerta y se propaga", async () => {
  for (const error of [new DomainError("ERR-CM-06"), pgError("RV004", "x"), pgError("RC003", "x")]) {
    const { cfg, alerts } = config();
    await assert.rejects(
      runBoundedApply(cfg, { tenantId: TENANT, revocationRef: () => REF }, async () => { throw error; }, async () => null),
      (e: unknown) => e === error,
    );
    assert.deepEqual(alerts, []);
  }
});

test("TEST-CNS-1733 si la tx de alerta falla va al log del proceso SIN PII (ni mensaje del error ni tenant) y el error original igual se propaga", async () => {
  const { cfg, logs } = config({ alert: async () => { throw new Error("alerta caida: detalle sensible"); } });
  const boom = pgError("XX000", "detalle sensible del titular");
  await assert.rejects(
    runBoundedApply(cfg, { tenantId: TENANT, revocationRef: () => REF }, async () => { throw boom; }, async () => null),
    (e: unknown) => e === boom,
  );
  assert.deepEqual(logs, [`revocation_apply_alert reason=R4_APPLY_FAILED ref=${REF} at=2026-10-16T00:00:00.000Z persisted=false`]);
  assert.ok(logs.every((l) => !/sensible/.test(l) && !l.includes(TENANT)));
  assert.equal(await raiseApplyAlert(cfg, { tenantId: "x", revocationRef: "no-es-ref", reason: "R4_APPLY_FAILED" }), "LOGGED");
});

test("TEST-CNS-1733 un transitorio seguido de un fallo no transitorio alerta R4_APPLY_FAILED (no R4_RETRIES_EXHAUSTED)", async () => {
  const { cfg, alerts } = config();
  let n = 0;
  await assert.rejects(
    runBoundedApply(cfg, { tenantId: TENANT, revocationRef: () => REF }, async () => { n += 1; throw n === 1 ? pgError("40001", "t") : pgError("XX000", "x"); }, async () => null),
  );
  assert.deepEqual(alerts.map((a) => a.reason), ["R4_APPLY_FAILED"]);
});
