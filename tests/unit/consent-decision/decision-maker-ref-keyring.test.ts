// Gobierna: OPEN-CM-10 (common.spec.yaml), INV-CM-09 (rev. 4f), LEGAL DECISION decisionMakerRef (Carlos 2026-10-01).
// TEST-CNS-1238..TEST-CNS-1241 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";

import {
  createDecisionMakerRefKeyring,
  deriveDecisionMakerRef,
  loadDecisionMakerRefKeyring,
  recomputeDecisionMakerRef,
} from "../../../src/server/modules/consent-decision/decision-maker-ref.ts";

const TENANT = "11111111-1111-4111-8111-111111111111";
const EMAIL = "persona.sintetica@example.invalid";
const S2 = Buffer.alloc(32, 7);
const S3 = Buffer.alloc(32, 9);
const b64 = (b: Buffer): string => b.toString("base64");

test("TEST-CNS-1238 OPEN-CM-10: rotacion - ref nuevo con la version activa; evento viejo se recomputa con su version", () => {
  const before = createDecisionMakerRefKeyring(new Map([[2, S2]]), 2);
  const refOld = deriveDecisionMakerRef(before.active(), TENANT, EMAIL);
  const after = createDecisionMakerRefKeyring(new Map([[2, S2], [3, S3]]), 3);
  assert.equal(after.active().keyVersion, 3);
  const refNew = deriveDecisionMakerRef(after.active(), TENANT, EMAIL);
  assert.notEqual(refNew, refOld);
  assert.equal(recomputeDecisionMakerRef(after, { decisionMakerRef: refOld, decisionMakerRefKeyVersion: 2 }, TENANT, EMAIL), refOld);
  assert.equal(recomputeDecisionMakerRef(after, { decisionMakerRef: refNew, decisionMakerRefKeyVersion: 3 }, TENANT, EMAIL), refNew);
  assert.throws(() => createDecisionMakerRefKeyring(new Map([[2, S2], [3, Buffer.from(S2)]]), 3), /comparten secreto/, "rotar exige secreto distinto");
  assert.throws(() => createDecisionMakerRefKeyring(new Map([[2, S2]]), 3), /version activa/);
});

test("TEST-CNS-1239 OPEN-CM-10: version desconocida, ausente en el keyring o invalida -> el mismo error uniforme (fail-closed)", () => {
  const kr = createDecisionMakerRefKeyring(new Map([[2, S2], [4, S3]]), 4);
  const messages = new Set<string>();
  for (const payload of [{ decisionMakerRefKeyVersion: 3 }, { decisionMakerRefKeyVersion: 99 }, { decisionMakerRefKeyVersion: 1 }, { decisionMakerRefKeyVersion: "2" }, { decisionMakerRefKeyVersion: null }]) {
    try {
      recomputeDecisionMakerRef(kr, payload, TENANT, EMAIL);
      assert.fail("debio fallar");
    } catch (e) {
      messages.add((e as Error).message);
    }
  }
  assert.equal(messages.size, 1, "mismo mensaje: no revela que versiones existen");
  assert.throws(() => kr.keyFor(undefined), /no disponible/);
  assert.throws(() => kr.keyFor(3), /no disponible/);
});

test("TEST-CNS-1240 OPEN-CM-10: evento sin el campo se lee como v2 (keyring con v2) y falla cerrado si el keyring ya no tiene v2", () => {
  const kr = createDecisionMakerRefKeyring(new Map([[2, S2], [3, S3]]), 3);
  const ref2 = deriveDecisionMakerRef(kr.keyFor(2), TENANT, EMAIL);
  assert.equal(recomputeDecisionMakerRef(kr, { decisionMakerRef: ref2 }, TENANT, EMAIL), ref2);
  const only3 = createDecisionMakerRefKeyring(new Map([[3, S3]]), 3);
  assert.throws(() => recomputeDecisionMakerRef(only3, { decisionMakerRef: ref2 }, TENANT, EMAIL), /no disponible/);
});

test("TEST-CNS-1241 OPEN-CM-10: config por entorno (compat. una clave, versionada, LOCAL sintetica, fail-closed) y las claves nunca aparecen en errores ni en serializacion", () => {
  // Compat: solo CNS_DECISION_MAKER_REF_SECRET -> {2} activo 2.
  const single = loadDecisionMakerRefKeyring({ CNS_DECISION_MAKER_REF_SECRET: b64(S2) }, "STAGING");
  assert.equal(single.active().keyVersion, 2);
  assert.equal(deriveDecisionMakerRef(single.active(), TENANT, EMAIL), deriveDecisionMakerRef(createDecisionMakerRefKeyring(new Map([[2, S2]]), 2).active(), TENANT, EMAIL));
  // Versionada.
  const env = { CNS_DECISION_MAKER_REF_SECRET: b64(S2), CNS_DECISION_MAKER_REF_SECRET_V3: b64(S3), CNS_DECISION_MAKER_REF_ACTIVE_VERSION: "3" };
  const multi = loadDecisionMakerRefKeyring(env, "STAGING");
  assert.equal(multi.active().keyVersion, 3);
  assert.equal(multi.keyFor(2).keyVersion, 2);
  // LOCAL sin nada: v2 sintetica; LOCAL con activa 3 sin secreto: sintetica de dev.
  assert.equal(loadDecisionMakerRefKeyring({}, "LOCAL").active().keyVersion, 2);
  assert.equal(loadDecisionMakerRefKeyring({ CNS_DECISION_MAKER_REF_ACTIVE_VERSION: "3" }, "LOCAL").active().keyVersion, 3);
  // Fail-closed.
  const leaky: Array<() => unknown> = [
    () => loadDecisionMakerRefKeyring({}, "STAGING"),
    () => loadDecisionMakerRefKeyring({ CNS_DECISION_MAKER_REF_ACTIVE_VERSION: "3" }, "STAGING"),
    () => loadDecisionMakerRefKeyring({ CNS_DECISION_MAKER_REF_SECRET: b64(S2), CNS_DECISION_MAKER_REF_SECRET_V3: b64(S3) }, "STAGING"),
    () => loadDecisionMakerRefKeyring({ ...env, CNS_DECISION_MAKER_REF_ACTIVE_VERSION: "4" }, "STAGING"),
    () => loadDecisionMakerRefKeyring({ ...env, CNS_DECISION_MAKER_REF_SECRET_V3: b64(Buffer.alloc(8, 5)) }, "STAGING"),
    () => loadDecisionMakerRefKeyring({ ...env, CNS_DECISION_MAKER_REF_SECRET_V3: b64(S2) }, "STAGING"),
    () => loadDecisionMakerRefKeyring({ ...env, CNS_DECISION_MAKER_REF_SECRET_V2: b64(S3) }, "STAGING"),
    () => loadDecisionMakerRefKeyring({ ...env, CNS_DECISION_MAKER_REF_ACTIVE_VERSION: "x" }, "STAGING"),
    () => recomputeDecisionMakerRef(multi, { decisionMakerRefKeyVersion: 7 }, TENANT, EMAIL),
  ];
  const secretsText = [b64(S2), b64(S3), S2.toString("hex"), S3.toString("hex"), b64(Buffer.alloc(8, 5))];
  for (const f of leaky) {
    assert.throws(f, (e: Error) => {
      for (const t of secretsText) assert.ok(!e.message.includes(t) && !(e.stack ?? "").includes(t), "el error no contiene secretos");
      return /fail-closed|no disponible/.test(e.message);
    });
  }
  // Serializacion / inspeccion del keyring no filtra secretos ni claves derivadas.
  const dump = JSON.stringify(multi) + String(multi) + JSON.stringify(Object.keys(multi));
  for (const t of [b64(S2), b64(S3), S2.toString("hex"), S3.toString("hex"), multi.active().key.toString("hex"), multi.active().key.toString("base64")]) {
    assert.ok(!dump.includes(t));
  }
});
