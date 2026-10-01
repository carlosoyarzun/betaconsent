// Gobierna: ADR-002 §10 (chainRef opaco), SEC-CNS-017 F2. TEST-CNS-878.

import test from "node:test";
import assert from "node:assert/strict";

import { deriveChainRef, deriveChainRefKey, loadChainRefSecret } from "../../../src/server/modules/consent-decision/chain-ref.ts";

const KEY = deriveChainRefKey(Buffer.alloc(32, 1));
const TENANT = "11111111-1111-4111-8111-111111111111";
const SUBJECT = "22222222-2222-4222-8222-222222222222";

test("TEST-CNS-878: chainRef opaco, determinista, de largo fijo y sin tenantId/subjectRef/decisionMakerRef", () => {
  const a = deriveChainRef(KEY, TENANT, "LECTORPRO/BETA_2026_01", SUBJECT, "dm:abcdef0123456789abcdef0123456789");
  assert.equal(a, deriveChainRef(KEY, TENANT, "LECTORPRO/BETA_2026_01", SUBJECT, "dm:abcdef0123456789abcdef0123456789"));
  assert.match(a, /^chain:[0-9a-f]{64}$/);
  assert.ok(a.length <= 100);
  for (const leak of [TENANT, SUBJECT, "abcdef0123456789", "BETA_2026_01", "dm:"]) assert.ok(!a.includes(leak));
  assert.notEqual(a, deriveChainRef(KEY, TENANT, "LECTORPRO/BETA_2026_01", SUBJECT, "dm:otro"));
  assert.notEqual(a, deriveChainRef(deriveChainRefKey(Buffer.alloc(32, 2)), TENANT, "LECTORPRO/BETA_2026_01", SUBJECT, "dm:abcdef0123456789abcdef0123456789"));
  // Sin ambigüedad por concatenación.
  assert.notEqual(deriveChainRef(KEY, "a", "bc", "d", "e"), deriveChainRef(KEY, "ab", "c", "d", "e"));
});

test("TEST-CNS-878: clave fail-closed fuera de LOCAL; LOCAL usa constante estable; secreto corto aborta", () => {
  assert.throws(() => loadChainRefSecret({}, "STAGING"), /fail-closed/);
  assert.throws(() => loadChainRefSecret({}, "PRODUCTION"), /fail-closed/);
  assert.deepEqual(loadChainRefSecret({}, "LOCAL"), loadChainRefSecret({}, "LOCAL"));
  assert.throws(() => loadChainRefSecret({ CNS_CHAIN_REF_SECRET: "c2hvcnQ=" }, "LOCAL"), /32 bytes/);
  assert.equal(loadChainRefSecret({ CNS_CHAIN_REF_SECRET: Buffer.alloc(32, 3).toString("base64") }, "STAGING").length, 32);
  assert.throws(() => deriveChainRefKey(Buffer.alloc(8)), /32 bytes/);
});
