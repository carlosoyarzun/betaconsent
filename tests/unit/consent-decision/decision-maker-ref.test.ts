// Gobierna: CA-128, LEGAL DECISION decisionMakerRef -> hash con clave (Carlos, 2026-10-01). TEST-CNS-930
// (derivacion HMAC, no recuperable por SHA-256 simple) y TEST-CNS-931 (secreto fail-closed, claves separadas).

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  deriveDecisionMakerRef,
  deriveDecisionMakerRefKey,
  loadDecisionMakerRefSecret,
} from "../../../src/server/modules/consent-decision/decision-maker-ref.ts";
import { deriveChainRef, deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";

const KEY = deriveDecisionMakerRefKey(Buffer.alloc(32, 1));
const EMAIL = "persona.sintetica@example.invalid";

test("TEST-CNS-930 decisionMakerRef: UUIDv4 desde HMAC, determinista con email normalizado, sin '@', <=100, no coincide con sha256(email) y cambia con la clave", () => {
  const ref = deriveDecisionMakerRef(KEY, EMAIL);
  assert.match(ref, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, "Ref UUIDv4 del contrato");
  assert.ok(ref.length <= 100 && !ref.includes("@"));
  assert.equal(ref, deriveDecisionMakerRef(KEY, `  ${EMAIL.toUpperCase()} `), "mismo email normalizado -> mismo ref");
  assert.notEqual(ref, deriveDecisionMakerRef(KEY, "otra.persona@example.invalid"));
  const sha = createHash("sha256").update(EMAIL).digest("hex");
  assert.ok(!ref.replaceAll("-", "").includes(sha.slice(0, 16)), "el ref no coincide con sha256(email), ni truncado");
  assert.notEqual(ref, deriveDecisionMakerRef(KEY, "persona.sintetica@example.invalid.x"), "sin colision trivial");
  assert.notEqual(ref, deriveDecisionMakerRef(deriveDecisionMakerRefKey(Buffer.alloc(32, 2)), EMAIL), "otra clave -> otro ref");
  // chainRef sigue cumpliendo el CHECK de largo con el nuevo decisionMakerRef (semantica de cadena intacta).
  const chainKey = deriveChainRefKey(Buffer.alloc(32, 1));
  const chain = deriveChainRef(chainKey, "t", "c", "s", ref);
  assert.ok(chain.length <= 100);
  assert.equal(chain, deriveChainRef(chainKey, "t", "c", "s", ref));
});

test("TEST-CNS-931 CNS_DECISION_MAKER_REF_SECRET: fuera de LOCAL sin secreto aborta (fail-closed), LOCAL usa constante, secreto corto se rechaza y la clave es distinta de la de chainRef", () => {
  assert.throws(() => loadDecisionMakerRefSecret({}, "STAGING"), /fail-closed/);
  assert.throws(() => loadDecisionMakerRefSecret({}, "PRODUCTION"), /fail-closed/);
  assert.throws(() => loadDecisionMakerRefSecret({ CNS_DECISION_MAKER_REF_SECRET: "" }, "STAGING"), /fail-closed/);
  assert.deepEqual(loadDecisionMakerRefSecret({}, "LOCAL"), loadDecisionMakerRefSecret({}, "LOCAL"));
  assert.throws(() => loadDecisionMakerRefSecret({ CNS_DECISION_MAKER_REF_SECRET: "c2hvcnQ=" }, "LOCAL"), /32 bytes/);
  assert.equal(loadDecisionMakerRefSecret({ CNS_DECISION_MAKER_REF_SECRET: Buffer.alloc(32, 3).toString("base64") }, "STAGING").length, 32);
  assert.throws(() => deriveDecisionMakerRefKey(Buffer.alloc(8)), /32 bytes/);
  const root = Buffer.alloc(32, 5);
  assert.notDeepEqual(deriveDecisionMakerRefKey(root), deriveChainRefKey(root), "HKDF info separado");
});
