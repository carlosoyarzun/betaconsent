// Gobierna: CA-128, LEGAL DECISION decisionMakerRef -> hash con clave (Carlos, 2026-10-01). TEST-CNS-930
// (derivacion HMAC, no recuperable por SHA-256 simple) y TEST-CNS-931 (secreto fail-closed, claves separadas).

import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, hkdfSync } from "node:crypto";

import {
  DECISION_MAKER_REF_KEY_VERSION,
  deriveDecisionMakerRef,
  deriveDecisionMakerRefKey,
  loadDecisionMakerRefSecret,
  normalizeChannelForRef,
} from "../../../src/server/modules/consent-decision/decision-maker-ref.ts";
import { uuidV4FromDigest } from "../../../src/server/modules/common/opaque-ref.ts";
import { deriveChainRef, deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";

const KEY = deriveDecisionMakerRefKey(Buffer.alloc(32, 1));
const TENANT = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";
const EMAIL = "persona.sintetica@example.invalid";

test("TEST-CNS-930 decisionMakerRef: UUIDv4 desde HMAC, determinista con email normalizado, sin '@', <=100, no coincide con sha256(email) y cambia con la clave", () => {
  const ref = deriveDecisionMakerRef(KEY, TENANT, EMAIL);
  assert.match(ref, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, "Ref UUIDv4 del contrato");
  assert.ok(ref.length <= 100 && !ref.includes("@"));
  assert.equal(ref, deriveDecisionMakerRef(KEY, TENANT, `  ${EMAIL.toUpperCase()} `), "mismo email normalizado -> mismo ref");
  assert.notEqual(ref, deriveDecisionMakerRef(KEY, TENANT, "otra.persona@example.invalid"));
  const sha = createHash("sha256").update(EMAIL).digest("hex");
  assert.ok(!ref.replaceAll("-", "").includes(sha.slice(0, 16)), "el ref no coincide con sha256(email), ni truncado");
  assert.notEqual(ref, deriveDecisionMakerRef(KEY, TENANT, "persona.sintetica@example.invalid.x"), "sin colision trivial");
  assert.notEqual(ref, deriveDecisionMakerRef(deriveDecisionMakerRefKey(Buffer.alloc(32, 2)), TENANT, EMAIL), "otra clave -> otro ref");
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

// CA-128, LEGAL DECISION Carlos 2026-10-01, (a) por tenant (KEY_VERSION 2).
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test("TEST-CNS-1050 decisionMakerRef por tenant: mismo sujeto y mismo tenant -> mismo ref (determinista), UUIDv4 valido", () => {
  const a = deriveDecisionMakerRef(KEY, TENANT, EMAIL);
  assert.equal(a, deriveDecisionMakerRef(KEY, TENANT, `  ${EMAIL.toUpperCase()} `));
  assert.match(a, UUID_V4);
});

test("TEST-CNS-1051 decisionMakerRef por tenant: mismo sujeto en tenants distintos -> refs distintos", () => {
  assert.notEqual(deriveDecisionMakerRef(KEY, TENANT, EMAIL), deriveDecisionMakerRef(KEY, TENANT_B, EMAIL));
  assert.notEqual(deriveDecisionMakerRef(KEY, TENANT, "ab@x.invalid"), deriveDecisionMakerRef(KEY, TENANT_B, "ab@x.invalid"));
});

test("TEST-CNS-1052 decisionMakerRef: KEY_VERSION 2 y el resultado difiere de la derivacion v1 (sin tenant, info v1)", () => {
  assert.equal(DECISION_MAKER_REF_KEY_VERSION, 2);
  const root = Buffer.alloc(32, 1);
  const v1Key = Buffer.from(hkdfSync("sha256", root, Buffer.alloc(0), "consent-app/decision-maker-ref/v1", 32));
  const v1 = uuidV4FromDigest(createHmac("sha256", v1Key).update(normalizeChannelForRef(EMAIL)).digest());
  assert.notEqual(deriveDecisionMakerRef(KEY, TENANT, EMAIL), v1);
  assert.notDeepEqual(deriveDecisionMakerRefKey(root), v1Key, "info HKDF v2 distinto de v1");
});

test("TEST-CNS-1053 decisionMakerRef: tenantId obligatorio (vacio o undefined lanza con el mensaje del guard; sin default)", () => {
  assert.throws(() => deriveDecisionMakerRef(KEY, "", EMAIL), /tenantId es obligatorio/);
  assert.throws(() => deriveDecisionMakerRef(KEY, undefined as unknown as string, EMAIL), /tenantId es obligatorio/);
});

test("TEST-CNS-1056 decisionMakerRef: tenantId debe ser Ref UUIDv4 en minusculas (fail-closed)", () => {
  assert.throws(() => deriveDecisionMakerRef(KEY, "tenant-1", EMAIL), /forma Ref UUIDv4/);
  assert.throws(() => deriveDecisionMakerRef(KEY, "C3A1F5D2-8B47-4E69-A0D3-5F7B9E1C2A48", EMAIL), /forma Ref UUIDv4/);
  assert.throws(() => deriveDecisionMakerRef(KEY, `${TENANT} `, EMAIL), /forma Ref UUIDv4/);
});

test("TEST-CNS-1057 decisionMakerRef: canal normalizado vacio se rechaza (fail-closed)", () => {
  assert.throws(() => deriveDecisionMakerRef(KEY, TENANT, ""), /canal normalizado vacio/);
  assert.throws(() => deriveDecisionMakerRef(KEY, TENANT, "   "), /canal normalizado vacio/);
});

test("TEST-CNS-1054 decisionMakerRef: los dos tenants sinteticos locales no colisionan para el mismo canal (los tests Postgres e2e usan ambos)", () => {
  const t1 = "c3a1f5d2-8b47-4e69-a0d3-5f7b9e1c2a48";
  const t2 = "5d2e8a1c-6b3f-4d97-9c04-7e1a3b5d9f20";
  assert.notEqual(deriveDecisionMakerRef(KEY, t1, EMAIL), deriveDecisionMakerRef(KEY, t2, EMAIL));
});
