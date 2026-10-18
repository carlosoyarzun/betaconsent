// Gobierna: ADR-001 rev. 8 F1 (fase B), contracts/openapi/consent-it0.openapi.yaml API-CNS-194 (GET /decision/page-state) y
// API-CNS-195 (GET /manage/page-state), contracts/schemas/api-payloads.schema.json DecisionPageState/ManagePageState y
// common.schema.json UniformNotFound. Valida el CUERPO real de cada respuesta contra su schema (validador propio, sin
// dependencias) y que el OpenAPI declare ambas operaciones con 200/404 y no-store. TEST-CNS-1903..1903.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { validateApiPayload, validateCommon, type ValidationResult } from "../schema-lite.ts";
import { MANAGE_ENTRY_HANDLE_COOKIE_NAME, SESSION_COOKIE_NAME, TENANT_ID, manageEntrySession, seedManageChain, startWorld, verifiedDecisionSession, verifiedManageSession } from "../../helpers/page-state-world.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

function assertValid(result: ValidationResult): void {
  assert.ok(result.ok, `violaciones de esquema:\n${result.errors.join("\n")}`);
}

test("TEST-CNS-1903: API-CNS-194 GET /decision/page-state: 200 cumple DecisionPageState y 404 cumple UniformNotFound", async () => {
  const world = await startWorld();
  try {
    const session = await verifiedDecisionSession(world, "ct1901");
    const ok = await fetch(`${world.baseUrl}/decision/page-state`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${session}` } });
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get("cache-control"), "no-store");
    assertValid(validateApiPayload("DecisionPageState", await ok.json()));
    const notFound = await fetch(`${world.baseUrl}/decision/page-state`);
    assert.equal(notFound.status, 404);
    assertValid(validateCommon("UniformNotFound", await notFound.json()));
    // El schema es cerrado: un campo extra (p. ej. el hash del texto) lo rechazaría.
    assert.equal(validateApiPayload("DecisionPageState", { relationshipRefs: [], servedVersion: { consentVersion: "v1", privacyNoticeVersion: "v1", text: "t", consentTextHash: "x" } }).ok, false);
  } finally {
    await world.close();
  }
});

test("TEST-CNS-1904: API-CNS-195 GET /manage/page-state: las tres variantes cumplen ManagePageState y 404 cumple UniformNotFound", async () => {
  const world = await startWorld();
  try {
    await seedManageChain(world, "ct1902", "mgmt-token-ct1902");
    const entry = await manageEntrySession(world, "mgmt-token-ct1902");
    const verified = await verifiedManageSession(world, "mgmt-token-ct1902");
    const call = (s: { session: string; handleCookie: string }) =>
      fetch(`${world.baseUrl}/manage/page-state`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${s.session}; ${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${s.handleCookie}` } });
    const seen: string[] = [];
    for (const [s, expected] of [[entry, "entry"], [verified, "status"]] as const) {
      const res = await call(s);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("cache-control"), "no-store");
      const body = await res.json();
      assertValid(validateApiPayload("ManagePageState", body));
      assert.equal((body as { variant: string }).variant, expected);
      seen.push(expected);
    }
    const seeded = await world.ports.decision.repo.findByConsentId(TENANT_ID, fixtureUuid("consent-ct1902"));
    assert.ok(seeded);
    await world.ports.decision.repo.save({ ...seeded, state: "REVOKED" });
    const revoked = await (await call(verified)).json();
    assertValid(validateApiPayload("ManagePageState", revoked));
    seen.push((revoked as { variant: string }).variant);
    assert.deepEqual(seen, ["entry", "status", "revoked"]);
    const notFound = await fetch(`${world.baseUrl}/manage/page-state`);
    assert.equal(notFound.status, 404);
    assertValid(validateCommon("UniformNotFound", await notFound.json()));
    assert.equal(validateApiPayload("ManagePageState", { variant: "desconocida" }).ok, false);
  } finally {
    await world.close();
  }
});

test("TEST-CNS-1905: el OpenAPI declara GET /decision/page-state (API-CNS-194) y GET /manage/page-state (API-CNS-195) con 200 no-store, 404 uniforme y sus schemas", () => {
  const yaml = readFileSync(new URL("../../../contracts/openapi/consent-it0.openapi.yaml", import.meta.url), "utf8");
  for (const [path, apiId, schema] of [["/decision/page-state:", "API-CNS-194", "DecisionPageState"], ["/manage/page-state:", "API-CNS-195", "ManagePageState"]] as const) {
    const start = yaml.indexOf(`\n  ${path}\n`);
    assert.ok(start >= 0, `${path} debe existir en paths`);
    const rest = yaml.slice(start + 1);
    const nextPath = rest.slice(1).search(/\n  \/|\n  # -{10}/);
    const block = nextPath === -1 ? rest : rest.slice(0, nextPath + 1);
    assert.match(block, /^ {4}get:/m);
    assert.ok(block.includes(`x-api-id: ${apiId}`));
    assert.ok(block.includes(`api-payloads.schema.json#/$defs/${schema}`));
    assert.ok(block.includes("'404': {$ref: '#/components/responses/UniformNotFound'}"));
    assert.ok(block.includes("const: no-store"));
    assert.doesNotMatch(block, /^ {4}(post|put|patch|delete):/m);
  }
  assert.match(yaml, /^ {2}version: 0\.1\.1-draft$/m);
});
