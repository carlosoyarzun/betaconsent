// Gobierna: ADR-001 rev. 8 F1 (fase B; decisión de Carlos 2026-10-18), contracts/openapi/consent-it0.openapi.yaml API-CNS-194
// (GET /decision/page-state) y API-CNS-195 (GET /manage/page-state). Los endpoints JSON entregan a la SPA lo que el SSR
// interpola en GET /decision y GET /manage, con las MISMAS comprobaciones de sesión y el MISMO 404 uniforme (INV-CM-05),
// solo lectura (INV-CM-08), no-store y sin PII. TEST-CNS-1896..1900 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";

import { getServedConsentVersion } from "../../../src/server/entrypoints/http/served-consent-version.ts";
import { MANAGE_ENTRY_HANDLE_COOKIE_NAME, SESSION_COOKIE_NAME, TENANT_ID, landingSession, manageEntrySession, post, seedManageChain, startWorld, verifiedDecisionSession, verifiedManageSession, type World } from "../../helpers/page-state-world.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

function get(world: World, path: string, cookies: Record<string, string> = {}): Promise<Response> {
  const cookie = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
  return fetch(`${world.baseUrl}${path}`, { headers: cookie ? { cookie } : {} });
}

async function withWorld(fn: (world: World) => Promise<void>): Promise<void> {
  const world = await startWorld();
  try {
    await fn(world);
  } finally {
    await world.close();
  }
}

function assertJsonNoStore(res: Response): void {
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.match(res.headers.get("content-type") ?? "", /^application\/json/);
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
}

test("TEST-CNS-1896: GET /decision/page-state con sesión verificada -> 200 JSON no-store con relaciones, versión servida (sin hash) y nada más", async () => {
  await withWorld(async (world) => {
    const session = await verifiedDecisionSession(world, "ps1896");
    const res = await get(world, "/decision/page-state", { [SESSION_COOKIE_NAME]: session });
    assert.equal(res.status, 200);
    assertJsonNoStore(res);
    const body = (await res.json()) as Record<string, unknown>;
    const served = getServedConsentVersion();
    assert.deepEqual(Object.keys(body).sort().filter((k) => k !== "subjectLabel"), ["relationshipRefs", "servedVersion"]);
    assert.deepEqual(body.relationshipRefs, ["SYNTHETIC_GUARDIAN"]);
    assert.deepEqual(body.servedVersion, { consentVersion: served.consentVersion, privacyNoticeVersion: served.privacyNoticeVersion, text: served.text });
    assert.equal(JSON.stringify(body).includes(served.consentTextHash), false, "no expone consentTextHash");
    if ("subjectLabel" in body) assert.match(String(body.subjectLabel), /^Alumno de prueba [0-9]{1,4}$/);
    // Equivalencia con el SSR: la misma versión servida aparece en GET /decision (ssr).
    const html = await (await get(world, "/decision", { [SESSION_COOKIE_NAME]: session })).text();
    assert.ok(html.includes(served.text) && html.includes('<option value="SYNTHETIC_GUARDIAN">'));
  });
});

test("TEST-CNS-1897: GET /decision/page-state sin sesión, con basura o con sesión solo LANDING -> 404 uniforme idéntico al de GET /decision, no-store", async () => {
  await withWorld(async (world) => {
    const landing = await landingSession(world, "ps1897");
    const attempts: Array<Record<string, string>> = [{}, { [SESSION_COOKIE_NAME]: "basura.firma" }, { [SESSION_COOKIE_NAME]: landing }];
    const bodies = new Set<string>();
    for (const cookies of attempts) {
      const res = await get(world, "/decision/page-state", cookies);
      assert.equal(res.status, 404);
      assertJsonNoStore(res);
      bodies.add(await res.text());
      assert.equal((await get(world, "/decision", cookies)).status, 404, "GET /decision responde el mismo estado");
    }
    assert.deepEqual([...bodies], ['{"status":404}']);
  });
});

test("TEST-CNS-1898: GET /decision/page-state con invitación cancelada (I9) -> 404 uniforme (P-30), igual que GET /decision", async () => {
  await withWorld(async (world) => {
    const session = await verifiedDecisionSession(world, "ps1898");
    assert.equal((await get(world, "/decision/page-state", { [SESSION_COOKIE_NAME]: session })).status, 200);
    const mismatch = await post(world.baseUrl, "/decision/subject-mismatch", session);
    assert.equal(mismatch.status, 200);
    const after = await get(world, "/decision/page-state", { [SESSION_COOKIE_NAME]: session });
    assert.equal(after.status, 404);
    assert.equal(await after.text(), '{"status":404}');
    assert.equal((await get(world, "/decision", { [SESSION_COOKIE_NAME]: session })).status, 404);
  });
});

test("TEST-CNS-1899: GET /manage/page-state devuelve solo la variante: entry (sin OTP MANAGE), status (post V3 MANAGE) y revoked (decisión REVOKED con OTP MANAGE)", async () => {
  await withWorld(async (world) => {
    await seedManageChain(world, "ps1899", "mgmt-token-ps1899");
    const entry = await manageEntrySession(world, "mgmt-token-ps1899");
    const entryRes = await get(world, "/manage/page-state", { [SESSION_COOKIE_NAME]: entry.session, [MANAGE_ENTRY_HANDLE_COOKIE_NAME]: entry.handleCookie });
    assert.equal(entryRes.status, 200);
    assertJsonNoStore(entryRes);
    assert.deepEqual(await entryRes.json(), { variant: "entry" });

    const verified = await verifiedManageSession(world, "mgmt-token-ps1899");
    const statusRes = await get(world, "/manage/page-state", { [SESSION_COOKIE_NAME]: verified.session, [MANAGE_ENTRY_HANDLE_COOKIE_NAME]: verified.handleCookie });
    assert.equal(statusRes.status, 200);
    assert.deepEqual(await statusRes.json(), { variant: "status" });
    assert.match(await (await get(world, "/manage", { [SESSION_COOKIE_NAME]: verified.session, [MANAGE_ENTRY_HANDLE_COOKIE_NAME]: verified.handleCookie })).text(), /start-revocation-btn/);

    // Decisión REVOKED (C6, INV-5): con OTP MANAGE -> revoked; sin OTP MANAGE -> entry (igual que el SSR, TEST-CNS-706).
    const seeded = await world.ports.decision.repo.findByConsentId(TENANT_ID, fixtureUuid("consent-ps1899"));
    assert.ok(seeded);
    await world.ports.decision.repo.save({ ...seeded, state: "REVOKED" });
    const revokedRes = await get(world, "/manage/page-state", { [SESSION_COOKIE_NAME]: verified.session, [MANAGE_ENTRY_HANDLE_COOKIE_NAME]: verified.handleCookie });
    assert.deepEqual(await revokedRes.json(), { variant: "revoked" });
    assert.match(await (await get(world, "/manage", { [SESSION_COOKIE_NAME]: verified.session, [MANAGE_ENTRY_HANDLE_COOKIE_NAME]: verified.handleCookie })).text(), /id="manage-revoked"/);
    const entryAgain = await get(world, "/manage/page-state", { [SESSION_COOKIE_NAME]: entry.session, [MANAGE_ENTRY_HANDLE_COOKIE_NAME]: entry.handleCookie });
    assert.deepEqual(await entryAgain.json(), { variant: "entry" });
  });
});

test("TEST-CNS-1900: GET /manage/page-state sin handle ni sesión, o con sesión ilegible -> 404 uniforme no-store; con handle ilegible coincide con GET /manage", async () => {
  await withWorld(async (world) => {
    await seedManageChain(world, "ps1900", "mgmt-token-ps1900");
    const none = await get(world, "/manage/page-state");
    assert.equal(none.status, 404);
    assertJsonNoStore(none);
    assert.equal(await none.text(), '{"status":404}');
    assert.equal((await get(world, "/manage")).status, 404);

    // Handle ilegible (no decodifica): se trata como ausente; page-state y GET /manage coinciden en estado y en Set-Cookie.
    const entry = await manageEntrySession(world, "mgmt-token-ps1900");
    const malformed = { [SESSION_COOKIE_NAME]: entry.session, [MANAGE_ENTRY_HANDLE_COOKIE_NAME]: "handle.invalido" };
    const pageState = await get(world, "/manage/page-state", malformed);
    const html = await get(world, "/manage", malformed);
    assert.equal(pageState.status, html.status);
    assert.deepEqual(pageState.headers.getSetCookie().filter((c) => c.startsWith(SESSION_COOKIE_NAME)), html.headers.getSetCookie().filter((c) => c.startsWith(SESSION_COOKIE_NAME)));
    // Sesión ilegible y sin handle: 404 uniforme.
    const garbage = await get(world, "/manage/page-state", { [SESSION_COOKIE_NAME]: "basura.firma" });
    assert.equal(garbage.status, 404);
    assert.equal(await garbage.text(), '{"status":404}');
  });
});
