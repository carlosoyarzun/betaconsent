// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-127 (POST /decision/submit,
// consolida C1/C2/C3/C5 en un solo POST IT0, ver x-scope-note en consent-flow.handler.ts);
// specs/state-machines/consent-decision.spec.yaml C1/C2/C3/C5; SM-CNS-001 R0.2 (actor/refs
// derivados de la sesión, nunca del body). `bringToVerifiedSession` recorre GET /i/{token}
// (API-CNS-101, P-12) -> POST /invitation/open -> V1 -> V3.
// TEST-CNS-504..TEST-CNS-506 (traceability/test-matrix.csv).

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { deriveDecisionMakerRef } from "../../../src/server/modules/consent-decision/decision-maker-ref.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const SESSION_COOKIE_NAME = "__Host-cns-session";
const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
const TENANT_ID = "tenant-1";
const CHANNEL_REF = "test+channel-2@example.invalid";

// LOCAL-only sintético (D4): ver otp-policy.config.ts.
const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
// LOCAL-only sintético (GRD-CD-04, decision-relationship.config.ts, opción b de Carlos).
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));

interface Harness {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  close(): Promise<void>;
}

function startServer(): Promise<Harness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  const server: Server = createConsentFlowHttpServer({ config: { allowedOrigin: ALLOWED_ORIGIN }, ports });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        ports,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

function parseSetCookie(res: Response): Record<string, string> {
  const raw = res.headers.get("set-cookie") ?? "";
  const out: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

/** GET /welcome puede fijar sesión + CSRF en la misma respuesta; getSetCookie() (undici) los
 * mantiene separados, a diferencia de parseSetCookie (un solo Set-Cookie). */
function parseAllSetCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  const raws = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie") ?? ""];
  for (const raw of raws) {
    for (const part of raw.split(";")) {
      const eq = part.indexOf("=");
      if (eq === -1) continue;
      const name = part.slice(0, eq).trim();
      if (!out[name]) out[name] = part.slice(eq + 1).trim();
    }
  }
  return out;
}

interface PostOpts {
  readonly path: string;
  readonly origin?: string;
  readonly csrfHeader?: string;
  readonly csrfCookie?: string;
  readonly sessionCookie?: string;
  readonly body?: unknown;
}

async function post(baseUrl: string, opts: PostOpts): Promise<Response> {
  const cookieParts: string[] = [];
  if (opts.csrfCookie !== undefined) cookieParts.push(`${CSRF_COOKIE_NAME}=${opts.csrfCookie}`);
  if (opts.sessionCookie !== undefined) cookieParts.push(`${SESSION_COOKIE_NAME}=${opts.sessionCookie}`);

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.csrfHeader !== undefined) headers[CSRF_HEADER_NAME] = opts.csrfHeader;
  if (cookieParts.length > 0) headers.cookie = cookieParts.join("; ");

  return fetch(`${baseUrl}${opts.path}`, { method: "POST", headers, body: JSON.stringify(opts.body ?? {}) });
}

const VALID_CSRF = { origin: ALLOWED_ORIGIN, csrfHeader: "csrf-token-abcdefgh", csrfCookie: "csrf-token-abcdefgh" };

/** Recorre invitación -> OTP hasta dejar una sesión verificada (post-V3), lista para
 * /decision/submit. Devuelve la cookie de sesión verificada. */
async function bringToVerifiedSession(harness: Harness, invitationRef: string, subjectRef: string): Promise<string> {
  await createInvitation(harness.ports.invitation, TENANT_ID, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef,
  });
  await markInvitationReady(harness.ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: CHANNEL_REF,
  });
  const { token } = await sendInvitation(harness.ports.invitation, TENANT_ID, "INVITER", invitationRef, { deliveryChannel: "CONSENT_APP_EMAIL" });

  const redeemed = await fetch(`${harness.baseUrl}/i/${token}`, { redirect: "manual" });
  const handleCookie = parseSetCookie(redeemed)[INVITATION_HANDLE_COOKIE_NAME];
  const welcome = await fetch(`${harness.baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handleCookie}` } });
  const landingSession = parseAllSetCookies(welcome)[SESSION_COOKIE_NAME];
  const opened = await post(harness.baseUrl, { path: "/invitation/open", ...VALID_CSRF, sessionCookie: landingSession });
  const sessionAfterOpen = parseSetCookie(opened)[SESSION_COOKIE_NAME];
  const requested = await post(harness.baseUrl, { path: "/otp/request", ...VALID_CSRF, sessionCookie: sessionAfterOpen });
  const sessionAfterRequest = parseSetCookie(requested)[SESSION_COOKIE_NAME];

  const sink = harness.ports.otp.channel as InMemoryOtpChannelSink;
  const code = sink.sent[sink.sent.length - 1]?.code ?? "";
  const submitted = await post(harness.baseUrl, {
    path: "/otp/submit",
    ...VALID_CSRF,
    sessionCookie: sessionAfterRequest,
    body: { code },
  });
  const sessionCookie = parseSetCookie(submitted)[SESSION_COOKIE_NAME];
  assert.ok(sessionCookie, "V3 debe fijar la cookie de sesión verificada");
  return sessionCookie;
}

/** Recorre C2 (POST /decision/steps) completo: CONTEXT_INFORMATION_VIEWED,
 * CONSENT_VERSION_VIEWED, DECISION_MAKER_AUTHORITY_DECLARED y SUBJECT_CONFIRMED, en ese orden.
 * Devuelve la cookie de sesión final (con `consentId` ya fijado por C1 perezoso). */
async function completeDecisionSteps(harness: Harness, sessionCookie: string): Promise<string> {
  const steps: unknown[] = [
    { stepKind: "CONTEXT_INFORMATION_VIEWED" },
    { stepKind: "CONSENT_VERSION_VIEWED" },
    { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true },
    { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true },
  ];
  let cookie = sessionCookie;
  for (const body of steps) {
    const res = await post(harness.baseUrl, { path: "/decision/steps", ...VALID_CSRF, sessionCookie: cookie, body });
    assert.equal(res.status, 200, `paso ${JSON.stringify(body)} debía responder 200`);
    const nextCookie = parseSetCookie(res)[SESSION_COOKIE_NAME];
    if (nextCookie) cookie = nextCookie;
  }
  return cookie;
}

test("TEST-CNS-504: sin sesión verificada (sin pasar por V3), /decision/submit -> 404 uniforme", async () => {
  const harness = await startServer();
  try {
    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      body: { purposes: GRANT_ALL },
    });
    assert.equal(res.status, 404);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-564: /decision/submit sin haber completado los pasos de C2 (incluido DECISION_MAKER_AUTHORITY_DECLARED) -> 409 DECISION_STEPS_INCOMPLETE (ERR-CD-04, GRD-CD-05)", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-564"), fixtureUuid("subject-564"));

    // Ningún POST /decision/steps previo: la sesión no tiene consentId todavía, así que el
    // servidor ni siquiera puede resolver una decisión PENDING (404 uniforme, mismo patrón que
    // TEST-CNS-504 sin sesión verificada: "sin pasos" y "sin decisión iniciada" son
    // indistinguibles en este slice porque C1 es perezoso, ver x-scope-note del handler).
    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: verifiedSession,
      body: { purposes: GRANT_ALL },
    });
    assert.equal(res.status, 404);

    // Con C1 ya iniciado (un paso registrado) pero SIN completar los 4 pasos de C2, el submit sí
    // resuelve la decisión PENDING y falla por GRD-CD-05 (prior_steps_complete): ERR-CD-04 ->
    // DECISION_STEPS_INCOMPLETE (EXTERNAL_ERROR_CODE, consent-flow.handler.ts).
    const oneStepDone = await post(harness.baseUrl, {
      path: "/decision/steps",
      ...VALID_CSRF,
      sessionCookie: verifiedSession,
      body: { stepKind: "CONTEXT_INFORMATION_VIEWED" },
    });
    assert.equal(oneStepDone.status, 200);
    const sessionWithConsentId = parseSetCookie(oneStepDone)[SESSION_COOKIE_NAME] ?? verifiedSession;

    const incomplete = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionWithConsentId,
      body: { purposes: GRANT_ALL },
    });
    assert.equal(incomplete.status, 409);
    const body = (await incomplete.json()) as { code: string };
    assert.equal(body.code, "DECISION_STEPS_INCOMPLETE");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-505: /decision/submit ignora decisionMakerRef del body; el actor se deriva de la sesión (C1/C2/C3 -> GRANTED, dispara I6)", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-505"), fixtureUuid("subject-505"));
    const sessionAfterSteps = await completeDecisionSteps(harness, verifiedSession);

    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterSteps,
      body: { purposes: GRANT_ALL, decisionMakerRef: "attacker-supplied-dm" },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { consentId: string; state: string };
    assert.equal(body.state, "GRANTED");

    const decision = await harness.ports.decision.repo.findByConsentId(TENANT_ID, body.consentId);
    // El decisionMakerRef persistido nunca es el valor "attacker-supplied-dm" del body.
    assert.notEqual(decision?.decisionMakerRef, "attacker-supplied-dm");
    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-505")))?.state, "COMPLETED");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-933: el decisionMakerRef persistido es UUIDv4 desde HMAC con clave (no sha256 del canal), determinista y cumple los CHECK de BD (CA-128, LEGAL DECISION Carlos 2026-10-01)", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-933"), fixtureUuid("subject-933"));
    const sessionAfterSteps = await completeDecisionSteps(harness, verifiedSession);
    const res = await post(harness.baseUrl, { path: "/decision/submit", ...VALID_CSRF, sessionCookie: sessionAfterSteps, body: { purposes: GRANT_ALL } });
    assert.equal(res.status, 200);
    const { consentId } = (await res.json()) as { consentId: string };
    const record = await harness.ports.decision.repo.findByConsentId(TENANT_ID, consentId);
    const dm = record?.decisionMakerRef ?? "";
    assert.match(dm, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.ok(dm.length >= 1 && dm.length <= 100 && !dm.includes("@"));
    assert.equal(dm, deriveDecisionMakerRef(harness.ports.decisionMakerRefKey, TENANT_ID, CHANNEL_REF), "determinista: mismo canal -> mismo ref");
    const sha = createHash("sha256").update(CHANNEL_REF).digest("hex");
    assert.ok(!dm.replaceAll("-", "").includes(sha.slice(0, 16)), "no recuperable por SHA-256 simple");
    assert.ok((record?.chainRef ?? "").length > 0 && (record?.chainRef ?? "").length <= 100);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-506: /decision/submit con >=1 finalidad requerida en DECLINE -> DECLINED, dispara I7", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-506"), fixtureUuid("subject-506"));
    const sessionAfterSteps = await completeDecisionSteps(harness, verifiedSession);
    const purposes = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose, i) => ({
      purpose,
      choice: i === 0 ? ("DECLINE" as const) : ("GRANT" as const),
    }));

    const res = await post(harness.baseUrl, {
      path: "/decision/submit",
      ...VALID_CSRF,
      sessionCookie: sessionAfterSteps,
      body: { purposes },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { state: string };
    assert.equal(body.state, "DECLINED");
    assert.equal((await harness.ports.invitation.invitationRepo.findByRef(TENANT_ID, fixtureUuid("inv-506")))?.state, "DECLINED");
  } finally {
    await harness.close();
  }
});

// ---------------------------------------------------------------------------
// Fixes de revisión en navegador (Carlos, dev.ts LOCAL): TEST-CNS-567..570.
// ---------------------------------------------------------------------------

test("TEST-CNS-567: GET /decision sirve el texto de consentimiento y la versión YA resueltos, sin esperar ningún POST /decision/steps (GRD-CD-03 servido; INV-CM-08 un GET nunca transiciona)", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-567"), fixtureUuid("subject-567"));
    const res = await fetch(`${harness.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${verifiedSession}` } });
    assert.equal(res.status, 200);
    const html = await res.text();
    // Nunca el placeholder "cargando…": el HTML servido por GET /decision ya trae la versión.
    assert.doesNotMatch(html, /cargando/);
    assert.match(html, /Versión vigente del texto: v1/);
    assert.match(html, /\[LEGAL DECISION — texto de consentimiento pendiente de aprobación de Carlos\]/);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-568: la sección Finalidades incluye el marcador visible [LEGAL DECISION] de los frames 24:2/24:64 (no solo en un comentario HTML)", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-568"), fixtureUuid("subject-568"));
    const res = await fetch(`${harness.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${verifiedSession}` } });
    const html = await res.text();
    assert.match(
      html,
      /<p class="lp-decision-legal-note">\[LEGAL DECISION — las descripciones de cada finalidad son borrador UX; texto legal definitivo pendiente de aprobación de Carlos\]<\/p>/,
    );
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-569: app.css da un tap target >=44px al checkbox de autoridad (#authority-declared), no solo a la fila que lo contiene (Carlos, 2026-09-27, misma decisión que /welcome y /verify)", async () => {
  const harness = await startServer();
  try {
    const css = await (await fetch(`${harness.baseUrl}/assets/app.css`)).text();
    assert.match(css, /\.lp-decision-checkbox-row \.lp-decision-checkbox\s*\{[^}]*min-width:\s*44px[^}]*min-height:\s*44px/s);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-570: decision.js oculta #decision-form y mueve el foco al encabezado de confirmación en GRANTED y DECLINED (frames 27:49/27:58: la confirmación reemplaza el formulario)", async () => {
  const harness = await startServer();
  try {
    const js = await (await fetch(`${harness.baseUrl}/assets/decision.js`)).text();
    assert.match(js, /function showGranted\(receiptRef\) \{\s*hideStates\(\);\s*if \(decisionForm\) decisionForm\.hidden = true;/);
    assert.match(js, /function showDeclined\(receiptRef\) \{\s*hideStates\(\);\s*if \(decisionForm\) decisionForm\.hidden = true;/);
    assert.match(js, /getElementById\("granted-heading"\)/);
    assert.match(js, /getElementById\("declined-heading"\)/);
    assert.match(js, /heading\.focus\(\)/);
  } finally {
    await harness.close();
  }
});

// Quita cualquier comentario HTML (`<!-- ... -->`) antes de buscar un marcador: si el marcador
// solo existe DENTRO de un comentario, esta función lo hace desaparecer y el assert.match falla
// (fix Carlos, revisión en navegador con dev.ts: los marcadores [LEGAL DECISION] no pueden
// quedar invisibles para el usuario dentro de un comentario HTML).
function stripHtmlComments(html: string): string {
  return html.replace(/<!--[\s\S]*?-->/g, "");
}

test("TEST-CNS-584: los marcadores [LEGAL DECISION] de /decision (finalidad, enum de relación, enunciado de autoridad) son texto visible, nunca solo un comentario HTML", async () => {
  const harness = await startServer();
  try {
    const verifiedSession = await bringToVerifiedSession(harness, fixtureUuid("inv-584"), fixtureUuid("subject-584"));
    const res = await fetch(`${harness.baseUrl}/decision`, { headers: { cookie: `${SESSION_COOKIE_NAME}=${verifiedSession}` } });
    const html = await res.text();
    const visible = stripHtmlComments(html);
    assert.match(visible, /\[LEGAL DECISION — descripción de finalidad, borrador UX grounded en el protocolo; texto legal definitivo pendiente de aprobación de Carlos, handoff §3\.3\]/);
    assert.match(visible, /\[LEGAL DECISION — enum de relación pendiente de DEC-BR-003 \/ EXT-A \/ LD-01; opción \(b\) de Carlos: lista de valores por configuración\]/);
    assert.match(visible, /\[LEGAL DECISION — enunciado de autoridad pendiente de DEC-BR-003 \/ EXT-A \/ LD-01\]/);
  } finally {
    await harness.close();
  }
});
