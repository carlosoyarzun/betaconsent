// Gobierna: CA-125 + aprobación de Carlos 2026-10-01 (consola dev del colegio, SOLO LOCAL,
// GET /__dev/staff-console). Reutiliza los handlers /staff/* (EN0 -> I1 -> I2 -> I3). Datos
// sintéticos, cero PII. TEST-CNS-1060..TEST-CNS-1064 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  createConsentFlowHttpServer,
  createDefaultConsentFlowPorts,
  createDefaultStaffConsolePorts,
} from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import {
  LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_STAFF_ADMIN_PRINCIPAL_REF,
  LOCAL_ONLY_DEV_STAFF_ROSTER,
  LOCAL_ONLY_DEV_STAFF_STUDENTS,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";

const ORIGIN = "http://consola-dev.test.localhost";
const STAFF_COOKIE = "__Host-cns-staff";
const STAFF_CSRF_COOKIE = "__Host-cns-staff-csrf";
const BASE = "/__dev/staff-console";
const S1 = LOCAL_ONLY_DEV_STAFF_STUDENTS[0]!.subjectRef;
const S2 = LOCAL_ONLY_DEV_STAFF_STUDENTS[1]!.subjectRef;

interface Harness {
  readonly baseUrl: string;
  readonly staff: ReturnType<typeof createDefaultStaffConsolePorts>;
  close(): Promise<void>;
}

function startServer(environment: "LOCAL" | "DEV"): Promise<Harness> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG);
  const staffIdentity = createInMemoryStaffIdentityAdapter([...LOCAL_ONLY_DEV_STAFF_ROSTER]);
  const staff = createDefaultStaffConsolePorts(ports.invitation, staffIdentity, loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY));
  for (const st of LOCAL_ONLY_DEV_STAFF_STUDENTS) {
    staff.catalog.seedSubject(LOCAL_ONLY_DEV_TENANT_ID, st.subjectRef);
    staff.catalog.seedParticipation(LOCAL_ONLY_DEV_TENANT_ID, {
      participationRef: st.participationRef,
      contextRef: LECTORPRO_BETA_CONFIG.contextRef,
      productRef: LECTORPRO_BETA_CONFIG.productRef,
      status: "ACTIVE",
    });
  }
  const server: Server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN },
    ports,
    sessionSecret: randomBytes(32),
    environment,
    staffIdentity,
    staffConsole: staff,
    devStaffConsole: {
      principalRef: LOCAL_ONLY_DEV_STAFF_ADMIN_PRINCIPAL_REF,
      students: LOCAL_ONLY_DEV_STAFF_STUDENTS,
      contextRef: LECTORPRO_BETA_CONFIG.contextRef,
      consentVersion: "v1-dev",
    },
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        staff,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

function cookieJar(res: Response): string {
  return res.headers
    .getSetCookie()
    .map((c) => c.split(";")[0] ?? "")
    .join("; ");
}

async function form(h: Harness, path: string, fields: Record<string, string>, opts: { cookie?: string; origin?: string | null } = {}): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (opts.origin !== null) headers.origin = opts.origin ?? ORIGIN;
  if (opts.cookie) headers.cookie = opts.cookie;
  return fetch(`${h.baseUrl}${path}`, { method: "POST", headers, body: new URLSearchParams(fields), redirect: "manual" });
}

async function loginViaForm(h: Harness): Promise<{ cookie: string; csrf: string }> {
  const res = await form(h, `${BASE}/login`, {});
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), BASE);
  const cookie = cookieJar(res);
  const csrf = cookie.split("; ").find((c) => c.startsWith(`${STAFF_CSRF_COOKIE}=`))?.slice(STAFF_CSRF_COOKIE.length + 1);
  assert.ok(csrf && cookie.includes(`${STAFF_COOKIE}=`));
  return { cookie, csrf };
}

test("TEST-CNS-1060: fuera de LOCAL la consola dev responde 404 en GET y en todos sus POST, sin crear nada", async () => {
  const h = await startServer("DEV");
  try {
    for (const path of [BASE, `${BASE}/login`, `${BASE}/invite`]) {
      const res = path === BASE ? await fetch(`${h.baseUrl}${path}`) : await form(h, path, { guardian_email: "a@example.invalid", csrf_token: "x" });
      assert.equal(res.status, 404, path);
      assert.deepEqual(await res.json(), { status: 404 });
    }
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1061: flujo feliz en LOCAL (login -> formulario -> EN0/I1/I2/I3) muestra un enlace /i/ canjeable (303 a /welcome) y el link a /__dev/otp-sink", async () => {
  const h = await startServer("LOCAL");
  try {
    const anon = await fetch(`${h.baseUrl}${BASE}`);
    assert.equal(anon.status, 200);
    assert.match(await anon.text(), /Entrar como administrador del colegio de prueba/);

    const { cookie, csrf } = await loginViaForm(h);
    const page = await fetch(`${h.baseUrl}${BASE}`, { headers: { cookie } });
    const html = await page.text();
    assert.match(html, /<select id="student"/);
    assert.match(html, /Correo del apoderado \(inventado\)/);
    assert.match(html, /placeholder="apoderado1@example\.invalid"/);
    assert.ok(html.includes(`name="csrf_token" value="${csrf}"`));
    assert.doesNotMatch(html, /<script/i);

    const res = await form(h, `${BASE}/invite`, { csrf_token: csrf, student: S1, guardian_email: "apoderado1@example.invalid" }, { cookie });
    assert.equal(res.status, 200);
    const out = await res.text();
    const link = /href="(\/i\/[^"]+)"/.exec(out)?.[1];
    assert.ok(link, "enlace /i/ presente");
    assert.match(out, /href="\/__dev\/otp-sink"/);
    assert.equal(h.staff.invitationLinkSink.sent.length, 1);
    assert.equal(h.staff.invitationLinkSink.sent[0]?.invitationPath, link);

    const redeem = await fetch(`${h.baseUrl}${link}`, { redirect: "manual" });
    assert.equal(redeem.status, 303);
    assert.equal(redeem.headers.get("location"), "/welcome");
    const welcome = await fetch(`${h.baseUrl}/welcome`, { headers: { cookie: cookieJar(redeem) } });
    assert.equal(welcome.status, 200);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1062: correo no reservado -> error visible en lenguaje claro, sin invitación enviada ni enrollment huérfano (reintento posible)", async () => {
  const h = await startServer("LOCAL");
  try {
    const { cookie, csrf } = await loginViaForm(h);
    const bad = await form(h, `${BASE}/invite`, { csrf_token: csrf, student: S1, guardian_email: "padre@gmail.com" }, { cookie });
    assert.equal(bad.status, 422);
    const html = await bad.text();
    assert.match(html, /role="alert"/);
    assert.match(html, /dominio reservado/);
    assert.ok(!html.includes("padre@gmail.com"), "el correo no se refleja");
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);

    const good = await form(h, `${BASE}/invite`, { csrf_token: csrf, student: S1, guardian_email: "apoderado1@example.invalid" }, { cookie });
    assert.equal(good.status, 200);
    assert.equal(h.staff.invitationLinkSink.sent.length, 1);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1063: sin sesión STAFF no se puede enviar (cookies ausentes o sesión basura): sin invitación", async () => {
  const h = await startServer("LOCAL");
  try {
    const noCookie = await form(h, `${BASE}/invite`, { csrf_token: "abc", student: S1, guardian_email: "apoderado1@example.invalid" });
    assert.equal(noCookie.status, 403);
    const csrf = "csrf-sin-sesion-0001";
    const cookie = `${STAFF_CSRF_COOKIE}=${csrf}; ${STAFF_COOKIE}=basura.firma`;
    const garbage = await form(h, `${BASE}/invite`, { csrf_token: csrf, student: S1, guardian_email: "apoderado1@example.invalid" }, { cookie });
    assert.equal(garbage.status, 401);
    assert.match(await garbage.text(), /sesión de administrador/);
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1064: CSRF ausente, distinto de la cookie u Origin ajeno -> rechazo 403 sin efecto", async () => {
  const h = await startServer("LOCAL");
  try {
    const { cookie, csrf } = await loginViaForm(h);
    const email = "apoderado1@example.invalid";
    const missing = await form(h, `${BASE}/invite`, { student: S1, guardian_email: email }, { cookie });
    assert.equal(missing.status, 403);
    const wrong = await form(h, `${BASE}/invite`, { csrf_token: `${csrf}x`, student: S1, guardian_email: email }, { cookie });
    assert.equal(wrong.status, 403);
    const foreignOrigin = await form(h, `${BASE}/invite`, { csrf_token: csrf, student: S1, guardian_email: email }, { cookie, origin: "http://evil.test.localhost" });
    assert.equal(foreignOrigin.status, 403);
    const noOrigin = await form(h, `${BASE}/invite`, { csrf_token: csrf, student: S1, guardian_email: email }, { cookie, origin: null });
    assert.equal(noOrigin.status, 403);
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    // el login tampoco acepta un Origin ajeno
    const loginForeign = await form(h, `${BASE}/login`, {}, { origin: "http://evil.test.localhost" });
    assert.equal(loginForeign.status, 403);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1065: dos invitaciones a alumnos distintos en el mismo arranque funcionan; repetir un alumno da error claro y alumno ajeno al catálogo se rechaza", async () => {
  const h = await startServer("LOCAL");
  try {
    assert.ok(LOCAL_ONLY_DEV_STAFF_STUDENTS.length >= 6);
    const { cookie, csrf } = await loginViaForm(h);
    const send = (student: string, email: string): Promise<Response> => form(h, `${BASE}/invite`, { csrf_token: csrf, student, guardian_email: email }, { cookie });
    assert.equal((await send(S1, "apoderado1@example.invalid")).status, 200);
    assert.equal((await send(S2, "apoderado2@example.invalid")).status, 200);
    assert.equal(h.staff.invitationLinkSink.sent.length, 2);
    assert.notEqual(h.staff.invitationLinkSink.sent[0]?.invitationPath, h.staff.invitationLinkSink.sent[1]?.invitationPath);
    const again = await send(S1, "apoderado3@example.invalid");
    assert.equal(again.status, 409);
    assert.match(await again.text(), /Elige otro alumno/);
    const unknown = await send("00000000-0000-4000-8000-000000000000", "apoderado4@example.invalid");
    assert.equal(unknown.status, 422);
    assert.equal(h.staff.invitationLinkSink.sent.length, 2);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1066: cuerpo > 8 KiB -> 413 y corte (solo LOCAL); fuera de LOCAL 404 sin leer cuerpo; CSP de la página restringe script/object/base", async () => {
  const h = await startServer("LOCAL");
  try {
    const { cookie, csrf } = await loginViaForm(h);
    const big = await form(h, `${BASE}/invite`, { csrf_token: csrf, student: S1, guardian_email: "a".repeat(20000) }, { cookie }).catch(() => null);
    if (big) assert.equal(big.status, 413); // el servidor puede cortar la conexión antes de que el cliente lea la respuesta
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
    const csp = (await fetch(`${h.baseUrl}${BASE}`)).headers.get("content-security-policy") ?? "";
    for (const d of ["script-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"]) assert.ok(csp.includes(d), d);
    // sigue vivo y funcional tras el corte
    assert.equal((await form(h, `${BASE}/invite`, { csrf_token: csrf, student: S1, guardian_email: "apoderado1@example.invalid" }, { cookie })).status, 200);
  } finally {
    await h.close();
  }
  const d = await startServer("DEV");
  try {
    const res = await form(d, `${BASE}/invite`, { x: "a".repeat(20000) });
    assert.equal(res.status, 404);
  } finally {
    await d.close();
  }
});

test("TEST-CNS-1188: GRD-SE-08 en la consola dev: el CSRF ligado al sid se valida antes del touch; una cookie robada sin CSRF valido no prolonga la inactividad", async () => {
  const h = await startServer("LOCAL");
  try {
    const a = await loginViaForm(h);
    const b = await loginViaForm(h);
    const store = h.staff.sessions as unknown as { rows(): readonly { lastSeenAtMs: number }[] };
    const before = store.rows().map((r) => r.lastSeenAtMs);
    (h.staff as { nowMs?: () => number }).nowMs = () => Date.now() + 29 * 60_000;
    const sessionOfA = a.cookie.split("; ").find((c) => c.startsWith(`${STAFF_COOKIE}=`))!;
    const foreign = `${sessionOfA}; ${STAFF_CSRF_COOKIE}=${b.csrf}`;
    const res = await form(h, `${BASE}/invite`, { csrf_token: b.csrf, student: S1, guardian_email: "apoderado1@example.invalid" }, { cookie: foreign });
    assert.equal(res.status, 403);
    assert.deepEqual(store.rows().map((r) => r.lastSeenAtMs), before, "sin CSRF valido no se avanza last_seen_at");
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1232: la consola dev (formularios POST sin JS) responde Referrer-Policy same-origin (Chromium manda Origin: null con no-referrer) y Origin: null sigue dando 403", async () => {
  const h = await startServer("LOCAL");
  try {
    const page = await fetch(`${h.baseUrl}${BASE}`);
    assert.equal(page.headers.get("referrer-policy"), "same-origin");
    const login = await form(h, `${BASE}/login`, {});
    assert.equal(login.status, 303);
    const nullLogin = await form(h, `${BASE}/login`, {}, { origin: "null" });
    assert.equal(nullLogin.status, 403);
    const { cookie, csrf } = await loginViaForm(h);
    const nullInvite = await form(h, `${BASE}/invite`, { csrf_token: csrf, student: S1, guardian_email: "apoderado1@example.invalid" }, { cookie, origin: "null" });
    assert.equal(nullInvite.status, 403);
    assert.equal(h.staff.invitationLinkSink.sent.length, 0);
  } finally {
    await h.close();
  }
});
