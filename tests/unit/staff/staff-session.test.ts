// Gobierna: CA-138 (SEC-CNS-018 rev. 2 D-3, SEC-CNS-020 P2-3), src/server/entrypoints/http/staff-session.ts. TEST-CNS-1140: sid aleatorio de
// 256 bits, iat/exp con reloj inyectado, firma, CSRF ligado al sid, emision sin PII (solo hash del sid) y rotacion. Solo datos sinteticos.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInMemoryStaffSessionStore } from "../../../src/infra/adapters/in-memory-staff-session-store.adapter.ts";
import {
  decodeStaffSession,
  deriveStaffSessionKey,
  encodeStaffSession,
  hashStaffSid,
  issueStaffSession,
  newStaffSid,
  revokeStaffSessionCookie,
  serializeStaffSessionCookie,
  staffCsrfMatchesSession,
  staffCsrfTokenFor,
  type StaffSessionPayload,
} from "../../../src/server/entrypoints/http/staff-session.ts";
import {
  PROPOSED_STAFF_SESSION_ABSOLUTE_TTL_MS,
  PROPOSED_STAFF_SESSION_IDLE_TIMEOUT_MS,
} from "../../../src/server/modules/common/approved-parameters.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const key = deriveStaffSessionKey(randomBytes(32));
const T0 = 1_800_000_000_000;
const who = { tenantId: fixtureUuid("t1140"), principalRef: fixtureUuid("p1140"), role: "TENANT_ADMIN" as const };
const payload = (over: Partial<StaffSessionPayload> = {}): StaffSessionPayload => ({ sid: "A".repeat(43), ...who, iat: T0, exp: T0 + 1000, ...over });

test("TEST-CNS-1140 sid: 32 bytes aleatorios (256 bits >= 128), base64url de 43 caracteres, distinto en cada llamada; su hash es sha256 hex", () => {
  const sids = new Set(Array.from({ length: 200 }, () => newStaffSid()));
  assert.equal(sids.size, 200);
  for (const sid of sids) assert.match(sid, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from([...sids][0]!, "base64url").length, 32);
  assert.match(hashStaffSid([...sids][0]!), /^[0-9a-f]{64}$/);
  assert.notEqual(hashStaffSid("A".repeat(43)), "A".repeat(43));
});

test("TEST-CNS-1140 decode: firma, formato, iat <= now < exp con reloj inyectado; sin nowMs solo valida firma; propuestos 8 h / 30 min no se presentan como aprobados", () => {
  const cookie = encodeStaffSession(key, payload());
  assert.deepEqual(decodeStaffSession(key, cookie, T0), payload());
  assert.notEqual(decodeStaffSession(key, cookie, T0 + 999), null);
  assert.equal(decodeStaffSession(key, cookie, T0 + 1000), null, "exp absoluta: now >= exp");
  assert.equal(decodeStaffSession(key, cookie, T0 + 5000), null);
  assert.equal(decodeStaffSession(key, cookie, T0 - 1), null, "iat en el futuro");
  assert.notEqual(decodeStaffSession(key, cookie), null, "sin reloj: solo firma (logout de una cookie vencida)");
  assert.equal(decodeStaffSession(deriveStaffSessionKey(randomBytes(32)), cookie, T0), null, "otra clave");
  const [body, mac] = cookie.split(".") as [string, string];
  assert.equal(decodeStaffSession(key, `${body}.${mac.slice(0, -2)}xx`, T0), null);
  for (const bad of [payload({ exp: T0 }), payload({ sid: "corto" }), payload({ sid: "A".repeat(44) }), payload({ iat: Number.NaN }), { ...payload(), role: "ROOT" } as never, { ...payload(), sid: undefined } as never]) {
    assert.equal(decodeStaffSession(key, encodeStaffSession(key, bad), T0), null);
  }
  assert.equal(decodeStaffSession(key, undefined, T0), null);
  assert.equal(PROPOSED_STAFF_SESSION_ABSOLUTE_TTL_MS, 8 * 60 * 60_000);
  assert.equal(PROPOSED_STAFF_SESSION_IDLE_TIMEOUT_MS, 30 * 60_000);
});

test("TEST-CNS-1140 CSRF ligado al sid: mismo sid mismo token, otro sid otro token, otra clave otro token; comparacion exacta", () => {
  const a = staffCsrfTokenFor(key, "A".repeat(43));
  assert.equal(staffCsrfTokenFor(key, "A".repeat(43)), a);
  assert.notEqual(staffCsrfTokenFor(key, "B".repeat(43)), a);
  assert.notEqual(staffCsrfTokenFor(deriveStaffSessionKey(randomBytes(32)), "A".repeat(43)), a);
  assert.equal(staffCsrfMatchesSession(key, "A".repeat(43), a), true);
  assert.equal(staffCsrfMatchesSession(key, "B".repeat(43), a), false);
  assert.equal(staffCsrfMatchesSession(key, "A".repeat(43), undefined), false);
  assert.equal(staffCsrfMatchesSession(key, "A".repeat(43), `${a}x`), false);
});

test("TEST-CNS-1140 issueStaffSession: iat/exp del reloj inyectado, registro con SOLO el hash del sid (sin sid ni cookie en el almacen), Max-Age = vida absoluta, rotacion revoca el sid previo", async () => {
  const sessions = createInMemoryStaffSessionStore();
  let now = T0;
  const deps = { sessions, staffSessionKey: key, nowMs: () => now };
  const first = await issueStaffSession(deps, who);
  const decoded = decodeStaffSession(key, first.cookieValue, now)!;
  assert.equal(decoded.sid, first.sid);
  assert.equal(decoded.iat, T0);
  assert.equal(decoded.exp, T0 + PROPOSED_STAFF_SESSION_ABSOLUTE_TTL_MS);
  assert.equal(first.maxAgeSec, PROPOSED_STAFF_SESSION_ABSOLUTE_TTL_MS / 1000);
  assert.match(serializeStaffSessionCookie("__Host-cns-staff", first.cookieValue, first.maxAgeSec), /^__Host-cns-staff=[^;]+; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800$/);
  assert.equal(first.csrfToken, staffCsrfTokenFor(key, first.sid));
  const stored = JSON.stringify(sessions.rows());
  assert.ok(!stored.includes(first.sid) && !stored.includes(first.cookieValue), "el sid en claro nunca se persiste");
  assert.ok(stored.includes(hashStaffSid(first.sid)));
  assert.deepEqual(Object.keys(sessions.rows()[0]!).sort(), ["expiresAtMs", "issuedAtMs", "lastSeenAtMs", "principalRef", "revokedAtMs", "role", "sidHash", "tenantId"]);

  // rotacion: un login con la cookie previa revoca ese sid y emite uno nuevo distinto
  now = T0 + 60_000;
  const second = await issueStaffSession(deps, who, first.cookieValue);
  assert.notEqual(second.sid, first.sid);
  const live = (sid: string) => sessions.validateAndTouch({ ...who, sidHash: hashStaffSid(sid), nowMs: now, idleTimeoutMs: PROPOSED_STAFF_SESSION_IDLE_TIMEOUT_MS });
  assert.equal(await live(first.sid), false, "el sid previo quedo revocado");
  assert.equal(await live(second.sid), true);

  // logout: revoca por cookie (aunque ya haya vencido por exp) y es idempotente; basura no hace nada
  now = T0 + PROPOSED_STAFF_SESSION_ABSOLUTE_TTL_MS + 1;
  assert.equal((await revokeStaffSessionCookie(deps, second.cookieValue))?.sid, second.sid);
  assert.equal(await revokeStaffSessionCookie(deps, second.cookieValue) !== null, true);
  assert.equal(await revokeStaffSessionCookie(deps, "basura"), null);
  assert.equal(await revokeStaffSessionCookie(deps, undefined), null);
});

test("TEST-CNS-1154 si falla la limpieza de expiradas el login sigue y solo se registra nombre/codigo del error (sin sid, hash, refs ni mensaje)", async () => {
  const sessions = createInMemoryStaffSessionStore();
  const failing = { ...sessions, purgeExpired: async () => { throw Object.assign(new TypeError(`detalle sensible ${who.principalRef}`), { code: "XX000" }); } };
  const printed: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { printed.push(a.map(String).join(" ")); };
  try {
    const issued = await issueStaffSession({ sessions: failing, staffSessionKey: key, nowMs: () => T0 }, who);
    assert.match(issued.cookieValue, /\./, "el login no falla");
  } finally {
    console.error = orig;
  }
  assert.deepEqual(printed, ["staff_session_purge_failed name=TypeError code=XX000"]);
});
