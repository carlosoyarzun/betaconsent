// Gobierna: CA-139 (SEC-CNS-018 rev. 2 D-3, P1-1 de CA-138), src/server/entrypoints/http/case-session.ts. TEST-CNS-1160: sid aleatorio de
// 256 bits, iat/exp con reloj inyectado, firma, CSRF ligado al sid, emision sin PII (solo hash del sid) y rotacion. Solo datos sinteticos.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInMemoryCaseSessionStore } from "../../../src/infra/adapters/in-memory-case-session-store.adapter.ts";
import {
  decodeCaseSession,
  deriveCaseSessionKey,
  encodeCaseSession,
  hashCaseSid,
  issueCaseSession,
  newCaseSid,
  revokeCaseSessionCookie,
  serializeCaseSessionCookie,
  caseCsrfMatchesSession,
  caseCsrfTokenFor,
  type CaseSessionPayload,
} from "../../../src/server/entrypoints/http/case-session.ts";
import {
  APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS,
  APPROVED_CASE_SESSION_IDLE_TIMEOUT_MS,
} from "../../../src/server/modules/common/approved-parameters.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const key = deriveCaseSessionKey(randomBytes(32));
const T0 = 1_800_000_000_000;
const who = { tenantId: fixtureUuid("t1160"), caseRef: fixtureUuid("c1160"), principalRef: fixtureUuid("p1160"), role: "RIGHTS_OPERATOR" as const };
const payload = (over: Partial<CaseSessionPayload> = {}): CaseSessionPayload => ({ sid: "A".repeat(43), ...who, iat: T0, exp: T0 + 1000, ...over });

test("TEST-CNS-1160 sid: 32 bytes aleatorios (256 bits >= 128), base64url de 43 caracteres, distinto en cada llamada; su hash es sha256 hex", () => {
  const sids = new Set(Array.from({ length: 200 }, () => newCaseSid()));
  assert.equal(sids.size, 200);
  for (const sid of sids) assert.match(sid, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from([...sids][0]!, "base64url").length, 32);
  assert.match(hashCaseSid([...sids][0]!), /^[0-9a-f]{64}$/);
  assert.notEqual(hashCaseSid("A".repeat(43)), "A".repeat(43));
});

test("TEST-CNS-1160 decode: firma, formato, iat <= now < exp con reloj inyectado; sin nowMs solo valida firma; parametros aprobados 8 h / 30 min (Carlos, 2026-10-06)", () => {
  const cookie = encodeCaseSession(key, payload());
  assert.deepEqual(decodeCaseSession(key, cookie, T0), payload());
  assert.notEqual(decodeCaseSession(key, cookie, T0 + 999), null);
  assert.equal(decodeCaseSession(key, cookie, T0 + 1000), null, "exp absoluta: now >= exp");
  assert.equal(decodeCaseSession(key, cookie, T0 + 5000), null);
  assert.equal(decodeCaseSession(key, cookie, T0 - 1), null, "iat en el futuro");
  assert.notEqual(decodeCaseSession(key, cookie), null, "sin reloj: solo firma (logout de una cookie vencida)");
  assert.equal(decodeCaseSession(deriveCaseSessionKey(randomBytes(32)), cookie, T0), null, "otra clave");
  const [body, mac] = cookie.split(".") as [string, string];
  assert.equal(decodeCaseSession(key, `${body}.${mac.slice(0, -2)}xx`, T0), null);
  for (const bad of [payload({ exp: T0 }), payload({ sid: "corto" }), payload({ sid: "A".repeat(44) }), payload({ iat: Number.NaN }), { ...payload(), role: "ROOT" } as never, { ...payload(), sid: undefined } as never]) {
    assert.equal(decodeCaseSession(key, encodeCaseSession(key, bad), T0), null);
  }
  assert.equal(decodeCaseSession(key, undefined, T0), null);
  assert.equal(APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS, 8 * 60 * 60_000);
  assert.equal(APPROVED_CASE_SESSION_IDLE_TIMEOUT_MS, 30 * 60_000);
});

test("TEST-CNS-1160 CSRF ligado al sid: mismo sid mismo token, otro sid otro token, otra clave otro token; comparacion exacta", () => {
  const a = caseCsrfTokenFor(key, "A".repeat(43));
  assert.equal(caseCsrfTokenFor(key, "A".repeat(43)), a);
  assert.notEqual(caseCsrfTokenFor(key, "B".repeat(43)), a);
  assert.notEqual(caseCsrfTokenFor(deriveCaseSessionKey(randomBytes(32)), "A".repeat(43)), a);
  assert.equal(caseCsrfMatchesSession(key, "A".repeat(43), a), true);
  assert.equal(caseCsrfMatchesSession(key, "B".repeat(43), a), false);
  assert.equal(caseCsrfMatchesSession(key, "A".repeat(43), undefined), false);
  assert.equal(caseCsrfMatchesSession(key, "A".repeat(43), `${a}x`), false);
});

test("TEST-CNS-1160 issueCaseSession: iat/exp del reloj inyectado, registro con SOLO el hash del sid (sin sid ni cookie en el almacen), Max-Age = vida absoluta, rotacion revoca el sid previo", async () => {
  const sessions = createInMemoryCaseSessionStore();
  let now = T0;
  const deps = { sessions, caseSessionKey: key, nowMs: () => now };
  const first = await issueCaseSession(deps, who);
  const decoded = decodeCaseSession(key, first.cookieValue, now)!;
  assert.equal(decoded.sid, first.sid);
  assert.equal(decoded.iat, T0);
  assert.equal(decoded.exp, T0 + APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS);
  assert.equal(first.maxAgeSec, APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS / 1000);
  assert.match(serializeCaseSessionCookie("__Host-cns-case", first.cookieValue, first.maxAgeSec), /^__Host-cns-case=[^;]+; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800$/);
  assert.equal(first.csrfToken, caseCsrfTokenFor(key, first.sid));
  const stored = JSON.stringify(sessions.rows());
  assert.ok(!stored.includes(first.sid) && !stored.includes(first.cookieValue), "el sid en claro nunca se persiste");
  assert.ok(stored.includes(hashCaseSid(first.sid)));
  assert.deepEqual(Object.keys(sessions.rows()[0]!).sort(), ["caseRef", "expiresAtMs", "issuedAtMs", "lastSeenAtMs", "principalRef", "revokedAtMs", "role", "sidHash", "tenantId"]);

  // rotacion: un login con la cookie previa revoca ese sid y emite uno nuevo distinto
  now = T0 + 60_000;
  const second = await issueCaseSession(deps, who, first.cookieValue);
  assert.notEqual(second.sid, first.sid);
  const live = (sid: string) => sessions.validateAndTouch({ ...who, sidHash: hashCaseSid(sid), nowMs: now, idleTimeoutMs: APPROVED_CASE_SESSION_IDLE_TIMEOUT_MS });
  assert.equal(await live(first.sid), false, "el sid previo quedo revocado");
  assert.equal(await live(second.sid), true);

  // logout: revoca por cookie (aunque ya haya vencido por exp) y es idempotente; basura no hace nada
  now = T0 + APPROVED_CASE_SESSION_ABSOLUTE_TTL_MS + 1;
  assert.equal((await revokeCaseSessionCookie(deps, second.cookieValue))?.sid, second.sid);
  assert.equal(await revokeCaseSessionCookie(deps, second.cookieValue) !== null, true);
  assert.equal(await revokeCaseSessionCookie(deps, "basura"), null);
  assert.equal(await revokeCaseSessionCookie(deps, undefined), null);
});

test("TEST-CNS-1164 si falla la limpieza de expiradas el login sigue y solo se registra nombre/codigo del error (sin sid, hash, refs ni mensaje)", async () => {
  const sessions = createInMemoryCaseSessionStore();
  const failing = { ...sessions, purgeExpired: async () => { throw Object.assign(new TypeError(`detalle sensible ${who.principalRef}`), { code: "XX000" }); } };
  const printed: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { printed.push(a.map(String).join(" ")); };
  try {
    const issued = await issueCaseSession({ sessions: failing, caseSessionKey: key, nowMs: () => T0 }, who);
    assert.match(issued.cookieValue, /\./, "el login no falla");
  } finally {
    console.error = orig;
  }
  assert.deepEqual(printed, ["case_session_purge_failed name=TypeError code=XX000"]);
});
