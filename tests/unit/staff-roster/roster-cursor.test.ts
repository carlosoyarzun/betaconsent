// Gobierna: API-CNS-116, SEC-CNS-018 rev. 2 (R4). TEST-CNS-1085: cursor AES-256-GCM c1. (HKDF, AAD canonico, TTL 15 min,
// version, UUIDv4 tras descifrar) y carga del secreto por entorno. Solo datos sinteticos.

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import {
  decodeRosterCursor,
  deriveStaffRosterCursorKey,
  encodeRosterCursor,
  loadStaffRosterCursorSecret,
  RosterCursorInvalidError,
  STAFF_ROSTER_CURSOR_TTL_MS,
} from "../../../src/server/modules/staff-roster/roster-cursor.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const key = deriveStaffRosterCursorKey(randomBytes(32));
const scope = { tenantId: fixtureUuid("t1085"), principalRef: fixtureUuid("p1085"), role: "TENANT_ADMIN", sid: "A".repeat(43) };
const position = { subjectRef: fixtureUuid("s1085"), contextRef: "BETA_2026_01" };
const bad = (fn: () => unknown): void => assert.throws(fn, (e: unknown) => e instanceof RosterCursorInvalidError);

test("TEST-CNS-1085 cursor: ida y vuelta, formato c1., sin la posicion en claro", () => {
  const cursor = encodeRosterCursor(key, scope, position, 1_000);
  assert.match(cursor, /^c1\.[A-Za-z0-9_-]{40,400}$/);
  assert.ok(!cursor.includes(position.subjectRef));
  assert.deepEqual(decodeRosterCursor(key, scope, cursor, 1_000 + 5_000), position);
  assert.notEqual(encodeRosterCursor(key, scope, position, 1_000), cursor, "nonce aleatorio");
});

test("TEST-CNS-1085 cursor: manipulado, otro tenant/principal/rol, otra clave, expirado, futuro, version o formato desconocido -> mismo error", () => {
  const cursor = encodeRosterCursor(key, scope, position, 1_000);
  const flip = cursor.slice(0, -3) + (cursor.endsWith("AAA") ? "BBB" : "AAA");
  bad(() => decodeRosterCursor(key, scope, flip, 1_000));
  bad(() => decodeRosterCursor(key, { ...scope, tenantId: fixtureUuid("otro") }, cursor, 1_000));
  bad(() => decodeRosterCursor(key, { ...scope, principalRef: fixtureUuid("otro") }, cursor, 1_000));
  bad(() => decodeRosterCursor(key, { ...scope, role: "RIGHTS_OPERATOR" }, cursor, 1_000));
  bad(() => decodeRosterCursor(deriveStaffRosterCursorKey(randomBytes(32)), scope, cursor, 1_000));
  bad(() => decodeRosterCursor(key, scope, cursor, 1_000 + STAFF_ROSTER_CURSOR_TTL_MS + 1));
  assert.deepEqual(decodeRosterCursor(key, scope, cursor, 1_000 + STAFF_ROSTER_CURSOR_TTL_MS), position, "justo en el TTL");
  bad(() => decodeRosterCursor(key, scope, cursor, 999)); // iat en el futuro
  bad(() => decodeRosterCursor(key, scope, `c2.${cursor.slice(3)}`, 1_000));
  bad(() => decodeRosterCursor(key, scope, cursor.slice(3), 1_000));
  for (const junk of ["", "c1.", "c1.@@@", `c1.${"A".repeat(500)}`, "x".repeat(60)]) bad(() => decodeRosterCursor(key, scope, junk, 1_000));
});

test("TEST-CNS-1085 cursor: el AAD es inambiguo (tenant/principal desplazados no colisionan) y lastSubjectRef debe ser UUIDv4 tras descifrar", () => {
  const a = { tenantId: "ab", principalRef: "c", role: "TENANT_ADMIN", sid: "s" };
  const b = { tenantId: "a", principalRef: "bc", role: "TENANT_ADMIN", sid: "s" };
  const cursor = encodeRosterCursor(key, a, position, 1_000);
  bad(() => decodeRosterCursor(key, b, cursor, 1_000));
  bad(() => decodeRosterCursor(key, scope, encodeRosterCursor(key, scope, { subjectRef: "no-es-uuid", contextRef: "BETA_2026_01" }, 1_000), 1_000));
  bad(() => decodeRosterCursor(key, scope, encodeRosterCursor(key, scope, { subjectRef: position.subjectRef, contextRef: "minuscula" }, 1_000), 1_000));
});

test("TEST-CNS-1085 secreto del cursor: LOCAL usa constante; fuera de LOCAL no arranca sin secreto; base64 >= 32 bytes", () => {
  assert.ok(loadStaffRosterCursorSecret({}, "LOCAL").length >= 32);
  for (const env of ["DEV", "STAGING", "PRODUCTION"]) assert.throws(() => loadStaffRosterCursorSecret({}, env), /CNS_STAFF_ROSTER_CURSOR_SECRET/);
  assert.throws(() => loadStaffRosterCursorSecret({ CNS_STAFF_ROSTER_CURSOR_SECRET: Buffer.alloc(8).toString("base64") }, "DEV"), /32 bytes/);
  const secret = randomBytes(32);
  assert.deepEqual(loadStaffRosterCursorSecret({ CNS_STAFF_ROSTER_CURSOR_SECRET: secret.toString("base64") }, "DEV"), secret);
  assert.throws(() => deriveStaffRosterCursorKey(Buffer.alloc(8)));
});

test("TEST-CNS-1144 cursor ligado al sid (CA-138): un cursor de otra sesion, aunque del mismo tenant/principal/rol, no descifra", () => {
  const cursor = encodeRosterCursor(key, scope, position, 1_000);
  assert.deepEqual(decodeRosterCursor(key, scope, cursor, 1_000), position);
  bad(() => decodeRosterCursor(key, { ...scope, sid: "B".repeat(43) }, cursor, 1_000));
});
