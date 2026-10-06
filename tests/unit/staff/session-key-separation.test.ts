// Gobierna: CA-140, specs/session.spec.yaml INV-SE-04 (separacion de claves HKDF). Con el MISMO secreto, las claves de sesion STAFF y CASE,
// sus tokens CSRF, el cursor de API-CNS-116 y la clave flash son todas distintas; comprometer una no compromete las demas. Solo sinteticos.
import test from "node:test";
import assert from "node:assert/strict";
import { hkdfSync } from "node:crypto";

import { CASE_CSRF_HKDF_INFO, CASE_SESSION_HKDF_INFO, caseCsrfTokenFor, deriveCaseSessionKey } from "../../../src/server/entrypoints/http/case-session.ts";
import { deriveRecoveryCsrfKey, deriveRecoveryHandleKey } from "../../../src/server/entrypoints/http/recovery-handle.ts";
import { STAFF_CSRF_HKDF_INFO, STAFF_SESSION_HKDF_INFO, deriveStaffSessionKey, staffCsrfTokenFor } from "../../../src/server/entrypoints/http/staff-session.ts";
import { FLASH_HKDF_INFO } from "../../../src/server/entrypoints/http/staff-ui.handler.ts";
import { STAFF_ROSTER_CURSOR_HKDF_INFO, deriveStaffRosterCursorKey } from "../../../src/server/modules/staff-roster/roster-cursor.ts";

test("TEST-CNS-1184 INV-SE-04: las claves HKDF de STAFF, CASE, CSRF, cursor y flash son distintas para el mismo secreto; el CSRF y la firma nunca coinciden", () => {
  const secret = Buffer.alloc(32, 9);
  const staffKey = deriveStaffSessionKey(secret);
  const caseKey = deriveCaseSessionKey(secret);
  const sid = "A".repeat(43);
  // el flash deriva de la clave STAFF con su propio info (CNS-STAFF-UI-FLASH-v1; no exportada: se reproduce la derivacion)
  const flashKey = Buffer.from(hkdfSync("sha256", staffKey, Buffer.alloc(0), FLASH_HKDF_INFO, 32));
  const csrfStaffKey = Buffer.from(hkdfSync("sha256", staffKey, Buffer.alloc(0), STAFF_CSRF_HKDF_INFO, 32));
  const csrfCaseKey = Buffer.from(hkdfSync("sha256", caseKey, Buffer.alloc(0), CASE_CSRF_HKDF_INFO, 32));
  // los info distintos son la garantia de la separacion: se comparan los exportados de produccion
  const infos = [STAFF_SESSION_HKDF_INFO, CASE_SESSION_HKDF_INFO, STAFF_CSRF_HKDF_INFO, CASE_CSRF_HKDF_INFO, FLASH_HKDF_INFO, STAFF_ROSTER_CURSOR_HKDF_INFO];
  assert.equal(new Set(infos).size, infos.length, "info HKDF distintos");
  const keys = [staffKey, caseKey, flashKey, csrfStaffKey, csrfCaseKey, deriveStaffRosterCursorKey(secret), deriveRecoveryHandleKey(secret), deriveRecoveryCsrfKey(secret), secret].map((k) => k.toString("hex"));
  assert.equal(new Set(keys).size, keys.length, "todas las claves son distintas");
  assert.notEqual(staffCsrfTokenFor(staffKey, sid), caseCsrfTokenFor(caseKey, sid), "mismo sid y secreto: el CSRF STAFF != CSRF CASE");
  assert.notEqual(staffCsrfTokenFor(staffKey, sid), staffCsrfTokenFor(caseKey, sid), "el CSRF depende de la clave de la consola");
});
