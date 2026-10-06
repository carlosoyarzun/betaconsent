// Gobierna: CA-141, src/server/ports/security-event.port.ts (espejo de los CHECK de 0025), security-event-failure.ts (contador sin etiquetas),
// specs/session.spec.yaml GRD-SE-14 / ERR-SE-04. TEST-CNS-1203. Solo datos sinteticos.

import assert from "node:assert/strict";
import test from "node:test";

import { reportSecurityEventWriteFailure, securityEventUnavailable } from "../../../src/server/entrypoints/http/security-event-failure.ts";
import { SecurityEventValidationError, SecurityEventWriteError, validateSecurityEventEntry, type SecurityEventEntry } from "../../../src/server/ports/security-event.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const ok: SecurityEventEntry = { tenantId: fixtureUuid("t1203"), eventType: "STAFF_LOGIN", actorRef: "staff-synthetic-01", actorRole: "TENANT_ADMIN", sessionKind: "STAFF", sessionRef: fixtureUuid("s1203") };

test("TEST-CNS-1203 validateSecurityEventEntry espeja los CHECK (tipo, forma por familia, refs sin PII) y el 503 / contador no filtran valores", () => {
  assert.doesNotThrow(() => validateSecurityEventEntry(ok));
  assert.doesNotThrow(() => validateSecurityEventEntry({ ...ok, eventType: "CASE_LOGOUT", sessionKind: "CASE", actorRole: "APPROVER", caseRef: fixtureUuid("c") }));
  assert.doesNotThrow(() => validateSecurityEventEntry({ ...ok, eventType: "SESSION_REVOKED_BY_ROTATION" }));
  const bad: Partial<SecurityEventEntry>[] = [
    { actorRef: "persona@ejemplo.cl" }, { actorRef: "12.345.678-5" }, { sessionRef: "no-uuid" }, { caseRef: fixtureUuid("c") },
    { eventType: "CASE_LOGIN", sessionKind: "CASE", actorRole: "RIGHTS_OPERATOR" }, { eventType: "CASE_LOGIN", sessionKind: "CASE", actorRole: "TENANT_ADMIN", caseRef: fixtureUuid("c") },
    { eventType: "SESSION_REVOKED_BY_ROTATION", sessionKind: "CASE", actorRole: "APPROVER" }, { eventType: "OTP_ISSUED" as never }, { actorRole: "ROOT" as never },
  ];
  for (const over of bad) {
    assert.throws(() => validateSecurityEventEntry({ ...ok, ...over }), (e: unknown) => e instanceof SecurityEventValidationError && e instanceof SecurityEventWriteError && !JSON.stringify(Object.values(over)).split(",").some((v) => e.message.includes(v.replaceAll('"', "").replace(/[\[\]]/g, ""))));
  }
  const lines: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    reportSecurityEventWriteFailure(new SecurityEventWriteError("23514"));
    const res = securityEventUnavailable(new SecurityEventWriteError());
    assert.equal(res.status, 503);
    assert.deepEqual(Object.keys(res).sort(), ["body", "extraHeaders", "status"], "sin campos de cookies");
  } finally {
    console.error = orig;
  }
  assert.deepEqual(lines, ["security_event_write_failed name=SecurityEventWriteError code=23514", "security_event_write_failed name=SecurityEventWriteError"]);
});
