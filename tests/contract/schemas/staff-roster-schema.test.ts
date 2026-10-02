// Gobierna: API-CNS-116, api-payloads.schema.json StaffRosterPage/StaffRosterRow/StaffInvitationStatus, REQ-CNS-036 AC-04/AC-06.
// TEST-CNS-1080 (lint de contrato): la fila solo tiene 4 campos, el enum es el vocabulario operativo (no el de dominio) y
// participationRef nulo salvo NOT_INVITED.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { validateApiPayload } from "../schema-lite.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

const schema = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "..", "contracts", "schemas", "api-payloads.schema.json"), "utf8")) as { $defs: Record<string, any> };

test("TEST-CNS-1080 contrato: StaffRosterRow solo expone 4 campos; ninguno prohibido; enum operativo sin vocabulario de dominio", () => {
  const row = schema.$defs.StaffRosterRow;
  assert.deepEqual(Object.keys(row.properties).sort(), ["invitationStatus", "participationRef", "subjectLabel", "subjectRef"]);
  assert.equal(row.additionalProperties, false);
  assert.deepEqual(schema.$defs.StaffInvitationStatus.enum, ["NOT_INVITED", "PENDING_SEND", "SENT", "DECISION_RECORDED", "CLOSED_WITHOUT_DECISION"]);
  for (const domain of ["COMPLETED", "DECLINED", "OPENED", "VERIFIED", "READY", "DRAFT", "EXPIRED", "CANCELLED"]) {
    assert.ok(!schema.$defs.StaffInvitationStatus.enum.includes(domain), domain);
  }
  const ref = fixtureUuid("r");
  const ok = (status: string, participationRef: string | null): boolean =>
    validateApiPayload("StaffRosterPage", { items: [{ subjectRef: ref, participationRef, subjectLabel: null, invitationStatus: status }], nextCursor: null }).ok;
  assert.equal(ok("NOT_INVITED", ref), true);
  assert.equal(ok("SENT", ref), false, "participationRef solo en NOT_INVITED");
  assert.equal(ok("SENT", null), true);
  assert.equal(ok("COMPLETED", null), false);
  assert.equal(validateApiPayload("StaffRosterPage", { items: [{ subjectRef: ref, participationRef: null, subjectLabel: "Juan", invitationStatus: "SENT" }], nextCursor: null }).ok, false);
  assert.equal(validateApiPayload("StaffRosterPage", { items: [{ subjectRef: ref, participationRef: null, subjectLabel: null, invitationStatus: "SENT", sentOn: "2026-01-01" }], nextCursor: null }).ok, false);
});
