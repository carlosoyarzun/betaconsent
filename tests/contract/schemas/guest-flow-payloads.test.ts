// Gobierna: contracts/schemas/api-payloads.schema.json (DecisionRecorded, DecisionStepRecorded,
// SubjectMismatchAck) y contracts/openapi/consent-it0.openapi.yaml API-CNS-126/127/128; D-02 (Carlos,
// 2026-10-14): `subjectLabel` es opcional, de solo lectura y solo "Alumno de prueba N" (nunca PII ni RUT).
// El comprobante/respuesta nunca incluye el enlace de gestión. TEST-CNS-1410.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { validateApiPayload } from "../schema-lite.ts";

const REF = "5f1c3b0e-8a7d-4a39-9d5e-0b1f6a2c4d11";

test("TEST-CNS-1410: DecisionRecorded y DecisionStepRecorded admiten subjectLabel sintético opcional y rechazan etiquetas con PII/RUT o campos de enlace de gestión; SubjectMismatchAck exige INVITATION_CANCELLED", () => {
  const recorded = { consentId: REF, state: "GRANTED", receiptRef: REF };
  assert.ok(validateApiPayload("DecisionRecorded", recorded).ok);
  assert.ok(validateApiPayload("DecisionRecorded", { ...recorded, subjectLabel: "Alumno de prueba 3" }).ok);
  assert.ok(!validateApiPayload("DecisionRecorded", { ...recorded, subjectLabel: "Martina González" }).ok);
  assert.ok(!validateApiPayload("DecisionRecorded", { ...recorded, subjectLabel: "24.123.456-7" }).ok);
  assert.ok(!validateApiPayload("DecisionRecorded", { ...recorded, managementLink: "/m/x" }).ok);

  const step = { stepKind: "CONTEXT_INFORMATION_VIEWED", state: "PENDING" };
  assert.ok(validateApiPayload("DecisionStepRecorded", step).ok);
  assert.ok(validateApiPayload("DecisionStepRecorded", { ...step, subjectLabel: "Alumno de prueba 12" }).ok);
  assert.ok(!validateApiPayload("DecisionStepRecorded", { ...step, subjectLabel: "Alumno real" }).ok);

  assert.ok(validateApiPayload("SubjectMismatchAck", { result: "INVITATION_CANCELLED" }).ok);
  assert.ok(!validateApiPayload("SubjectMismatchAck", { result: "OK" }).ok);

  const openapi = readFileSync(fileURLToPath(new URL("../../../contracts/openapi/consent-it0.openapi.yaml", import.meta.url)), "utf8");
  assert.match(openapi, /subjectLabel/);
  assert.match(openapi, /operationId: reportSubjectMismatch/);
});
