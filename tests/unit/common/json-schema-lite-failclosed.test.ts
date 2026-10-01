// Gobierna: CA-128 (X6 P1, INV-CM-05), common.spec.yaml ledgerEnvelope.payloadPolicy y ERR-RV-13.
// TEST-CNS-1000..1003: el validador del ledger es FAIL-CLOSED (sin palabras clave ignoradas en silencio).
// Solo datos sintéticos.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { assertLedgerPayload, LedgerPayloadViolationError } from "../../../src/server/modules/common/ledger-payload-contract.ts";
import {
  assertSchemaKeywordsSupported,
  isRfc3339DateTime,
  validateCommon,
} from "../../../src/server/modules/common/json-schema-lite.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const U = (l: string) => fixtureUuid(l);
const EMAIL = "padre@x.cl";

function rejected(eventType: string, payload: Record<string, unknown>): void {
  assert.throws(() => assertLedgerPayload(eventType, payload), LedgerPayloadViolationError, `${eventType} ${JSON.stringify(Object.keys(payload))}`);
}

test("TEST-CNS-1000 ledger: PII/valores fuera de contrato en rama null de oneOf, boolean, items/uniqueItems y dependentRequired -> ERR-RV-13", () => {
  const inv = { invitationRef: U("i"), participationRef: U("p"), enrollmentRef: U("e"), subjectRef: U("s") };
  // positivo: null y UUID válido (antes el UUID se rechazaba por calzar 2 ramas de oneOf)
  assert.doesNotThrow(() => assertLedgerPayload("INVITATION_CREATED", { ...inv, reissueOfRef: null }));
  assert.doesNotThrow(() => assertLedgerPayload("INVITATION_CREATED", { ...inv, reissueOfRef: U("old") }));
  rejected("INVITATION_CREATED", { ...inv, reissueOfRef: EMAIL });
  rejected("INVITATION_CREATED", { ...inv, reissueOfRef: 5 });
  rejected("INVITATION_CREATED", { ...inv, reissueOfRef: { rut: "1-9" } });

  assert.doesNotThrow(() => assertLedgerPayload("RECEIPT_CREATED", { receiptRef: U("r"), managementLinkIssued: true }));
  rejected("RECEIPT_CREATED", { receiptRef: U("r"), managementLinkIssued: EMAIL });
  rejected("RECEIPT_CREATED", { receiptRef: U("r"), managementLinkIssued: "true" });

  const down = { revocationRef: U("rv") };
  assert.doesNotThrow(() => assertLedgerPayload("REVOCATION_DOWNSTREAM_EMITTED", { ...down, subscriptionRefs: [U("a"), U("b")] }));
  rejected("REVOCATION_DOWNSTREAM_EMITTED", { ...down, subscriptionRefs: [EMAIL, { rut: "1-9" }] });
  rejected("REVOCATION_DOWNSTREAM_EMITTED", { ...down, subscriptionRefs: [U("a"), U("a")] });
  rejected("REVOCATION_DOWNSTREAM_EMITTED", { ...down, subscriptionRefs: EMAIL });

  assert.doesNotThrow(() => assertLedgerPayload("REVOCATION_CONFIRMED", { revocationRef: U("rv"), recordedByRef: U("x"), cosignedByRef: U("y") }));
  assert.doesNotThrow(() => assertLedgerPayload("REVOCATION_CONFIRMED", { revocationRef: U("rv") }));
  rejected("REVOCATION_CONFIRMED", { revocationRef: U("rv"), recordedByRef: U("x") });
  rejected("REVOCATION_CONFIRMED", { revocationRef: U("rv"), cosignedByRef: U("y") });
});

test("TEST-CNS-1001 seed LOCAL: solo objeto vacío; cualquier string arbitrario se rechaza", () => {
  assert.doesNotThrow(() => assertLedgerPayload("TENANT_SEEDED", {}));
  assert.doesNotThrow(() => assertLedgerPayload("SCHOOL_PARTICIPATION_SEEDED", {}));
  rejected("TENANT_SEEDED", { note: EMAIL });
  rejected("SCHOOL_PARTICIPATION_SEEDED", { count: 1 });
});

test("TEST-CNS-1002 validador: if/then/else, not, anyOf, oneOf exacto, null, formatos y longitudes", () => {
  // anyOf (common OriginPurposeRef) y minLength/maxLength (IdempotencyKey)
  assert.equal(validateCommon("OriginPurposeRef", "ALL").ok, true);
  assert.equal(validateCommon("OriginPurposeRef", "STUDY_PARTICIPATION").ok, true);
  assert.equal(validateCommon("OriginPurposeRef", "padre@x.cl").ok, false);
  assert.equal(validateCommon("OriginPurposeRef", null).ok, false);
  assert.equal(validateCommon("IdempotencyKey", "a".repeat(15)).ok, false);
  assert.equal(validateCommon("IdempotencyKey", "a".repeat(16)).ok, true);
  assert.equal(validateCommon("IdempotencyKey", "a".repeat(129)).ok, false);
  // format date-time RFC 3339 estricto
  assert.equal(validateCommon("Timestamp", "2026-10-01T12:00:00Z").ok, true);
  assert.equal(validateCommon("Timestamp", "2026-10-01T12:00:00.123+02:00").ok, true);
  for (const bad of ["2026-10-01", "2026-10-01 12:00:00Z", "2026-13-01T12:00:00Z", "2026-02-30T12:00:00Z", "2026-10-01T24:00:00Z", "2026-10-01T12:00:00", "2026-10-01t12:00:00z", "x"]) {
    assert.equal(isRfc3339DateTime(bad), false, bad);
    assert.equal(validateCommon("Timestamp", bad).ok, false, bad);
  }
  assert.equal(isRfc3339DateTime("2028-02-29T00:00:00Z"), true);
  assert.equal(isRfc3339DateTime("2027-02-29T00:00:00Z"), false);
  // else + not (ENROLLMENT_STATUS_CHANGED: closeReason prohibido si el estado no es el que lo exige)
  const base = { enrollmentRef: U("e"), participationRef: U("p") };
  const ok = (payload: Record<string, unknown>) => assert.doesNotThrow(() => assertLedgerPayload("ENROLLMENT_STATUS_CHANGED", payload));
  ok({ ...base, subjectRef: U("s"), toStatus: "ACTIVE" });
  ok({ ...base, subjectRef: U("s"), toStatus: "CLOSED", closeReason: "TRANSFERRED" });
  rejected("ENROLLMENT_STATUS_CHANGED", { ...base, subjectRef: U("s"), toStatus: "ACTIVE", closeReason: "TRANSFERRED" }); // else/not
  rejected("ENROLLMENT_STATUS_CHANGED", { ...base, subjectRef: U("s"), toStatus: "CLOSED" }); // then
});

test("TEST-CNS-1003 fail-closed: palabra clave desconocida lanza; todos los $defs de ledger y security usan solo palabras soportadas", () => {
  assert.throws(() => assertSchemaKeywordsSupported({ type: "string", patternProperties: {} }), /no soportada/);
  assert.throws(() => assertSchemaKeywordsSupported({ properties: { a: { exclusiveMinimum: 1 } } }), /no soportada/);
  assert.throws(() => assertSchemaKeywordsSupported({ type: "string", format: "uri" }), /format no soportado/);
  assert.throws(() => assertSchemaKeywordsSupported({ type: "bigint" }), /type no soportado/);
  assert.throws(() => assertSchemaKeywordsSupported({ oneOf: [{ type: "null" }, { containss: 1 }] }), /no soportada/);
  assert.doesNotThrow(() => assertSchemaKeywordsSupported({ type: ["string", "null"], "x-nota": 1, description: "d" }));
  for (const file of ["ledger-event-payloads.schema.json", "security-event-payloads.schema.json"]) {
    const doc = JSON.parse(readFileSync(new URL(`../../../contracts/schemas/${file}`, import.meta.url), "utf8")) as { $defs: Record<string, unknown> };
    assert.ok(Object.keys(doc.$defs).length > 0);
    for (const [name, def] of Object.entries(doc.$defs)) {
      assert.doesNotThrow(() => assertSchemaKeywordsSupported(def, `${file}#/$defs/${name}`), `${file}#/$defs/${name}`);
    }
  }
});
