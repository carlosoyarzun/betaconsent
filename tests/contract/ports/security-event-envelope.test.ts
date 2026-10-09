// Gobierna: CA-141, contracts/schemas/security-event-payloads.schema.json (API-CNS-184: sobre SecurityEvent con el actor en el payload, F-1),
// specs/session.spec.yaml INV-SE-05. TEST-CNS-1202: cada evento que escriben los stores de sesion, proyectado al sobre, valida contra el contrato;
// los tipos de sesion no son transitorios del ledger; una proyeccion con PII o campos extra se rechaza. Solo datos sinteticos.

import assert from "node:assert/strict";
import test from "node:test";

import { createInMemoryCaseSessionStore } from "../../../src/infra/adapters/in-memory-case-session-store.adapter.ts";
import { createInMemorySecurityEventLog } from "../../../src/infra/adapters/in-memory-security-event.adapter.ts";
import { createInMemoryStaffSessionStore } from "../../../src/infra/adapters/in-memory-staff-session-store.adapter.ts";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { contractLedgerEventTypes, contractSecurityEventTypes, validateSecurityEvent } from "../../../src/server/modules/common/json-schema-lite.ts";
import { isLedgerEventType } from "../../../src/server/modules/common/ledger-event-types.ts";
import { OTP_FAMILY_SECURITY_EVENT_TYPES, SECURITY_EVENT_TYPES, type SecurityEventRecord } from "../../../src/server/ports/security-event.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

export function toEnvelope(e: SecurityEventRecord): Record<string, unknown> {
  return {
    eventId: e.eventId,
    eventType: e.eventType,
    schemaVersion: e.schemaVersion,
    tenantRef: e.tenantId,
    occurredAt: e.occurredAt.toISOString(),
    payload: { sessionKind: e.sessionKind, sessionRef: e.sessionRef, actorRef: e.actorRef, actorRole: e.actorRole, ...(e.caseRef ? { caseRef: e.caseRef } : {}) },
    environment: e.environment,
    dataClass: e.dataClass,
  };
}

test("TEST-CNS-1202 contrato API-CNS-184: cada evento de sesion proyectado al sobre SecurityEvent valida; con PII, campo extra o forma incoherente se rechaza; no son transitorios del ledger", async () => {
  const log = createInMemorySecurityEventLog();
  const staff = createInMemoryStaffSessionStore({ securityEvents: log });
  const cases = createInMemoryCaseSessionStore({ securityEvents: log });
  const T = fixtureUuid("t1202");
  const now = Date.now();
  const base = { issuedAtMs: now, expiresAtMs: now + 3_600_000 };
  await staff.create({ tenantId: T, sidHash: "a".repeat(64), principalRef: "staff-synthetic-01", role: "TENANT_ADMIN", ...base });
  await staff.revoke(T, "a".repeat(64), now, "USER_LOGOUT");
  await staff.create({ tenantId: T, sidHash: "b".repeat(64), principalRef: fixtureUuid("p1202"), role: "APPROVER", ...base });
  await staff.revoke(T, "b".repeat(64), now, "ROTATION");
  await cases.create({ tenantId: T, sidHash: "c".repeat(64), caseRef: fixtureUuid("c1202"), principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR", ...base });
  await cases.revoke(T, "c".repeat(64), now, "USER_LOGOUT");
  await cases.create({ tenantId: T, sidHash: "d".repeat(64), caseRef: fixtureUuid("c1202"), principalRef: "staff-synthetic-02", role: "APPROVER", ...base });
  await cases.revoke(T, "d".repeat(64), now, "ROTATION");
  const events = log.list(T);
  assert.deepEqual(new Set(events.map((e) => e.eventType)), new Set(["STAFF_LOGIN", "STAFF_LOGOUT", "SESSION_REVOKED_BY_ROTATION", "CASE_LOGIN", "CASE_LOGOUT"]));
  for (const e of events) {
    const v = validateSecurityEvent(toEnvelope(e));
    assert.ok(v.ok, `${e.eventType}: ${v.errors.join("; ")}`);
  }
  const ok = toEnvelope(events[0]!);
  const bad = (mut: (x: Record<string, unknown>) => void): boolean => {
    const copy = JSON.parse(JSON.stringify(ok)) as Record<string, unknown>;
    mut(copy);
    return validateSecurityEvent(copy).ok;
  };
  assert.equal(bad((x) => { (x.payload as Record<string, unknown>).email = "persona@ejemplo.cl"; }), false, "campo extra con PII");
  assert.equal(bad((x) => { (x.payload as Record<string, unknown>).actorRef = "persona@ejemplo.cl"; }), false, "actor con correo");
  assert.equal(bad((x) => { (x.payload as Record<string, unknown>).caseRef = fixtureUuid("x"); }), false, "STAFF con caseRef");
  assert.equal(bad((x) => { x.eventType = "CASE_LOGIN"; }), false, "tipo CASE con payload STAFF");
  assert.equal(bad((x) => { x.eventType = "OTP_ISSUED"; }), false);
  assert.equal(bad((x) => { delete (x.payload as Record<string, unknown>).sessionRef; }), false);
  // SEC-CNS-021 PR-2: los tipos OTP/RECOVERY/MANAGEMENT ya no son del ledger (0030); el contrato SECURITY = familia del puerto
  assert.deepEqual([...OTP_FAMILY_SECURITY_EVENT_TYPES].sort(), contractSecurityEventTypes().sort());
  for (const t of contractSecurityEventTypes()) assert.equal(isLedgerEventType(t), false, `${t} no debe estar en la lista blanca del ledger`);
  assert.ok(!contractSecurityEventTypes().includes("STAFF_LOGIN"));
  // R2: x-ops-only es EXACTAMENTE el vocabulario del puerto y no comparte ningun tipo con el ledger (ni con los transitorios SECURITY).
  const schema = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "contracts", "schemas", "security-event-payloads.schema.json"), "utf8")) as Record<string, unknown>;
  const opsOnly = schema["x-ops-only"] as string[];
  assert.deepEqual([...opsOnly].sort(), [...SECURITY_EVENT_TYPES].sort(), "x-ops-only == SECURITY_EVENT_TYPES");
  const ledgerSide = new Set<string>(contractLedgerEventTypes());
  assert.deepEqual(opsOnly.filter((t) => ledgerSide.has(t)), [], "ningun tipo de sesion es del ledger");
});
