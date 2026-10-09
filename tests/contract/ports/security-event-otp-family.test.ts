// Gobierna: SEC-CNS-021 PR-1 (aceptada por Carlos 2026-10-08; CA-146 / P-34), INV-21-04, contracts/schemas/security-event-payloads.schema.json
// (API-CNS-184), src/server/ports/security-event.port.ts, db/migrations/0029_security_event_otp_family.sql, SEC-CNS-006 rev. 5.
// TEST-CNS-1304 (contrato, sin Postgres): la entrada del puerto para OTP_* / RECOVERY / MANAGEMENT, proyectada al sobre SecurityEvent, valida
// contra el JSON schema; lo que el CHECK de la base rechaza, el validador y el schema tambien (paridad de combinaciones); el vocabulario del
// puerto == enums del schema == enums de 0029. Un campo desconocido (PII) se rechaza por nombre. Solo datos sinteticos.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createInMemorySecurityEventLog } from "../../../src/infra/adapters/in-memory-security-event.adapter.ts";
import { validateSecurityEvent } from "../../../src/server/modules/common/json-schema-lite.ts";
import {
  ALL_SECURITY_EVENT_TYPES,
  MANAGEMENT_TOKEN_TRIGGERS,
  RECOVERY_TOKEN_TRIGGERS,
  SECURITY_EVENT_KEY_KINDS,
  SECURITY_EVENT_OTP_SCOPES,
  SECURITY_EVENT_SCOPE_CLASSES,
  SECURITY_EVENT_WINDOW_KINDS,
  SecurityEventValidationError,
  validateSecurityEventEntry,
  type AnySecurityEventRecord,
  type OtpFamilySecurityEventEntry,
} from "../../../src/server/ports/security-event.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const T = fixtureUuid("t1304");
const V = fixtureUuid("v1304");
const CH = fixtureUuid("ch1304");
const CN = fixtureUuid("cn1304");
const RC = fixtureUuid("rc1304");

const VALID: OtpFamilySecurityEventEntry[] = [
  { tenantId: T, eventType: "OTP_ISSUED", verificationRef: V, otpScope: "DECISION", channelRef: CH },
  { tenantId: T, eventType: "OTP_FAILED", verificationRef: V, otpScope: "REVOCATION" },
  { tenantId: T, eventType: "OTP_LOCKED", verificationRef: V, otpScope: "MANAGE" },
  { tenantId: T, eventType: "OTP_EXPIRED", verificationRef: V, otpScope: "DECISION" },
  { tenantId: T, eventType: "OTP_BUDGET_EXHAUSTED", verificationRef: V, scopeClass: "DECISION", keyKind: "CHANNEL", windowKind: "DAY_1" },
  { tenantId: T, eventType: "OTP_BUDGET_EXHAUSTED", verificationRef: V, scopeClass: "DECISION", keyKind: "INVITATION", windowKind: "DAY_1" },
  { tenantId: T, eventType: "OTP_BUDGET_EXHAUSTED", verificationRef: V, scopeClass: "RIGHTS", keyKind: "CHAIN", windowKind: "DAYS_30" },
  { tenantId: T, eventType: "RECOVERY_TOKEN_ISSUED", recoveryRef: RC, trigger: "LIMIT_REACHED" },
  { tenantId: T, eventType: "MANAGEMENT_TOKEN_ROTATED", chainRef: CN, trigger: "RECEIPT_REISSUED" },
];

/** Proyeccion al sobre SecurityEvent (payload del contrato; el sobre lleva eventId/tenantRef/occurredAt/environment/dataClass). */
function envelopeOf(r: AnySecurityEventRecord): Record<string, unknown> {
  const e = r as unknown as Record<string, string>;
  let payload: Record<string, unknown>;
  switch (r.eventType) {
    case "OTP_ISSUED": payload = { verificationRef: e.verificationRef, scope: e.otpScope, channelRef: e.channelRef }; break;
    case "OTP_FAILED": case "OTP_LOCKED": case "OTP_EXPIRED": payload = { verificationRef: e.verificationRef, scope: e.otpScope }; break;
    case "OTP_BUDGET_EXHAUSTED": payload = { verificationRef: e.verificationRef, scopeClass: e.scopeClass, keyKind: e.keyKind, windowKind: e.windowKind }; break;
    case "RECOVERY_TOKEN_ISSUED": payload = { recoveryRef: e.recoveryRef, trigger: e.trigger }; break;
    case "MANAGEMENT_TOKEN_ROTATED": payload = { chainRef: e.chainRef, trigger: e.trigger }; break;
    default: throw new Error("tipo de sesion fuera de esta prueba");
  }
  return {
    eventId: e.eventId, eventType: r.eventType, schemaVersion: "1.0.0", tenantRef: r.tenantId,
    occurredAt: (r as { occurredAt: Date }).occurredAt.toISOString(), payload, environment: "LOCAL", dataClass: "SYNTHETIC",
  };
}

test("TEST-CNS-1304 contrato: la familia OTP/RECOVERY/MANAGEMENT del puerto valida contra el sobre SecurityEvent y el validador rechaza lo que rechaza el CHECK de 0029 (INV-21-04)", async () => {
  const log = createInMemorySecurityEventLog();
  for (const entry of VALID) {
    assert.doesNotThrow(() => validateSecurityEventEntry(entry), entry.eventType);
    await log.record(entry);
  }
  const stored = log.listAll(T);
  assert.equal(stored.length, VALID.length);
  assert.deepEqual(log.list(T), [], "list() sigue siendo solo de sesion");
  for (const r of stored) {
    const v = validateSecurityEvent(envelopeOf(r));
    assert.ok(v.ok, `${r.eventType}: ${v.errors.join("; ")}`);
  }

  // Combinaciones prohibidas (CFG-OT-BUDGET): las rechaza el puerto Y el schema.
  const budget = (over: Record<string, string>): OtpFamilySecurityEventEntry =>
    ({ tenantId: T, eventType: "OTP_BUDGET_EXHAUSTED", verificationRef: V, scopeClass: "DECISION", keyKind: "CHANNEL", windowKind: "DAY_1", ...over }) as OtpFamilySecurityEventEntry;
  const forbidden = [
    budget({ scopeClass: "RIGHTS", keyKind: "INVITATION" }),
    budget({ keyKind: "CHAIN" }),
    budget({ windowKind: "DAYS_30" }),
    budget({ scopeClass: "RIGHTS", windowKind: "DAYS_30" }),
  ];
  const probe = createInMemorySecurityEventLog();
  for (const bad of forbidden) {
    assert.throws(() => validateSecurityEventEntry(bad), SecurityEventValidationError, JSON.stringify([bad.eventType, (bad as unknown as Record<string, string>).keyKind]));
    // El schema tambien las rechaza: se proyecta saltando el puerto.
    const b = bad as unknown as Record<string, string>;
    const env = envelopeOf({ ...bad, eventId: fixtureUuid("e1304"), schemaVersion: "1.0.0", occurredAt: new Date(), environment: "LOCAL", dataClass: "SYNTHETIC" } as unknown as AnySecurityEventRecord);
    assert.equal(validateSecurityEvent(env).ok, false, `schema acepto ${b.scopeClass}/${b.keyKind}/${b.windowKind}`);
  }
  assert.deepEqual(probe.listAll(), []);

  // Refs que no son UUIDv4, enums fuera de rango, campos faltantes y desconocidos (PII) -> error por NOMBRE de campo, nunca el valor.
  const bads: Array<[Record<string, unknown>, string]> = [
    [{ ...VALID[0], verificationRef: "persona@ejemplo.cl" }, "verificationRef"],
    [{ ...VALID[0], channelRef: "12.345.678-5" }, "channelRef"],
    [{ ...VALID[0], otpScope: "ROOT" }, "otpScope"],
    [{ ...VALID[0], channelRef: undefined }, "channelRef"],
    [{ ...VALID[1], channelRef: CH }, "unknownField"],
    [{ ...VALID[1], email: "persona@ejemplo.cl" }, "unknownField"],
    [{ ...VALID[7], trigger: "FAILURE_CAP" }, "trigger"],
    [{ ...VALID[8], trigger: "CASE_CONTACT" }, "trigger"],
    [{ ...VALID[8], chainRef: "chain-1" }, "chainRef"],
    [{ ...VALID[7], recoveryRef: "no-uuid" }, "recoveryRef"],
    [{ ...VALID[4], windowKind: "HOURS_1" }, "windowKind"],
    [{ ...VALID[0], tenantId: "" }, "tenantId"],
  ];
  for (const [bad, field] of bads) {
    assert.throws(
      () => validateSecurityEventEntry(bad as unknown as OtpFamilySecurityEventEntry),
      (e: unknown) => e instanceof SecurityEventValidationError && e.field === field && !/@|12\.345|chain-1|no-uuid|ROOT/.test((e as Error).message),
      field,
    );
  }
  // El sobre rechaza campos de PII en el payload.
  const env = envelopeOf(stored[0]!);
  (env.payload as Record<string, unknown>).email = "persona@ejemplo.cl";
  assert.equal(validateSecurityEvent(env).ok, false);

  // Paridad de vocabulario: puerto == schema == CHECK de 0029.
  const schema = JSON.parse(readFileSync(join(ROOT, "contracts", "schemas", "security-event-payloads.schema.json"), "utf8")) as { $defs: Record<string, any> };
  assert.deepEqual([...schema.$defs.SecurityEvent.properties.eventType.enum].sort(), [...ALL_SECURITY_EVENT_TYPES].sort(), "enum de eventType del sobre == tipos del puerto");
  assert.deepEqual([...schema.$defs.OTP_BUDGET_EXHAUSTED.properties.keyKind.enum].sort(), [...SECURITY_EVENT_KEY_KINDS].sort());
  assert.deepEqual([...schema.$defs.OTP_BUDGET_EXHAUSTED.properties.windowKind.enum].sort(), [...SECURITY_EVENT_WINDOW_KINDS].sort());
  assert.deepEqual([...schema.$defs.RECOVERY_TOKEN_ISSUED.properties.trigger.enum].sort(), [...RECOVERY_TOKEN_TRIGGERS].sort());
  assert.deepEqual([...schema.$defs.MANAGEMENT_TOKEN_ROTATED.properties.trigger.enum].sort(), [...MANAGEMENT_TOKEN_TRIGGERS].sort());

  const sql = readFileSync(join(ROOT, "db", "migrations", "0029_security_event_otp_family.sql"), "utf8").replace(/--[^\n]*/g, "");
  const listOf = (column: string): string[] => {
    const m = new RegExp(`CHECK \\(${column} IN \\(([^)]*)\\)\\)`).exec(sql);
    assert.ok(m, `no hay CHECK de enum para ${column} en 0029`);
    return [...m![1]!.matchAll(/'([A-Z0-9_]+)'/g)].map((x) => x[1]!).sort();
  };
  assert.deepEqual(listOf("otp_scope"), [...SECURITY_EVENT_OTP_SCOPES].sort());
  assert.deepEqual(listOf("scope_class"), [...SECURITY_EVENT_SCOPE_CLASSES].sort());
  assert.deepEqual(listOf("key_kind"), [...SECURITY_EVENT_KEY_KINDS].sort());
  assert.deepEqual(listOf("window_kind"), [...SECURITY_EVENT_WINDOW_KINDS].sort());
  assert.deepEqual(listOf("trigger_kind"), [...RECOVERY_TOKEN_TRIGGERS, ...MANAGEMENT_TOKEN_TRIGGERS].sort());
  const typeEnum = /security_event_type_enum CHECK \(event_type IN \(([^)]*)\)\)/.exec(sql);
  assert.ok(typeEnum, "no hay security_event_type_enum en 0029");
  assert.deepEqual([...typeEnum![1]!.matchAll(/'([A-Z_]+)'/g)].map((x) => x[1]!).sort(), [...ALL_SECURITY_EVENT_TYPES].sort(), "CHECK de tipo de 0029 == tipos del puerto");
});
