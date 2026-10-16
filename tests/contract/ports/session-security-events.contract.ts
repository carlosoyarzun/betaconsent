// Gobierna: CA-141 (decision de Carlos, 2026-10-06; D-3 fail-closed), specs/session.spec.yaml GRD-SE-14 / INV-SE-05 / INV-SE-06,
// src/server/ports/staff-session-store.port.ts (ADR-010 rev. 5 6d parte 2: las sesiones CASE salieron de app; sus eventos viven en platform.session_event, TEST-CNS-1550+) y security-event.port.ts. Suite de contrato compartida memoria/Postgres de los eventos de
// seguridad que escriben los stores de sesion en la MISMA transaccion: TEST-CNS-1194 (login), 1195 (logout; el logout idempotente no escribe),
// 1196 (rotacion; el evento nace en el tenant de la sesion previa y no lleva datos de la nueva), 1197 (atomicidad ante un fallo del evento) y 1200 (logout concurrente con rotacion: un solo evento).
// Los eventos se leen por un lector del harness (en Postgres, la conexion del dueno: app_rw no puede leer, D-5). Solo datos sinteticos.

import assert from "node:assert/strict";

import { SecurityEventWriteError, type SecurityEventEntry } from "../../../src/server/ports/security-event.port.ts";
import type { StaffSessionStorePort } from "../../../src/server/ports/staff-session-store.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

export interface EventView {
  readonly eventType: string;
  readonly tenantId: string;
  readonly actorRef: string | null;
  readonly actorRole: string | null;
  readonly sessionKind: string | null;
  readonly sessionRef: string | null;
  readonly caseRef: string | null;
}

export interface SessionEventsHarness {
  readonly staff: StaffSessionStorePort;
  /** Eventos del tenant en orden de insercion. */
  events(tenantId: string): Promise<readonly EventView[]>;
  /** session_ref de la fila de sesion (o null si no existe). */
  sessionRefOf(kind: "STAFF" | "CASE", tenantId: string, sidHash: string): Promise<string | null>;
  /** revoked_at no nulo de la fila (null si la fila no existe). */
  revokedOf(kind: "STAFF" | "CASE", tenantId: string, sidHash: string): Promise<boolean | null>;
  /** Inyecta (true) o quita (false) un fallo en la escritura del evento. */
  failEvents(on: boolean): Promise<void>;
}

export type RegisterSessionEventsTest = (name: string, body: (h: SessionEventsHarness) => Promise<void>) => void;

export const UUIDV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hex = (label: string): string => fixtureUuid(label).replaceAll("-", "").padEnd(64, "0").slice(0, 64);
const T0 = Date.now();
const ABS = 8 * 3_600_000;
const staffRec = (tenantId: string, label: string, principalRef: string, role: "TENANT_ADMIN" | "RIGHTS_OPERATOR" | "APPROVER" = "TENANT_ADMIN") =>
  ({ tenantId, sidHash: hex(label), principalRef, role, issuedAtMs: T0, expiresAtMs: T0 + ABS });
export function runSessionSecurityEventsContract(register: RegisterSessionEventsTest): void {
  register("TEST-CNS-1194 login: crear una sesion STAFF escribe exactamente UN evento *_LOGIN con el session_ref de la fila (UUIDv4 distinto por sesion), el actor del registro y, en CASE, el caseRef; un sid repetido no escribe nada", async (h) => {
    const T = fixtureUuid("t1194");
    const admin = fixtureUuid("admin-1194");
    const created = await h.staff.create(staffRec(T, "a", admin));
    assert.match(created.sessionRef, UUIDV4);
    assert.equal(await h.sessionRefOf("STAFF", T, hex("a")), created.sessionRef, "el sessionRef devuelto es el de la fila");
    assert.deepEqual(await h.events(T), [
      { eventType: "STAFF_LOGIN", tenantId: T, actorRef: admin, actorRole: "TENANT_ADMIN", sessionKind: "STAFF", sessionRef: created.sessionRef, caseRef: null },
    ]);
    // todos los roles de staff proyectan a un evento valido (INV-SE-06)
    const op = await h.staff.create(staffRec(T, "b", "staff-synthetic-01", "RIGHTS_OPERATOR"));
    const ap = await h.staff.create(staffRec(T, "c", "staff-synthetic-03", "APPROVER"));
    assert.equal(new Set([created.sessionRef, op.sessionRef, ap.sessionRef]).size, 3, "un session_ref distinto por sesion");

    const before = (await h.events(T)).length;
    await assert.rejects(() => h.staff.create(staffRec(T, "a", admin)), "un sid no se reutiliza");
    assert.equal((await h.events(T)).length, before, "un create rechazado no deja evento");
  });

  register("TEST-CNS-1195 logout: revocar una sesion activa (USER_LOGOUT) escribe UN evento *_LOGOUT con el actor de la FILA y el mismo session_ref del login; un segundo logout, un sid desconocido o de otro tenant no escriben nada", async (h) => {
    const T = fixtureUuid("t1195");
    const OTHER = fixtureUuid("t1195-other");
    const admin = fixtureUuid("admin-1195");
    const s = await h.staff.create(staffRec(T, "a", admin, "APPROVER"));
    assert.equal(await h.staff.revoke(OTHER, hex("a"), T0 + 1, "USER_LOGOUT"), false, "otro tenant: la sesion no existe");
    assert.equal(await h.staff.revoke(T, hex("a"), T0 + 2, "USER_LOGOUT"), true);
    assert.equal(await h.staff.revoke(T, hex("a"), T0 + 3, "USER_LOGOUT"), false, "segundo logout: idempotente, sin evento");
    assert.equal(await h.staff.revoke(T, hex("desconocido"), T0 + 3, "USER_LOGOUT"), false);
    assert.deepEqual((await h.events(T)).map((e) => [e.eventType, e.sessionRef]), [
      ["STAFF_LOGIN", s.sessionRef],
      ["STAFF_LOGOUT", s.sessionRef],
    ]);
    const logout = (await h.events(T)).filter((e) => e.eventType.endsWith("_LOGOUT"));
    assert.deepEqual(logout.map((e) => [e.actorRef, e.actorRole, e.caseRef]), [[admin, "APPROVER", null]]);
    assert.deepEqual(await h.events(OTHER), [], "nada en el tenant ajeno");
  });

  register("TEST-CNS-1196 rotacion: revocar con cause ROTATION escribe SESSION_REVOKED_BY_ROTATION en el tenant de la sesion PREVIA, con su actor y su session_ref; el LOGIN nuevo de otro tenant no comparte tenant, principal ni session_ref con ese evento", async (h) => {
    const A = fixtureUuid("t1196-a");
    const B = fixtureUuid("t1196-b");
    const prevAdmin = fixtureUuid("admin-1196-a");
    const newAdmin = fixtureUuid("admin-1196-b");
    const prev = await h.staff.create(staffRec(A, "prev", prevAdmin));
    assert.equal(await h.staff.revoke(A, hex("prev"), T0 + 5, "ROTATION"), true);
    const next = await h.staff.create(staffRec(B, "next", newAdmin, "APPROVER"));
    const evA = await h.events(A);
    assert.deepEqual(evA.map((e) => e.eventType), ["STAFF_LOGIN", "SESSION_REVOKED_BY_ROTATION"]);
    const rotation = evA[1]!;
    assert.deepEqual(rotation, { eventType: "SESSION_REVOKED_BY_ROTATION", tenantId: A, actorRef: prevAdmin, actorRole: "TENANT_ADMIN", sessionKind: "STAFF", sessionRef: prev.sessionRef, caseRef: null });
    const serialized = JSON.stringify(evA);
    for (const leak of [B, newAdmin, next.sessionRef]) assert.ok(!serialized.includes(leak), "el evento del tenant A no lleva datos de la sesion nueva del tenant B");
    assert.deepEqual((await h.events(B)).map((e) => [e.eventType, e.actorRef, e.sessionRef]), [["STAFF_LOGIN", newAdmin, next.sessionRef]]);

    // una rotacion sobre una sesion ya revocada (carrera de dos logins) no escribe un segundo evento
    assert.equal(await h.staff.revoke(A, hex("prev"), T0 + 7, "ROTATION"), false);
    assert.equal((await h.events(A)).filter((e) => e.eventType === "SESSION_REVOKED_BY_ROTATION").length, 1, "una por sesion previa");
  });

  register("TEST-CNS-1197 atomicidad: si falla la escritura del evento, create no deja sesion y revoke no revoca (sigue activa); ambos fallan con SecurityEventWriteError; al quitar el fallo todo procede", async (h) => {
    const T = fixtureUuid("t1197");
    const admin = fixtureUuid("admin-1197");
    const isWriteError = (e: unknown): boolean => e instanceof SecurityEventWriteError;
    await h.failEvents(true);
    try {
      await assert.rejects(() => h.staff.create(staffRec(T, "s1", admin)), isWriteError);
      assert.equal(await h.sessionRefOf("STAFF", T, hex("s1")), null, "login STAFF sin fila");
    } finally {
      await h.failEvents(false);
    }
    assert.deepEqual(await h.events(T), []);
    await h.staff.create(staffRec(T, "s1", admin));
    await h.failEvents(true);
    try {
      await assert.rejects(() => h.staff.revoke(T, hex("s1"), T0 + 1, "USER_LOGOUT"), isWriteError);
      await assert.rejects(() => h.staff.revoke(T, hex("s1"), T0 + 1, "ROTATION"), isWriteError);
      assert.equal(await h.revokedOf("STAFF", T, hex("s1")), false, "logout fallido: revoked_at sigue NULL");
      assert.equal(await h.staff.validateAndTouch({ tenantId: T, sidHash: hex("s1"), principalRef: admin, role: "TENANT_ADMIN", nowMs: T0 + 2, idleTimeoutMs: 1_800_000 }), true, "la sesion sigue siendo valida");
    } finally {
      await h.failEvents(false);
    }
    assert.deepEqual((await h.events(T)).map((e) => e.eventType), ["STAFF_LOGIN"], "ningun evento parcial");
    assert.equal(await h.staff.revoke(T, hex("s1"), T0 + 3, "USER_LOGOUT"), true);
    assert.equal(await h.revokedOf("STAFF", T, hex("s1")), true);
  });

  register("TEST-CNS-1200 concurrencia: un logout y una rotacion simultaneos (y repetidos) sobre la MISMA sesion producen exactamente UN evento de revocacion y exactamente un revoke devuelve true", async (h) => {
    const T = fixtureUuid("t1200");
    const admin = fixtureUuid("admin-1200");
    for (let i = 0; i < 6; i += 1) {
      await h.staff.create(staffRec(T, `s${i}`, admin));
      const staffResults = await Promise.all([
        h.staff.revoke(T, hex(`s${i}`), T0 + 10, "USER_LOGOUT"),
        h.staff.revoke(T, hex(`s${i}`), T0 + 10, "ROTATION"),
        h.staff.revoke(T, hex(`s${i}`), T0 + 10, "USER_LOGOUT"),
      ]);
      assert.equal(staffResults.filter(Boolean).length, 1, "exactamente un revoke STAFF gana");
    }
    const revocations = (await h.events(T)).filter((e) => e.eventType !== "STAFF_LOGIN");
    assert.equal(revocations.length, 6, "un evento de revocacion por sesion (6 STAFF), nunca dos");
    assert.equal(new Set(revocations.map((e) => e.sessionRef)).size, 6, "cada sesion tiene exactamente un evento de revocacion");
  });
}

/** Solo para tipar el espejo en tests de unidad. */
export type { SecurityEventEntry };
