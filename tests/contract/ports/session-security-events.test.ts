// Gobierna: CA-141. Registra la suite de contrato de eventos de seguridad de los stores de sesion contra los adaptadores in-memory
// (TEST-CNS-1194, 1195, 1196, 1197). El registro contra Postgres vive en tests/integration/postgres/session-security-event.test.ts.

import test from "node:test";

import { createInMemoryCaseSessionStore } from "../../../src/infra/adapters/in-memory-case-session-store.adapter.ts";
import { createInMemorySecurityEventLog } from "../../../src/infra/adapters/in-memory-security-event.adapter.ts";
import { createInMemoryStaffSessionStore } from "../../../src/infra/adapters/in-memory-staff-session-store.adapter.ts";
import { runSessionSecurityEventsContract } from "./session-security-events.contract.ts";

runSessionSecurityEventsContract((name, body) => {
  test(name, async () => {
    const log = createInMemorySecurityEventLog();
    const staff = createInMemoryStaffSessionStore({ securityEvents: log });
    const caseSessions = createInMemoryCaseSessionStore({ securityEvents: log });
    const rowOf = (kind: "STAFF" | "CASE", tenantId: string, sidHash: string) => (kind === "STAFF" ? staff.rows() : caseSessions.rows()).find((r) => r.tenantId === tenantId && r.sidHash === sidHash);
    await body({
      staff,
      caseSessions,
      events: async (tenantId) => log.list(tenantId).map((e) => ({ eventType: e.eventType, tenantId: e.tenantId, actorRef: e.actorRef, actorRole: e.actorRole, sessionKind: e.sessionKind, sessionRef: e.sessionRef, caseRef: e.caseRef ?? null })),
      sessionRefOf: async (kind, tenantId, sidHash) => rowOf(kind, tenantId, sidHash)?.sessionRef ?? null,
      revokedOf: async (kind, tenantId, sidHash) => { const r = rowOf(kind, tenantId, sidHash); return r === undefined ? null : r.revokedAtMs !== null; },
      failEvents: async (on) => { log.failWith = on ? () => true : null; },
    });
  });
});
