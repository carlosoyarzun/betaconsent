// Gobierna: CA-141. Registra contra Postgres real la suite de contrato de eventos de seguridad de los stores de sesion (TEST-CNS-1194,
// 1195, 1196, 1197, 1200). El runtime (app_rw) solo INSERTA (D-5): los eventos y las filas se leen con la conexion del dueno/superusuario.
// El fallo del evento se inyecta con un trigger de prueba en la base desechable de este archivo (nunca en las migraciones).

import { createPgCaseSessionStore } from "../../../src/infra/adapters/postgres/case-session.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgStaffSessionStore } from "../../../src/infra/adapters/postgres/staff-session.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { runSessionSecurityEventsContract } from "../../contract/ports/session-security-events.contract.ts";
import { installEventFailureTrigger } from "./security-event-fixtures.ts";
import { pgTest } from "./harness.ts";

runSessionSecurityEventsContract((name, body) => {
  pgTest(name, async (ctx) => {
    const admin = await ctx.connectAsSuperuser();
    await installEventFailureTrigger(admin);
    const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 4 });
    try {
      const uow = new PgUnitOfWork(pool, {});
      const table = (kind: "STAFF" | "CASE"): string => (kind === "STAFF" ? "app.staff_session" : "app.case_session");
      await body({
        staff: createPgStaffSessionStore(uow),
        caseSessions: createPgCaseSessionStore(uow),
        events: async (tenantId) =>
          (await admin.query<{ event_type: string; tenant_id: string; actor_ref: string | null; actor_role: string | null; session_kind: string | null; session_ref: string | null; case_ref: string | null }>(
            "SELECT event_type, tenant_id, actor_ref, actor_role, session_kind, session_ref, case_ref FROM ops.security_event WHERE tenant_id = $1 ORDER BY event_seq",
            [tenantId],
          )).rows.map((r) => ({ eventType: r.event_type, tenantId: r.tenant_id, actorRef: r.actor_ref, actorRole: r.actor_role, sessionKind: r.session_kind, sessionRef: r.session_ref, caseRef: r.case_ref })),
        sessionRefOf: async (kind, tenantId, sidHash) =>
          (await admin.query<{ session_ref: string }>(`SELECT session_ref FROM ${table(kind)} WHERE tenant_id = $1 AND sid_hash = $2`, [tenantId, sidHash])).rows[0]?.session_ref ?? null,
        revokedOf: async (kind, tenantId, sidHash) => {
          const r = (await admin.query<{ revoked: boolean }>(`SELECT revoked_at IS NOT NULL AS revoked FROM ${table(kind)} WHERE tenant_id = $1 AND sid_hash = $2`, [tenantId, sidHash])).rows[0];
          return r === undefined ? null : r.revoked;
        },
        failEvents: async (on) => {
          await admin.query("UPDATE ops.ca141_fail_flag SET fail_on = $1", [on]);
        },
      });
    } finally {
      await pool.end();
    }
  });
});
