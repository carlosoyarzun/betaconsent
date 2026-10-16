// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.1, §6, §10 fila 6d; specs/db-roles.spec.yaml (platform_rw); db/migrations/0060-0062;
// src/server/ports/platform-grant.port.ts; ADR-001 §11 (solo adapters conocen el SQL).
//
// Adaptador sobre issue_step_up_nonce / request_grant / approve_grant (pool de platform_rw, sin privilegios de tabla). Cada operacion corre en UNA transaccion (withPlatformTransaction): el nonce se
// consume y el efecto se escribe atomicamente. Solo se fija el sid de la sesion (app.session_sid, local a la tx): la BASE lo resuelve; nunca se declara un principal. El sid no se registra.

import type { CaseStepUpAction, PlatformGrantPort } from "../../../server/ports/platform-grant.port.ts";
import type { PoolLike } from "./pool.ts";
import { withPlatformTransaction } from "./platform-call.ts";

const SID_RE = /^[0-9a-f]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ACTIONS: ReadonlySet<string> = new Set(["REQUEST_GRANT", "APPROVE_GRANT"]);

const one = async (pool: PoolLike, sid: string, sql: string, params: readonly unknown[]): Promise<string | null> => {
  if (!SID_RE.test(sid)) return null;
  const rows = await withPlatformTransaction(pool, null, async (tx) => (await tx.query<{ r: string | null }>(sql, params)).rows, { sessionSid: sid });
  const r = rows[0]?.r;
  return typeof r === "string" ? r : null;
};

export function createPgPlatformGrants(pool: PoolLike): PlatformGrantPort {
  return {
    async issueStepUpNonce(input: { sid: string; action: CaseStepUpAction; targetRef: string; ttlSeconds: number }): Promise<string | null> {
      if (!ACTIONS.has(input.action)) return null;
      return one(pool, input.sid, "SELECT platform.issue_step_up_nonce($1, $2, $3) AS r", [input.action, input.targetRef, input.ttlSeconds]);
    },
    async requestGrant(input): Promise<string | null> {
      return one(pool, input.sid, "SELECT platform.request_grant($1, $2, $3) AS r", [input.caseRef, input.limit.max, input.limit.windowSeconds]);
    },
    async approveGrant(input): Promise<string | null> {
      if (!UUID_RE.test(input.requestRef)) return null;
      return one(pool, input.sid, "SELECT platform.approve_grant($1, $2::uuid, $3, $4, $5) AS r", [input.caseRef, input.requestRef, input.validSeconds, input.limit.max, input.limit.windowSeconds]);
    },
  };
}
