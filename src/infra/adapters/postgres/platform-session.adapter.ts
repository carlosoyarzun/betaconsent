// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.2 pasos 5-7, §6, §10 fila PR-6c; specs/db-roles.spec.yaml (platform_rw); db/migrations/0053;
// src/server/ports/platform-session.port.ts; ADR-001 §11 (solo adapters conocen el SQL).
//
// Adaptador sobre las funciones SECURITY DEFINER open_platform_session / open_case_session / validate_session / revoke_session (pool de platform_rw, sin privilegios de tabla). Cada
// operacion corre en UNA transaccion (withPlatformTransaction): la asercion se consume y la sesion se crea (y el evento se escribe) atomicamente. El sid devuelto por la base se entrega
// una sola vez al llamador y no se registra. Un error de base -> PlatformDeniedError uniforme (sin motivo).

import type { PlatformSessionPort, SessionKind, SessionLifetime, ValidatedSession } from "../../../server/ports/platform-session.port.ts";
import type { PoolLike } from "./pool.ts";
import { withPlatformTransaction } from "./platform-call.ts";

const SID_RE = /^[0-9a-f]{64}$/;
const KINDS: ReadonlySet<string> = new Set(["PLATFORM", "CASE"]);

function sidOrNull(value: string | null | undefined): string | null {
  return typeof value === "string" && SID_RE.test(value) ? value : null;
}

export function createPgPlatformSessionStore(pool: PoolLike): PlatformSessionPort {
  const open = async (sql: string, params: readonly unknown[]): Promise<string | null> => {
    const rows = await withPlatformTransaction(pool, null, async (tx) => (await tx.query<{ sid: string | null }>(sql, params)).rows);
    const sid = rows[0]?.sid;
    return typeof sid === "string" && SID_RE.test(sid) ? sid : null;
  };
  const life = (l: SessionLifetime): [number, number] => [l.absoluteSeconds, l.idleSeconds];
  return {
    async openPlatformSession(input) {
      return open("SELECT platform.open_platform_session($1::uuid, $2, $3, $4, $5) AS sid", [input.exchangeRef, input.state, ...life(input.lifetime), sidOrNull(input.previousSid)]);
    },
    async openCaseSession(input) {
      return open("SELECT platform.open_case_session($1::uuid, $2, $3, $4, $5, $6, $7) AS sid", [
        input.exchangeRef, input.state, input.caseRef, input.platformSid, ...life(input.lifetime), sidOrNull(input.previousCaseSid),
      ]);
    },
    async validate(input): Promise<ValidatedSession | null> {
      if (!SID_RE.test(input.sid)) return null;
      const rows = await withPlatformTransaction(pool, null, async (tx) =>
        (await tx.query<{ o_session_ref: string; o_session_kind: string; o_principal_ref: string; o_case_ref: string | null }>(
          "SELECT o_session_ref, o_session_kind, o_principal_ref, o_case_ref FROM platform.validate_session($1, $2)",
          [input.sid, input.kind],
        )).rows,
      );
      const row = rows[0];
      if (row === undefined || !KINDS.has(row.o_session_kind) || row.o_session_kind !== input.kind) return null;
      return { sessionRef: row.o_session_ref, kind: row.o_session_kind as SessionKind, principalRef: row.o_principal_ref, caseRef: row.o_case_ref };
    },
    async revoke(input) {
      if (!SID_RE.test(input.sid)) return false;
      const rows = await withPlatformTransaction(pool, null, async (tx) => (await tx.query<{ r: boolean }>("SELECT platform.revoke_session($1, $2) AS r", [input.sid, input.kind])).rows);
      return rows[0]?.r === true;
    },
  };
}
