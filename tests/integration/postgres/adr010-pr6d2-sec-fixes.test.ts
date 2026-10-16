// Gobierna: ADR-010 rev. 5 (enmienda rev. c, 2026-10-15) §4.2.a (G-3), §4.2.d, §6 (GRD-RC-10, GRD-RC-12); registers/findings-register-IT0.md F-6D3-SEC-01/05/06/07 (hallazgos de seguridad del PR #103).
// TEST-CNS-1723 P2-1 el worker descubre CONFIRMED solo por funcion (2 columnas, sin lectura cross-tenant directa), 1724 P2-5 concurrencia: RH2 del mismo principal vs approve_grant deja GRANT_REJECTED,
// 1725 P2-6 step-up RH2 ligado a caso+propuesta, 1726 P2-7 relectura de estado con la sesion CASE vencida (sin oraculo). SYNTHETIC ONLY. Requiere Postgres real.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { Client, Pool, PoolClient } from "pg";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import type { PoolLike } from "../../../src/infra/adapters/postgres/pool.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { call } from "../../helpers/pg-login-flow.ts";
import { casePath, recordRh3, rh2Target, seedAttestedStepUp, seedCaseWorld, seedOperator, seedPlatformSession, startPlatformHttp } from "../../helpers/pg-case-world.ts";
import { pgTest } from "./harness.ts";

const LIMIT = { max: 50, windowSeconds: 600 } as const;
const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

pgTest("TEST-CNS-1723 pg (P2-1): el worker no lee case_state.revocation de otros tenants; case_state.list_confirmed_unapplied devuelve solo (tenant_id, revocation_ref) de CONFIRMED; app_rw/platform_rw no la ejecutan; la policy cross-tenant del worker no existe", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1723");
  const http = await startPlatformHttp(ctx);
  const worker = await ctx.connectAs("worker");
  const appRw = await ctx.connectAs("app_rw");
  try {
    await recordRh3(admin, http, w);
    const { seedConfirmedWithoutApplied } = await import("../../helpers/pg-case-world.ts");
    await seedConfirmedWithoutApplied(admin, w);
    // Lectura directa sin tenant: RLS tenant-acotada del worker (0042) = 0 filas; ya no hay policy cross-tenant.
    assert.equal((await worker.query("SELECT 1 FROM case_state.revocation")).rowCount, 0, "sin tenant el worker no ve filas");
    assert.equal((await admin.query("SELECT 1 FROM pg_policies WHERE schemaname = 'app' AND tablename = 'revocation' AND policyname = 'revocation_worker_recovery_select'")).rowCount, 0);
    const r = await worker.query("SELECT * FROM case_state.list_confirmed_unapplied(100, ARRAY[]::text[]) WHERE o_revocation_ref = $1", [w.revocationRef]);
    assert.deepEqual(r.rows, [{ o_tenant_id: w.tenantId, o_revocation_ref: w.revocationRef }], "solo las dos columnas");
    const skipped = await worker.query("SELECT * FROM case_state.list_confirmed_unapplied(100, ARRAY[$1]::text[]) WHERE o_revocation_ref = $1", [w.revocationRef]);
    assert.equal(skipped.rowCount, 0, "la lista de omision (backoff) se respeta");
    await assert.rejects(worker.query("SELECT * FROM case_state.list_confirmed_unapplied(0, ARRAY[]::text[])"), (e: unknown) => (e as { code?: string }).code === "22023");
    await assert.rejects(appRw.query("SELECT * FROM case_state.list_confirmed_unapplied(10, ARRAY[]::text[])"), (e: unknown) => (e as { code?: string }).code === "42501");
    // Fijar el efecto desde el cliente no abre la policy: solo transition_owner la tiene.
    await worker.query("BEGIN");
    await worker.query("SELECT set_config('case_state.effect', 'list_confirmed_unapplied', true)");
    assert.equal((await worker.query("SELECT 1 FROM case_state.revocation")).rowCount, 0);
    await worker.query("ROLLBACK");
  } finally {
    await worker.end();
    await appRw.end();
    await http.close();
  }
});

pgTest("TEST-CNS-1724 pg (P2-5): el aprobador de una RH2 en curso que aprueba un grant del mismo caso concurrentemente recibe GRANT_REJECTED / RH_TWO_APPROVER (no un error sin evidencia) y no nace el grant", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1724");
  const http = await startPlatformHttp(ctx);
  const platform = await ctx.connectAs("platform_rw");
  const a = await ctx.connectAs("platform_rw");
  const b = await ctx.connectAs("platform_rw");
  try {
    const proposalRef = fixtureUuid("proposal-1724");
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    assert.equal((await http.cases.propose({ sid: w.op1.caseSession.sid, caseRef: w.caseRef, proposalRef, scriptVersion: "g", limit: LIMIT })).ok, true);
    const op3 = fixtureUuid("world-1724-op3");
    await seedOperator(admin, op3, "RIGHTS_OPERATOR");
    const op3Sid = (await seedPlatformSession(admin, op3, { absoluteSeconds: 14400, idleSeconds: 900 })).sid;
    await seedAttestedStepUp(admin, op3, "REQUEST_GRANT", w.caseRef);
    const request = (await call<{ r: string | null }>(platform, null, "SELECT platform.request_grant($1, 50, 600) AS r", [w.caseRef], op3Sid))[0]!.r!;
    await seedAttestedStepUp(admin, w.approver.principal, "APPROVE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    await seedAttestedStepUp(admin, w.approver.principal, "APPROVE_GRANT", request);

    // A: RH2 del aprobador, SIN commit (retiene el advisory lock del step-up).
    await a.query("BEGIN");
    await a.query("SELECT set_config('app.session_sid', $1, true)", [w.approver.platform.sid]);
    const approved = await a.query("SELECT case_state.approve_case_verification($1, $2, 50, 600) AS r", [w.caseRef, proposalRef]);
    assert.equal((approved.rows[0] as { r: { ok?: boolean } }).r.ok, true);
    // B: el mismo aprobador aprueba el grant: queda esperando el lock del step-up (la revision GRD-RC-10 va DESPUES).
    let settled = false;
    const grantPromise = call<{ r: string | null }>(b, null, "SELECT platform.approve_grant($1, $2::uuid, NULL, 50, 600) AS r", [w.caseRef, request], w.approver.platform.sid).then((x) => { settled = true; return x; });
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(settled, false, "B espera a A");
    await a.query("COMMIT");
    const out = await grantPromise;
    assert.equal(out[0]!.r, null, "el grant no se aprueba");
    const ev = (await admin.query<{ reason_code: string }>("SELECT reason_code FROM platform.session_event WHERE principal_ref = $1 AND event_type = 'GRANT_REJECTED' AND request_ref = $2", [w.approver.principal, request])).rows;
    assert.deepEqual(ev.map((e) => e.reason_code), ["RH_TWO_APPROVER"], "evidencia GRANT_REJECTED");
    assert.equal((await admin.query("SELECT 1 FROM platform.rights_case_grant WHERE request_ref = $1", [request])).rowCount, 0);
  } finally {
    await a.end();
    await b.end();
    await platform.end();
    await http.close();
  }
});

pgTest("TEST-CNS-1725 pg (P2-6): el step-up de RH2 queda ligado a caseRef + proposalRef: con solo proposalRef, con otro caso o emitido para otra propuesta no sirve; issue_step_up_nonce exige `caseRef:proposalRef`", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1725a");
  const other = await seedCaseWorld(ctx, "1725b");
  const http = await startPlatformHttp(ctx);
  const platform = await ctx.connectAs("platform_rw");
  try {
    const proposalRef = fixtureUuid("proposal-1725");
    const propose = (): ReturnType<typeof http.cases.propose> => http.cases.propose({ sid: w.op1.caseSession.sid, caseRef: w.caseRef, proposalRef, scriptVersion: "g", limit: LIMIT });
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", proposalRef); // formato anterior: solo proposalRef
    assert.deepEqual(await propose(), { ok: false, reason: "STEP_UP" });
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(other.caseRef, proposalRef)); // mismo proposalRef, OTRO caso
    assert.deepEqual(await propose(), { ok: false, reason: "STEP_UP" });
    assert.equal((await admin.query("SELECT 1 FROM case_state.revocation WHERE tenant_id = $1 AND revocation_ref = $2 AND proposal_ref IS NOT NULL", [w.tenantId, w.revocationRef])).rowCount, 0);
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
    assert.equal((await propose()).ok, true, "con caso + propuesta correctos pasa");
    // issue_step_up_nonce: solo el formato compuesto para RH2 (y el plano sigue para REQUEST_GRANT).
    const issue = async (action: string, target: string): Promise<string | null> =>
      (await call<{ r: string | null }>(platform, null, "SELECT platform.issue_step_up_nonce($1, $2, 300) AS r", [action, target], w.op1.platform.sid))[0]!.r;
    assert.equal(await issue("PROPOSE_CASE_VERIFICATION", proposalRef), null, "solo proposalRef: rechazado");
    assert.equal(typeof (await issue("PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef))), "string");
    assert.equal(await issue("REQUEST_GRANT", rh2Target(w.caseRef, proposalRef)), null, "el formato compuesto es solo de RH2");
  } finally {
    await platform.end();
    await http.close();
  }
});

/** Commit ambiguo de la co-firma tras el cual la sesion CASE vence (P2-7): el COMMIT se aplica, la sesion expira, y al cliente le llega 08006. */
function ambiguousThenExpire(onFire: () => Promise<void>): (pool: Pool) => PoolLike {
  let armed = true;
  const PATCHED = Symbol.for("qa.ambiguousExpire");
  return (pool) => ({
    async connect(): Promise<PoolClient> {
      const client = await pool.connect();
      const tagged = client as PoolClient & { [PATCHED]?: boolean };
      if (tagged[PATCHED] !== true) {
        tagged[PATCHED] = true;
        const original = client.query.bind(client) as (...args: unknown[]) => Promise<unknown>;
        let saw = false;
        (client as unknown as { query: unknown }).query = async (...args: unknown[]): Promise<unknown> => {
          if (typeof args[0] === "string" && args[0].includes("cosign_case_confirmation")) saw = true;
          if (args[0] === "ROLLBACK") saw = false;
          if (args[0] === "COMMIT" && saw && armed) {
            saw = false;
            armed = false;
            await original("COMMIT");
            await onFire();
            throw Object.assign(new Error("connection terminated unexpectedly"), { code: "08006" });
          }
          return original(...args);
        };
      }
      return client;
    },
  });
}

async function readApplyState(client: Client, sid: string, caseRef: string): Promise<{ applied?: boolean } | "ERR"> {
  await client.query("BEGIN");
  try {
    await client.query("SELECT set_config('app.session_sid', $1, true)", [sid]);
    await client.query("SET LOCAL ROLE rights_operator");
    const r = await client.query("SELECT case_state.read_case_apply_state($1) AS r", [caseRef]);
    return (r.rows[0] as { r: { applied?: boolean } }).r;
  } catch {
    return "ERR";
  } finally {
    await client.query("ROLLBACK");
  }
}

pgTest("TEST-CNS-1726 pg (P2-7): si la sesion CASE vence entre el commit ambiguo y la relectura, la co-firma devuelve el resultado REAL (200 APPLIED), no 404; la relectura no sirve a otro principal, otro caso, sesion revocada ni vencida hace mas de 15 min", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1726");
  const sidHash = sha(w.op2.caseSession.sid);
  // El guard de platform_session (ADR-010 §5.2) impide editar sesiones: el fixture lo deshabilita DENTRO de su tx y lo deja ENABLE ALWAYS antes del COMMIT (solo tests).
  const editSession = async (sql: string, params: unknown[]): Promise<void> => {
    await admin.query("BEGIN");
    try {
      await admin.query("ALTER TABLE platform.platform_session DISABLE TRIGGER platform_session_guard");
      await admin.query(sql, params);
      await admin.query("ALTER TABLE platform.platform_session ENABLE ALWAYS TRIGGER platform_session_guard");
      await admin.query("COMMIT");
    } catch (error) {
      await admin.query("ROLLBACK");
      throw error;
    }
  };
  const expire = (minutes: number): Promise<void> =>
    editSession("UPDATE platform.platform_session SET issued_at = now() - interval '3 hours', last_seen_at = now() - interval '3 hours', expires_at = now() - make_interval(mins => $2) WHERE sid_hash = $1", [sidHash, minutes]);
  const http = await startPlatformHttp(ctx, { casePool: ambiguousThenExpire(() => expire(1)) });
  const reader = await ctx.connectAs("platform_rw");
  try {
    await recordRh3(admin, http, w);
    const res = await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {});
    assert.equal(res.status, 200, res.body);
    assert.deepEqual(JSON.parse(res.body), { cosign: "COSIGNED", revocationState: "APPLIED" });
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = 'CONSENT_REVOKED'", [w.tenantId, w.revocationRef])).rows[0]!.n, 1);
    // La relectura con la sesion vencida hace 1 min responde el estado de ESA co-firma...
    assert.equal((await readApplyState(reader, w.op2.caseSession.sid, w.caseRef) as { applied?: boolean }).applied, true);
    // ... pero no sirve a otro principal (op1 no co-firmo), a otro caso, a una sesion vencida hace > 15 min ni a una revocada, y una accion con efecto sigue dando 404 con la sesion vencida.
    assert.equal((await readApplyState(reader, w.op1.caseSession.sid, w.caseRef) as { applied?: boolean }).applied, false);
    const other = await seedCaseWorld(ctx, "1726b");
    assert.equal(await readApplyState(reader, w.op2.caseSession.sid, other.caseRef), "ERR");
    assert.equal(await readApplyState(reader, "0".repeat(64), w.caseRef), "ERR");
    assert.equal((await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {})).status, 404, "una accion con sesion vencida sigue siendo 404");
    await expire(20);
    assert.equal(await readApplyState(reader, w.op2.caseSession.sid, w.caseRef), "ERR");
    await expire(1);
    await editSession("UPDATE platform.platform_session SET revoked_at = now(), revoke_cause = 'USER_LOGOUT' WHERE sid_hash = $1", [sidHash]);
    assert.equal(await readApplyState(reader, w.op2.caseSession.sid, w.caseRef), "ERR");
  } finally {
    await reader.end();
    await http.close();
  }
});
