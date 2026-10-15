// Gobierna: ADR-010 rev. 5 §4.2.b (capa 1; LG-1..LG-10; aceptada por Carlos el 2026-10-15), LG-4 (siembra LOCAL), LG-6 (concurrencia con condiciones), F-PR6-10 (C6 sin emision con su guarda),
// F-PR6-22/30 (I9 frente a C3/C5), dictamen de arquitectura 2026-10-15 (F-PRB-01 managementLinkIssued derivado de tenant_resolve.handle; F-PRB-02 sin siembra de REVOKED),
// db/migrations/0049_adr010_ledger_gen_decision_seed_close_insert.sql, specs/ledger-derivation.spec.yaml. SYNTHETIC ONLY.
// TEST-CNS-1459 (vectores dorados TS<->SQL de ConsentDecision, incluido managementLinkIssued: handle registrado / sin handle / rotado),
// TEST-CNS-1460 (guardas de ConsentDecision: INSERT, pasos, GRANTED/DECLINED y terminales; C6 solo con Revocation CONFIRMED; app_rw -> REVOKED = 42501),
// TEST-CNS-1461 (ledger_gen.seed_local_catalog_event: payload fijo, actor FIXTURE, solo LOCAL; app_rw sin EXECUTE de ninguna otra funcion de ledger_gen),
// TEST-CNS-1462 (LG-6: lock_timeout -> 55P03 y deadlock -> 40P01 sobre el lock de ledger por tenant, sin dejar eventos),
// TEST-CNS-1463 (carrera C3 frente a V2/I5 de otra invitacion: serializadas por el orden de locks, cadena sin huecos),
// TEST-CNS-1464 (carrera I9 frente a C3 y a C5: exactamente una gana, la otra recibe un error uniforme; sin COMPLETED/DECLINED y CANCELLED a la vez; secuencia por agregado unica).
// Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import type { Client } from "pg";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { createPgConsentDecisionRepository } from "../../../src/infra/adapters/postgres/consent-decision.adapter.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { deriveConsentDecisionEvents } from "../../../src/server/modules/common/ledger-derivation.ts";
import type { ConsentDecisionRecord } from "../../../src/server/ports/consent-decision-repository.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest, seedRaw, type PgTestContext } from "./harness.ts";

const codeOf = (e: unknown): string | undefined => (e as { code?: string }).code;
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const DM = "dm-pr-b-decision";
const PURPOSE = "STUDY_PARTICIPATION";
const GRANT = JSON.stringify([{ purpose: PURPOSE, choice: "GRANT" }]);
const DECLINE = JSON.stringify([{ purpose: PURPOSE, choice: "DECLINE" }]);

async function withApp<T>(ctx: PgTestContext, fn: (uow: PgUnitOfWork) => Promise<T>, max = 2): Promise<T> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max });
  try {
    return await fn(new PgUnitOfWork(pool, { lockTimeoutMs: 3000 }));
  } finally {
    await pool.end();
  }
}

async function seedVerifiedInvitation(admin: Client, T: string, ref: string, subject: string): Promise<void> {
  await seedRaw(admin, () => admin.query(
    `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref, bound_decision_maker_ref, verified_by_ref, dm_ref_key_version)
     VALUES ($1, $2, 'C', 'P', $3, 'VERIFIED', 'e', 'p', $4, 'v', 2)`, [T, ref, subject, DM]));
}

/** Decision PENDING con los 3 pasos requeridos ya registrados (fixture crudo): lista para GRANTED/DECLINED. */
async function seedReadyDecision(admin: Client, T: string, id: string, inv: string, subject: string, chain: string): Promise<void> {
  await seedRaw(admin, () => admin.query(
    `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes,
       prior_steps_complete, steps_recorded, relationship_ref, consent_version, consent_text_hash, privacy_notice_version)
     VALUES ($1, $2, 'C', 'P', $3, $4, $5, 'v', $6, 'PENDING', '[]', true,
       ARRAY['CONSENT_VERSION_VIEWED', 'DECISION_MAKER_AUTHORITY_DECLARED', 'SUBJECT_CONFIRMED'], 'SYNTHETIC_GUARDIAN', 'v1', $7, 'p1')`,
    [T, id, subject, DM, inv, chain, sha("texto")]));
}

const closeSql = (state: "COMPLETED" | "DECLINED"): string => `UPDATE app.invitation SET state = '${state}', closed_by_consent_id = $1 WHERE invitation_ref = $2`;
const decideSql = (state: "GRANTED" | "DECLINED"): string =>
  `UPDATE app.consent_decision SET state = '${state}', purposes = '${state === "GRANTED" ? GRANT : DECLINE}'::jsonb, receipt_ref = $2, consent_version = 'v1', consent_text_hash = '${sha("texto")}',
          privacy_notice_version = 'p1' WHERE consent_id = $1`;

pgTest("TEST-CNS-1459 pg: vectores dorados TS<->SQL de ConsentDecision: la base emite los mismos eventos, claves, actores y payloads que ledger-derivation.ts; managementLinkIssued sale de tenant_resolve.handle (registrado / sin handle / rotado)", async (ctx) => {
  const T = fixtureUuid("t1459");
  const admin = await ctx.connectAsSuperuser();
  const base = (n: string, inv: string): ConsentDecisionRecord => ({
    consentId: fixtureUuid(`c1459-${n}`), tenantId: T, contextRef: "C", productRef: "P", subjectRef: fixtureUuid(`s1459-${n}`), decisionMakerRef: DM, invitationRef: inv,
    verificationRef: fixtureUuid("v1459"), chainRef: fixtureUuid(`ch1459-${n}`), state: "PENDING", purposes: [], priorStepsComplete: false, stepsRecorded: [],
  });
  const steps = ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"] as const;
  const required = ["CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"];
  const cases: Array<{ n: string; handle: "none" | "registered" | "rotated"; final: "GRANTED" | "DECLINED" }> = [
    { n: "a", handle: "registered", final: "GRANTED" },
    { n: "b", handle: "none", final: "GRANTED" },
    { n: "c", handle: "rotated", final: "GRANTED" },
    { n: "d", handle: "registered", final: "DECLINED" },
  ];
  await withApp(ctx, async (uow) => {
    for (const c of cases) {
      const inv = fixtureUuid(`i1459-${c.n}`);
      const pending = base(c.n, inv);
      await seedVerifiedInvitation(admin, T, inv, pending.subjectRef);
      await uow.inTenant(T, (tx) => tx.consentDecisionRepo.save(pending));
      let cur = pending;
      const expected = [...deriveConsentDecisionEvents(null, pending)];
      for (const step of steps) {
        const next: ConsentDecisionRecord = {
          ...cur,
          stepsRecorded: [...cur.stepsRecorded, step],
          priorStepsComplete: required.every((k) => [...cur.stepsRecorded, step].includes(k)),
          ...(step === "CONSENT_VERSION_VIEWED" ? { consentVersion: "v1", consentTextHash: sha("texto"), privacyNoticeVersion: "p1" } : {}),
          ...(step === "DECISION_MAKER_AUTHORITY_DECLARED" ? { relationshipRef: "SYNTHETIC_GUARDIAN" } : {}),
        };
        await uow.inTenant(T, (tx) => tx.consentDecisionRepo.save(next));
        expected.push(...deriveConsentDecisionEvents(cur, next));
        cur = next;
      }
      const handleHash = sha(`handle-1459-${c.n}`);
      const linkIssued = c.final === "GRANTED" && c.handle === "registered";
      const decided: ConsentDecisionRecord = {
        ...cur, state: c.final, purposes: [{ purpose: PURPOSE, choice: c.final === "GRANTED" ? "GRANT" : "DECLINE" }], receiptRef: fixtureUuid(`r1459-${c.n}`),
        consentVersion: "v1", consentTextHash: sha("texto"), privacyNoticeVersion: "p1", ...(linkIssued ? { managementLinkIssued: true } : {}),
      };
      await uow.withTenantTx(T, async (tx) => {
        // F-PRB-01: el handle se registra ANTES del UPDATE a GRANTED, en la misma tx.
        if (c.handle !== "none") await tx.query("SELECT tenant_resolve.register_handle($1, $2, $3)", [handleHash, cur.chainRef, cur.consentId]);
        if (c.handle === "rotated") await tx.query("SELECT tenant_resolve.rotate_handle($1)", [handleHash]);
        await createPgConsentDecisionRepository(tx).save(decided);
      });
      expected.push(...deriveConsentDecisionEvents(cur, decided));
      const got = (await admin.query<{ event_type: string; actor_type: string; actor_role: string; payload: unknown; idempotency_key_hash: string; sequence: number }>(
        "SELECT event_type, actor_type, actor_role, payload, idempotency_key_hash, sequence FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 ORDER BY sequence", [T, cur.consentId])).rows;
      assert.equal(got.length, expected.length, c.n);
      expected.forEach((e, i) => {
        const g = got[i]!;
        assert.deepEqual([g.event_type, g.actor_type, g.actor_role, g.payload, g.idempotency_key_hash, g.sequence], [e.eventType, e.actorType, e.actorRole ?? null, e.payload, sha(e.idempotencyKey), i + 1], `${c.n}:${e.eventType}`);
      });
      const receipt = got.find((g) => g.event_type === "RECEIPT_CREATED");
      assert.equal((receipt?.payload as { managementLinkIssued?: boolean }).managementLinkIssued, linkIssued, `${c.n}: managementLinkIssued = handle no rotado registrado (solo GRANTED)`);
    }
  });
});

pgTest("TEST-CNS-1460 pg: guardas de ConsentDecision: INSERT solo PENDING sobre invitacion VERIFIED del mismo seudonimo; un paso nuevo y conocido por UPDATE; GRANTED/DECLINED con reglas; terminales; C6 solo con Revocation CONFIRMED y app_rw -> REVOKED = 42501 (F-PR6-10)", async (ctx) => {
  const T = fixtureUuid("t1460");
  const admin = await ctx.connectAsSuperuser();
  const inv = fixtureUuid("i1460");
  const subj = fixtureUuid("s1460");
  await seedVerifiedInvitation(admin, T, inv, subj);
  await seedRaw(admin, async () => {
    await admin.query(
      `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref)
       VALUES ($1, 'i1460-open', 'C', 'P', 's-open', 'OPENED', 'e', 'p')`, [T]);
  });
  await seedReadyDecision(admin, T, "d1460-a", inv, subj, "ch1460-a");
  await withApp(ctx, async (uow) => {
    const run = (sql: string, v: unknown[] = []) => uow.withTenantTx(T, (tx) => tx.query(sql, v));
    const denied = async (label: string, sql: string, v: unknown[] = []): Promise<void> =>
      assert.rejects(() => run(sql, v), (e: unknown) => codeOf(e) === "42501" && !/d1460|i1460/.test((e as Error).message), label);
    const ins = (id: string, invitation: string, extra = "", state = "PENDING"): string =>
      `INSERT INTO app.consent_decision (tenant_id, consent_id, context_ref, product_ref, subject_ref, decision_maker_ref, invitation_ref, verification_ref, chain_ref, state, purposes, prior_steps_complete${extra ? ", " + extra.split("=")[0] : ""})
       VALUES ($1, '${id}', 'C', 'P', '${subj}', '${DM}', '${invitation}', 'v', 'ch-${id}', '${state}', '[]', false${extra ? ", " + extra.split("=")[1] : ""})`;
    await denied("INSERT GRANTED", ins("d1460-x1", inv, "", "GRANTED"), [T]);
    await denied("INSERT sobre invitacion OPENED", ins("d1460-x2", "i1460-open"), [T]);
    await denied("INSERT con otro seudonimo", ins("d1460-x3", inv).replace(`'${DM}'`, "'otro'"), [T]);
    await denied("INSERT con recibo", ins("d1460-x4", inv, "receipt_ref='r'"), [T]);
    // C6 sin Revocation CONFIRMED: ni app_rw ni transition_owner.
    await denied("GRANTED sin pasos -> terminal desde PENDING sin finalidades", "UPDATE app.consent_decision SET state = 'GRANTED', receipt_ref = 'r', consent_version = 'v1', consent_text_hash = $1, privacy_notice_version = 'p1' WHERE consent_id = 'd1460-a'", [sha("texto")]);
    await denied("DECLINED sin ningun DECLINE", decideSql("DECLINED").replace(DECLINE, GRANT), ["d1460-a", "r"]);
    await denied("GRANTED con una finalidad DECLINE", decideSql("GRANTED").replace(GRANT, DECLINE), ["d1460-a", "r"]);
    await denied("finalidad duplicada", decideSql("GRANTED").replace(GRANT, JSON.stringify([{ purpose: PURPOSE, choice: "GRANT" }, { purpose: PURPOSE, choice: "GRANT" }])), ["d1460-a", "r"]);
    await denied("sin recibo", decideSql("GRANTED"), ["d1460-a", null]);
    await denied("paso desconocido", "UPDATE app.consent_decision SET steps_recorded = steps_recorded || ARRAY['PASO_INVENTADO'] WHERE consent_id = 'd1460-a'");
    await denied("PENDING -> REVOKED", "UPDATE app.consent_decision SET state = 'REVOKED' WHERE consent_id = 'd1460-a'");
    // Camino legal: GRANTED; despues, terminal (sin DECLINED, sin PENDING, sin REVOKED por app_rw).
    await run(decideSql("GRANTED"), ["d1460-a", fixtureUuid("r1460")]);
    await denied("GRANTED -> DECLINED", decideSql("DECLINED"), ["d1460-a", "r"]);
    await denied("GRANTED -> PENDING", "UPDATE app.consent_decision SET state = 'PENDING' WHERE consent_id = 'd1460-a'");
    await denied("app_rw GRANTED -> REVOKED (policy FN-10 y guarda)", "UPDATE app.consent_decision SET state = 'REVOKED' WHERE consent_id = 'd1460-a'");
  });
  const asTransitionOwner = async (sql: string): Promise<string> => {
    await admin.query("BEGIN");
    try {
      await admin.query("SET LOCAL ROLE transition_owner");
      await admin.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
      await admin.query(sql);
      return "ok";
    } catch (e) {
      return codeOf(e) ?? "?";
    } finally {
      await admin.query("ROLLBACK");
    }
  };
  // C6 por transition_owner SIN Revocation CONFIRMED: la guarda lo rechaza (sin exencion por rol, GUC ni entorno), incluso con case_state.effect fijado.
  assert.equal(await asTransitionOwner("UPDATE app.consent_decision SET state = 'REVOKED' WHERE consent_id = 'd1460-a'"), "42501");
  assert.equal(await asTransitionOwner("SELECT set_config('case_state.effect', 'seed_local_revoke_decision', true); UPDATE app.consent_decision SET state = 'REVOKED' WHERE consent_id = 'd1460-a'"), "42501");
  // Con una Revocation CONFIRMED del tenant sobre esa decision: C6 se admite (la fila no cambia mas que state).
  await admin.query("SELECT set_config('case_state.effect', 'seed_local_revocation', false)");
  await admin.query(
    "INSERT INTO app.revocation (tenant_id, revocation_ref, chain_ref, revoked_decision_ref, status, verified_auth_path) VALUES ($1, 'r1460', 'ch-1460-a', 'd1460-a', 'CONFIRMED', 'OTP')", [T]);
  await admin.query("RESET ALL");
  assert.equal(await asTransitionOwner("UPDATE app.consent_decision SET state = 'REVOKED' WHERE consent_id = 'd1460-a'"), "ok");
  assert.equal(await asTransitionOwner("UPDATE app.consent_decision SET state = 'REVOKED', purposes = '[]'::jsonb WHERE consent_id = 'd1460-a'"), "42501", "C6 no cambia mas columnas");
  // F-PRB-02: la siembra LOCAL de REVOKED fue retirada.
  assert.equal((await admin.query("SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'case_state' AND p.proname = 'seed_local_revoke_decision'")).rowCount, 0);
  // C6 no emite: el ledger de la decision no tiene eventos de revocacion.
  assert.equal((await admin.query("SELECT 1 FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = 'd1460-a' AND event_type = 'CONSENT_REVOKED'", [T])).rowCount, 0);
});

pgTest("TEST-CNS-1461 pg: ledger_gen.seed_local_catalog_event: payload constante {}, actor FIXTURE, solo TENANT_SEEDED/SCHOOL_PARTICIPATION_SEEDED, entorno LOCAL del catalogo; app_rw no ejecuta ninguna otra funcion de ledger_gen (F-PR6-28)", async (ctx) => {
  const T = fixtureUuid("t1461");
  const admin = await ctx.connectAsSuperuser();
  await withApp(ctx, async (uow) => {
    const run = (sql: string, v: unknown[] = []) => uow.withTenantTx(T, (tx) => tx.query(sql, v));
    await run("SELECT ledger_gen.seed_local_catalog_event('TENANT_SEEDED', $1)", [T]);
    await run("SELECT ledger_gen.seed_local_catalog_event('SCHOOL_PARTICIPATION_SEEDED', 'part-1461')");
    await assert.rejects(() => run("SELECT ledger_gen.seed_local_catalog_event('TENANT_SEEDED', 'otro-tenant')"), (e: unknown) => codeOf(e) === "42501");
    await assert.rejects(() => run("SELECT ledger_gen.seed_local_catalog_event('CONSENT_GRANTED', 'x')"), (e: unknown) => codeOf(e) === "42501");
    await assert.rejects(() => run("SELECT ledger_gen.ledger_append('Invitation', 'x', 'INVITATION_OPENED', 'HUMAN', 'INVITER', '{}'::jsonb, 'k')"), (e: unknown) => codeOf(e) === "42501");
    await assert.rejects(() => run("SELECT ledger_gen.canonical_json('{}'::jsonb)"), (e: unknown) => codeOf(e) === "42501");
  });
  const rows = (await admin.query<{ event_type: string; actor_type: string; payload: unknown; aggregate_type: string }>(
    "SELECT event_type, actor_type, payload, aggregate_type FROM integrity.audit_event WHERE tenant_id = $1 ORDER BY chain_seq", [T])).rows;
  assert.deepEqual(rows, [
    { event_type: "TENANT_SEEDED", actor_type: "FIXTURE", payload: {}, aggregate_type: "Tenant" },
    { event_type: "SCHOOL_PARTICIPATION_SEEDED", actor_type: "FIXTURE", payload: {}, aggregate_type: "SchoolParticipation" },
  ]);
  // Fuera de LOCAL falla cerrado: el entorno sale de la fila de ops.db_catalog (no de un GUC elegible por el llamador).
  await admin.query("BEGIN");
  try {
    await admin.query("ALTER TABLE ops.db_catalog DISABLE TRIGGER ALL");
    await admin.query("UPDATE ops.db_catalog SET environment = 'DEV'");
    await admin.query("SET LOCAL ROLE app_rw");
    await admin.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
    await assert.rejects(() => admin.query("SELECT ledger_gen.seed_local_catalog_event('SCHOOL_PARTICIPATION_SEEDED', 'part-1461-dev')"), (e: unknown) => codeOf(e) === "42501");
  } finally {
    await admin.query("ROLLBACK");
  }
});

pgTest("TEST-CNS-1462 pg (LG-6): el lock de ledger por tenant solo lo toma quien emite: lock_timeout da 55P03 y un cruce fila->ledger / ledger->fila da 40P01; ninguna tx perdedora deja eventos", async (ctx) => {
  const T = fixtureUuid("t1462");
  const admin = await ctx.connectAsSuperuser();
  await seedRaw(admin, async () => {
    for (const ref of ["x1462", "y1462"]) {
      await admin.query(
        `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref)
         VALUES ($1, $2, 'C', 'P', 's-' || $2::text, 'DRAFT', 'e', 'p')`, [T, ref]);
    }
  });
  const open = async (): Promise<Client> => {
    const c = await ctx.connectAs("app_rw");
    await c.query("BEGIN");
    await c.query("SELECT set_config('app.tenant_id', $1, true)", [T]);
    return c;
  };
  const newInv = (ref: string): string =>
    `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref) VALUES (app.current_tenant_id(), '${ref}', 'C', 'P', 's-${ref}', 'DRAFT', 'e', 'p')`;
  const pidOf = async (c: Client): Promise<number> => Number((await c.query<{ p: number }>("SELECT pg_backend_pid() AS p")).rows[0]?.p);
  const waiting = async (pid: number): Promise<void> => {
    for (let i = 0; i < 100; i += 1) {
      const r = await admin.query("SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock'", [pid]);
      if (r.rowCount && r.rowCount > 0) return;
      await new Promise((res) => setTimeout(res, 30));
    }
    throw new Error("la transaccion no quedo esperando un lock");
  };
  // 55P03: A toma el lock del ledger emitiendo (INVITATION_CREATED); B, con lock_timeout corto, no espera sin fin.
  {
    const a = await open();
    const b = await open();
    await a.query(newInv("a1462"));
    await b.query("SET LOCAL lock_timeout = '300ms'");
    await assert.rejects(() => b.query(newInv("b1462")), (e: unknown) => codeOf(e) === "55P03");
    await b.query("ROLLBACK");
    // Una tx que NO emite no toma el lock de ledger: un UPDATE sin cambio de estado de otra fila (otp_exhausted) pasa aunque A lo tenga.
    const c = await open();
    await c.query("SET LOCAL lock_timeout = '300ms'");
    await c.query("UPDATE app.invitation SET otp_exhausted = true WHERE invitation_ref = 'x1462'");
    await c.query("ROLLBACK");
    await a.query("ROLLBACK");
  }
  // 40P01: T1 toma la fila X y despues quiere emitir (lock de ledger); T2 emite primero (lock de ledger) y despues quiere la fila X.
  {
    const t1 = await open();
    const t2 = await open();
    await t1.query("SELECT 1 FROM app.invitation WHERE invitation_ref = 'x1462' FOR UPDATE");
    await t2.query(newInv("p1462")); // T2 ya tiene el lock de ledger
    const p2PidWait = pidOf(t2);
    const r2 = t2.query("UPDATE app.invitation SET state = 'READY', consent_version = 'v', expires_at = now() + interval '1 day', recipient_binding = 'UNBOUND' WHERE invitation_ref = 'x1462'").then(() => "ok", (e: unknown) => codeOf(e));
    await waiting(await p2PidWait);
    const r1 = t1.query(newInv("q1462")).then(() => "ok", (e: unknown) => codeOf(e));
    const [o1, o2] = await Promise.all([r1, r2]);
    assert.deepEqual([o1, o2].filter((o) => o === "40P01").length, 1, `exactamente una tx es victima del deadlock: ${o1}/${o2}`);
    await t1.query("ROLLBACK").catch(() => {});
    await t2.query("ROLLBACK").catch(() => {});
  }
  assert.equal((await admin.query("SELECT 1 FROM integrity.audit_event WHERE tenant_id = $1", [T])).rowCount, 0, "ninguna tx confirmo: sin eventos");
});

pgTest("TEST-CNS-1463 pg (LG-6): carrera C3 frente a V2/I5 de otra invitacion del tenant: orden de locks invitacion -> fila -> ledger; sin 40P01, ambas confirman y la cadena queda sin huecos", async (ctx) => {
  const T = fixtureUuid("t1463");
  const admin = await ctx.connectAsSuperuser();
  const rounds = 4;
  await withApp(ctx, async (uow) => {
    for (let r = 0; r < rounds; r += 1) {
      const invC3 = `ic3-${r}`;
      const invV = `iv-${r}`;
      const ver = `ver-1463-${r}`;
      await seedVerifiedInvitation(admin, T, invC3, `s-c3-${r}`);
      await seedReadyDecision(admin, T, `d1463-${r}`, invC3, `s-c3-${r}`, `ch-1463-${r}`);
      await seedRaw(admin, async () => {
        await admin.query(
          `INSERT INTO app.invitation (tenant_id, invitation_ref, context_ref, product_ref, subject_ref, state, enrollment_ref, participation_ref)
           VALUES ($1, $2, 'C', 'P', $3, 'OPENED', 'e', 'p')`, [T, invV, `s-v-${r}`]);
        await admin.query(
          `INSERT INTO app.otp_verification (tenant_id, verification_ref, scope, parent_ref, channel_ref, code_hash, attempts, expires_at, state)
           VALUES ($1, $2, 'DECISION', $3, 'a@example.invalid', $4, 0, now() + interval '1 hour', 'CODE_SENT')`, [T, ver, invV, "a".repeat(64)]);
      });
      const c3 = uow.withTenantTx(T, async (tx) => {
        const l = await tx.query("SELECT 1 FROM app.invitation WHERE invitation_ref = $1 FOR UPDATE", [invC3]);
        assert.equal(l.rowCount, 1);
        await tx.query(decideSql("GRANTED"), [`d1463-${r}`, fixtureUuid(`rc-${r}`)]);
        await tx.query(closeSql("COMPLETED"), [`d1463-${r}`, invC3]);
      });
      const v = uow.withTenantTx(T, async (tx) => {
        await tx.query("SELECT 1 FROM app.invitation WHERE invitation_ref = $1 FOR UPDATE", [invV]); // F-4: invitacion -> challenge
        await tx.query("UPDATE app.otp_verification SET attempts = 1 WHERE verification_ref = $1", [ver]); // V2: intento fallido
        await tx.query("UPDATE app.otp_verification SET attempts = 2, state = 'VERIFIED', consumed_at = now(), decision_maker_ref = $2, dm_ref_key_version = 2 WHERE verification_ref = $1", [ver, DM]); // V3
        await tx.query("UPDATE app.invitation SET state = 'VERIFIED', bound_decision_maker_ref = $2, verified_by_ref = $3, dm_ref_key_version = 2 WHERE invitation_ref = $1", [invV, DM, ver]); // I5
      });
      const results = await Promise.allSettled([c3, v]);
      assert.deepEqual(results.map((x) => x.status), ["fulfilled", "fulfilled"], JSON.stringify(results.map((x) => (x.status === "rejected" ? codeOf(x.reason) : "ok"))));
    }
  }, 4);
  const chain = (await admin.query<{ s: string }>("SELECT chain_seq::text AS s FROM integrity.audit_event WHERE tenant_id = $1 ORDER BY chain_seq", [T])).rows.map((x) => Number(x.s));
  assert.deepEqual(chain, chain.map((_, i) => i + 1), "cadena sin huecos ni duplicados");
  assert.equal(chain.length, rounds * 6, "C3: finalidad + GRANTED + RECEIPT + COMPLETED; V2/I5: DMV + INVITATION_VERIFIED");
});

for (const outcome of ["GRANTED", "DECLINED"] as const) {
  pgTest(`TEST-CNS-1464 pg (F-PR6-22/30): carrera I9 frente a ${outcome === "GRANTED" ? "C3" : "C5"}: exactamente una gana y la otra recibe un error uniforme; nunca ${outcome === "GRANTED" ? "COMPLETED" : "DECLINED"} y CANCELLED a la vez; secuencia por agregado unica`, async (ctx) => {
    const T = fixtureUuid(`t1464-${outcome}`);
    const admin = await ctx.connectAsSuperuser();
    const rounds = 5;
    const uniform = new Set(["IV009", "RV409", "42501", "RV001", "40001"]);
    await withApp(ctx, async (uow) => {
      for (let r = 0; r < rounds; r += 1) {
        const inv = `i1464-${r}`;
        const cid = `d1464-${r}`;
        await seedVerifiedInvitation(admin, T, inv, `s-${r}`);
        await seedReadyDecision(admin, T, cid, inv, `s-${r}`, `ch-1464-${r}`);
        const decide = uow.withTenantTx(T, async (tx) => {
          const l = await tx.query("SELECT 1 FROM app.invitation WHERE invitation_ref = $1 FOR UPDATE", [inv]); // el dominio relee la invitacion bloqueada: ERR-CM-01 si ya no la ve
          if (l.rowCount !== 1) throw Object.assign(new Error("invitacion no visible"), { code: "RV001" });
          await tx.query(decideSql(outcome), [cid, fixtureUuid(`rc1464-${outcome}-${r}`)]);
          const closed = await tx.query(closeSql(outcome === "GRANTED" ? "COMPLETED" : "DECLINED"), [cid, inv]);
          assert.equal(closed.rowCount, 1);
        });
        const cancel = uow.withTenantTx(T, (tx) => tx.query("SELECT case_state.cancel_invitation_subject_mismatch($1, $2, 0)", [inv, DM]));
        const [d, c] = await Promise.allSettled([decide, cancel]);
        const okCount = [d, c].filter((x) => x.status === "fulfilled").length;
        assert.equal(okCount, 1, `ronda ${r}: ${d.status}/${c.status}`);
        const loser = (d.status === "rejected" ? d : c) as PromiseRejectedResult;
        assert.ok(uniform.has(codeOf(loser.reason) ?? "?"), `error uniforme: ${codeOf(loser.reason)}`);
        const st = (await admin.query<{ state: string }>("SELECT state FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2", [T, inv])).rows[0]?.state;
        const dec = (await admin.query<{ state: string }>("SELECT state FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2", [T, cid])).rows[0]?.state;
        if (d.status === "fulfilled") {
          assert.deepEqual([st, dec], [outcome === "GRANTED" ? "COMPLETED" : "DECLINED", outcome]);
        } else {
          assert.deepEqual([st, dec], ["CANCELLED", "PENDING"], "I9 cierra sin decision y la decision no avanzo");
        }
      }
    }, 4);
    // Secuencia por agregado unica entre ambos emisores (ledger_writer y transition_owner): sin repetidos ni huecos por aggregate_id.
    const dup = await admin.query(
      `SELECT aggregate_id FROM integrity.audit_event WHERE tenant_id = $1 GROUP BY aggregate_id HAVING count(*) <> max(sequence) OR count(DISTINCT sequence) <> count(*)`, [T]);
    assert.equal(dup.rowCount, 0);
  });
}
