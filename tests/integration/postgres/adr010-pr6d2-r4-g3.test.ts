// Gobierna: ADR-010 rev. 5 (enmienda rev. c, 2026-10-15) §4.2.a puntos 4 y 5 (G-3, lectura (A), decision de Carlos: R4 atomica con R3/RH3, reintentos acotados, agotamiento = alerta + caso pendiente sin APPLIED y
// NUNCA acuse de exito; commit ambiguo = leer el estado y devolver el resultado real; el worker solo recupera CONFIRMED sin APPLIED), §10 fila 6d; src/server/modules/revocation/apply-guard.ts;
// db/migrations/0066, 0067, 0070; revocation.spec R3/RH3/R4. SYNTHETIC ONLY. Requiere Postgres real (harness.ts). Cada test usa su propio mundo (refs y tenant propios): la base se comparte en el archivo.
// TEST-CNS-1702 R4 atomica con RH3 (una sola tx), 1703 reintento acotado, 1704 agotamiento (alerta + 503 + sin APPLIED), 1714 (F-6D2-QA-02) 5 fallos 40001 nunca dan 503 con APPLIED, 1705 commit ambiguo devuelve el resultado real, 1706 respaldo del worker.

import assert from "node:assert/strict";
import type { Client } from "pg";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { RecoveryBackoff, recoverConfirmedRevocations } from "../../../src/server/entrypoints/worker/worker-process.ts";
import { ambiguousCommitPool, casePath, injectOutboxFailure, recordRh3, seedCaseWorld, seedConfirmedWithoutApplied, startPlatformHttp } from "../../helpers/pg-case-world.ts";
import type { CaseWorld } from "../../helpers/pg-case-world.ts";
import { pgTest } from "./harness.ts";

const events = async (admin: Client, w: CaseWorld): Promise<string[]> =>
  (await admin.query<{ event_type: string }>("SELECT event_type FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 ORDER BY sequence", [w.tenantId, w.revocationRef])).rows.map((r) => r.event_type);
const outbox = async (admin: Client, w: CaseWorld): Promise<number> => (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1", [w.tenantId])).rows[0]!.n;
const revocation = async (admin: Client, w: CaseWorld) =>
  (await admin.query<{ status: string; recorded_by_ref: string | null; cosigned_by_ref: string | null }>("SELECT status, recorded_by_ref, cosigned_by_ref FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0]!;
const alerts = async (admin: Client, w: CaseWorld): Promise<string[]> =>
  (await admin.query<{ alert_reason: string }>("SELECT alert_reason FROM ops.security_event WHERE tenant_id = $1 AND event_type = 'REVOCATION_APPLY_ALERT' AND revocation_ref = $2 ORDER BY event_seq", [w.tenantId, w.revocationRef])).rows.map((r) => r.alert_reason);
const countOf = (all: readonly string[], type: string): number => all.filter((x) => x === type).length;

pgTest("TEST-CNS-1702 pg platform: la co-firma RH3 aplica R3 + R4 + C6 en UNA transaccion (revocation, decision, ledger y outbox con el mismo xmin) y deja APPLIED con el recibo; sin CONFIRMED visible sin APPLIED", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1702");
  const http = await startPlatformHttp(ctx);
  try {
    await recordRh3(admin, http, w);
    const before = await events(admin, w);
    assert.ok(!before.includes("REVOCATION_CONFIRMED"));
    const res = await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {});
    assert.equal(res.status, 200, res.body);
    assert.deepEqual(JSON.parse(res.body), { cosign: "COSIGNED", revocationState: "APPLIED" });
    assert.deepEqual(await revocation(admin, w), { status: "APPLIED", recorded_by_ref: w.op1.principal, cosigned_by_ref: w.op2.principal });
    const after = await events(admin, w);
    assert.deepEqual(after.slice(before.length), ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"]);
    assert.equal(await outbox(admin, w), 1);
    assert.equal((await admin.query("SELECT state FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2", [w.tenantId, w.consentId])).rows[0]?.state, "REVOKED");
    // Una sola transaccion: todo lo que R3 + R4 + C6 escribio comparte el xmin de la tx de la co-firma.
    const xmins = new Set<string>();
    xmins.add((await admin.query<{ x: string }>("SELECT xmin::text AS x FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0]!.x);
    xmins.add((await admin.query<{ x: string }>("SELECT xmin::text AS x FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2", [w.tenantId, w.consentId])).rows[0]!.x);
    xmins.add((await admin.query<{ x: string }>("SELECT xmin::text AS x FROM app.outbox WHERE tenant_id = $1", [w.tenantId])).rows[0]!.x);
    for (const r of (await admin.query<{ x: string }>("SELECT xmin::text AS x FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type IN ('REVOCATION_CONFIRMED', 'CONSENT_REVOKED', 'RECEIPT_CREATED')", [w.tenantId, w.revocationRef])).rows) xmins.add(r.x);
    assert.equal(xmins.size, 1, `R3, R4 y C6 comparten una sola transaccion (xmin): ${[...xmins].join(",")}`);
    // El ledger no tiene huecos y no hay alerta ni acuse alternativo.
    const seqs = (await admin.query<{ sequence: number }>("SELECT sequence FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 ORDER BY sequence", [w.tenantId, w.revocationRef])).rows.map((r) => Number(r.sequence));
    assert.deepEqual(seqs, seqs.map((_, i) => i + 1));
    assert.deepEqual(await alerts(admin, w), []);
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1703 pg platform: ante un error transitorio (40001) la tx COMPLETA se reintenta (acotado a 3 intentos) y la co-firma llega a APPLIED con un solo juego de eventos y un solo outbox; sin alerta", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1703");
  const http = await startPlatformHttp(ctx);
  try {
    await recordRh3(admin, http, w);
    const before = await events(admin, w);
    const failure = await injectOutboxFailure(admin, { name: "f1703", tenantId: w.tenantId, failures: 2, sqlstate: "40001" });
    const res = await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {});
    assert.equal(res.status, 200, res.body);
    assert.equal(await failure.attempts(), 3, "dos intentos fallidos revertidos + el tercero aplica");
    assert.equal((await revocation(admin, w)).status, "APPLIED");
    const after = await events(admin, w);
    assert.deepEqual(after.slice(before.length), ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"], "los intentos revertidos no dejan eventos");
    assert.equal(await outbox(admin, w), 1);
    assert.deepEqual(await alerts(admin, w), []);
    await failure.remove();
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1704 pg platform: agotados los reintentos (3) la tx queda revertida, se persiste la alerta R4_RETRIES_EXHAUSTED, la respuesta es 503 uniforme SIN acuse de exito y la Revocation sigue VERIFIED sin APPLIED; el worker no la toca y el operador puede reintentar", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1704");
  const logs: string[] = [];
  const http = await startPlatformHttp(ctx, { applyGuard: { maxAttempts: 3, log: (line) => logs.push(line) } });
  const workerPool = createPool({ connectionString: ctx.urlFor("worker"), max: 2 });
  try {
    await recordRh3(admin, http, w);
    const before = await events(admin, w);
    const failure = await injectOutboxFailure(admin, { name: "f1704", tenantId: w.tenantId, failures: 1_000, sqlstate: "40001" });
    const res = await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {});
    assert.equal(res.status, 503, res.body);
    assert.deepEqual(Object.keys(JSON.parse(res.body)).sort(), ["code", "correlationId", "status"]);
    assert.equal(JSON.parse(res.body).code, "GUARD_EVALUATOR_UNAVAILABLE");
    assert.ok(!/APPLIED|COSIGNED|revoked|receipt/i.test(res.body), "sin acuse de exito ni texto para el titular");
    assert.deepEqual(res.setCookie, []);
    // F-6D2-QA-02 (cerrado): la lectura previa al reintento es read_case_apply_state (sin efectos), no otra co-firma: exactamente maxAttempts ejecuciones de la tx.
    assert.equal(await failure.attempts(), 3, "acotado: maxAttempts intentos; las relecturas de estado no ejecutan la co-firma");
    assert.deepEqual(await revocation(admin, w), { status: "VERIFIED", recorded_by_ref: w.op1.principal, cosigned_by_ref: null }, "caso pendiente: sin CONFIRMED ni APPLIED");
    assert.deepEqual(await events(admin, w), before);
    assert.equal(await outbox(admin, w), 0);
    assert.equal((await admin.query("SELECT state FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2", [w.tenantId, w.consentId])).rows[0]?.state, "GRANTED");
    assert.deepEqual(await alerts(admin, w), ["R4_RETRIES_EXHAUSTED"], "alerta persistida en tx separada, una sola");
    assert.ok(logs.every((l) => !l.includes(w.op2.principal) && !l.includes(w.op2.caseSession.sid)), "el log de respaldo, si lo hubo, no lleva PII ni sid");
    // El worker solo recupera CONFIRMED sin APPLIED: esta Revocation sigue VERIFIED y no se toca.
    const recovered = await recoverConfirmedRevocations(workerPool, new PgUnitOfWork(workerPool), 20, () => {});
    assert.deepEqual(recovered, { applied: 0, failed: 0, skipped: 0 });
    assert.equal((await revocation(admin, w)).status, "VERIFIED");
    // Pasada la falla, el operador reintenta y el caso se resuelve (sin duplicar la alerta ni los eventos).
    await failure.remove();
    const retried = await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {});
    assert.equal(retried.status, 200, retried.body);
    assert.equal((await revocation(admin, w)).status, "APPLIED");
    assert.equal(countOf(await events(admin, w), "CONSENT_REVOKED"), 1);
    assert.deepEqual(await alerts(admin, w), ["R4_RETRIES_EXHAUSTED"]);
  } finally {
    await workerPool.end();
    await http.close();
  }
});

pgTest("TEST-CNS-1714 pg platform (F-6D2-QA-02): con 5 fallos 40001 y maxAttempts=3 la co-firma nunca responde 503 si la Revocation quedo APPLIED: la lectura previa al reintento es una lectura de estado sin efectos (3 tx de cosign, no 6)", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1714");
  const http = await startPlatformHttp(ctx, { applyGuard: { maxAttempts: 3 } });
  try {
    await recordRh3(admin, http, w);
    const failure = await injectOutboxFailure(admin, { name: "f1714", tenantId: w.tenantId, failures: 5, sqlstate: "40001" });
    const res = await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {});
    const status = (await revocation(admin, w)).status;
    assert.equal(await failure.attempts(), 3, "ninguna lectura previa ejecuta la co-firma");
    // Invariante G-3: 503 si y solo si NO quedo APPLIED; nunca informar fallo de algo que se aplico.
    assert.equal(res.status === 503, status !== "APPLIED", `status HTTP ${res.status} con Revocation ${status}`);
    assert.equal(res.status, 503, res.body);
    assert.equal(status, "VERIFIED");
    assert.deepEqual(await alerts(admin, w), ["R4_RETRIES_EXHAUSTED"]);
    await failure.remove();
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1705 pg platform: commit ambiguo (COMMIT aplicado, conexion perdida al cliente) -> se lee el estado y se devuelve el resultado REAL (200 APPLIED), sin reaplicar, sin eventos ni outbox duplicados y sin alerta", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1705");
  const ambiguous = ambiguousCommitPool();
  const http = await startPlatformHttp(ctx, { casePool: ambiguous.wrap });
  try {
    await recordRh3(admin, http, w);
    const before = await events(admin, w);
    ambiguous.arm(1);
    const res = await http.post(casePath(w.caseRef).cosign, w.op2.caseSession.sid, {});
    assert.equal(ambiguous.fired(), 1, "el commit ambiguo se inyecto una vez");
    assert.equal(res.status, 200, res.body);
    assert.deepEqual(JSON.parse(res.body), { cosign: "COSIGNED", revocationState: "APPLIED" }, "el resultado real de lo aplicado");
    assert.deepEqual(await revocation(admin, w), { status: "APPLIED", recorded_by_ref: w.op1.principal, cosigned_by_ref: w.op2.principal });
    assert.deepEqual((await events(admin, w)).slice(before.length), ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"], "una sola aplicacion");
    assert.equal(await outbox(admin, w), 1);
    assert.deepEqual(await alerts(admin, w), []);
    // El replay lo marca la funcion: la misma co-firma ya aplicada devuelve el resultado real; otro co-firmante NO se beneficia (la Revocation no esta VERIFIED).
    const replay = await http.cases.cosign({ sid: w.op2.caseSession.sid, caseRef: w.caseRef });
    assert.equal(replay.ok && replay.data.replay === true && replay.data.applied === true, true, JSON.stringify(replay));
    assert.equal(countOf(await events(admin, w), "CONSENT_REVOKED"), 1);
    const other = await http.cases.cosign({ sid: w.op1.caseSession.sid, caseRef: w.caseRef });
    assert.equal(other.ok, false, "otro principal no recibe el acuse de una co-firma ajena");
  } finally {
    await http.close();
  }
});

pgTest("TEST-CNS-1706 pg worker: el respaldo recupera SOLO las Revocation CONFIRMED sin APPLIED (APPLIED + alerta R4_BACKUP_APPLIED, un solo outbox); si falla deja la fila CONFIRMED, escribe R4_BACKUP_FAILED y no se detiene; no toca VERIFIED", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const a = await seedCaseWorld(ctx, "1706a");
  const b = await seedCaseWorld(ctx, "1706b");
  const c = await seedCaseWorld(ctx, "1706c");
  const http = await startPlatformHttp(ctx);
  const workerPool = createPool({ connectionString: ctx.urlFor("worker"), max: 2 });
  const logs: string[] = [];
  let clock = 1_000_000;
  const backoff = new RecoveryBackoff(() => clock, 30_000, 3_600_000);
  try {
    await recordRh3(admin, http, a);
    await recordRh3(admin, http, b); // b queda VERIFIED (no CONFIRMED): el worker no la toca
    await recordRh3(admin, http, c);
    await seedConfirmedWithoutApplied(admin, a);
    await seedConfirmedWithoutApplied(admin, c);
    assert.equal((await revocation(admin, a)).status, "CONFIRMED");
    const failure = await injectOutboxFailure(admin, { name: "f1706", tenantId: c.tenantId, failures: 1_000, sqlstate: "40001" });

    const first = await recoverConfirmedRevocations(workerPool, new PgUnitOfWork(workerPool), 20, (l) => logs.push(l), backoff);
    assert.deepEqual(first, { applied: 1, failed: 1, skipped: 0 }, "a se aplica; c falla sin detener el ciclo");
    assert.equal((await revocation(admin, a)).status, "APPLIED");
    assert.deepEqual((await events(admin, a)).slice(-3), ["REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED"]);
    assert.equal(countOf(await events(admin, a), "CONSENT_REVOKED"), 1);
    assert.equal(await outbox(admin, a), 1);
    assert.deepEqual(await alerts(admin, a), ["R4_BACKUP_APPLIED"]);
    assert.equal((await admin.query("SELECT state FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2", [a.tenantId, a.consentId])).rows[0]?.state, "REVOKED");

    assert.equal((await revocation(admin, c)).status, "CONFIRMED", "la fila fallida queda como estaba (sin APPLIED)");
    assert.equal(await outbox(admin, c), 0);
    assert.deepEqual(await alerts(admin, c), ["R4_BACKUP_FAILED"]);
    assert.equal((await revocation(admin, b)).status, "VERIFIED", "el worker no toca una Revocation VERIFIED");
    assert.deepEqual(await alerts(admin, b), []);
    assert.ok(logs.length >= 1 && logs.every((l) => !l.includes(c.op1.principal) && !l.includes(c.op2.principal) && !l.includes(c.consentId)), `log sin PII: ${logs.join(" | ")}`);

    // Idempotencia: una segunda pasada no reaplica a (ya APPLIED); c sigue pendiente hasta que la falla cese.
    clock += 31_000; // vence el backoff de c: se reintenta (falla de nuevo) SIN repetir la alerta R4_BACKUP_FAILED (P2-2)
    const second = await recoverConfirmedRevocations(workerPool, new PgUnitOfWork(workerPool), 20, () => {}, backoff);
    assert.deepEqual(second, { applied: 0, failed: 1, skipped: 0 });
    assert.deepEqual(await alerts(admin, c), ["R4_BACKUP_FAILED"], "una sola alerta por fallo consecutivo");
    assert.equal(countOf(await events(admin, a), "CONSENT_REVOKED"), 1);
    assert.deepEqual(await alerts(admin, a), ["R4_BACKUP_APPLIED"]);
    await failure.remove();
    const mid = await recoverConfirmedRevocations(workerPool, new PgUnitOfWork(workerPool), 20, () => {}, backoff);
    assert.deepEqual(mid, { applied: 0, failed: 0, skipped: 1 }, "c esta en backoff: no se toca antes de tiempo");
    clock += 120_000;
    const third = await recoverConfirmedRevocations(workerPool, new PgUnitOfWork(workerPool), 20, () => {}, backoff);
    assert.deepEqual(third, { applied: 1, failed: 0, skipped: 0 });
    assert.equal((await revocation(admin, c)).status, "APPLIED");
    assert.equal((await revocation(admin, b)).status, "VERIFIED");
  } finally {
    await workerPool.end();
    await http.close();
  }
});

pgTest("TEST-CNS-1722 pg worker (P2-2): filas que fallan siempre no bloquean a las nuevas ni generan R4_BACKUP_FAILED en cada ciclo (backoff por fila); con lote 2 y dos filas fallidas mas antiguas, la nueva se aplica en el ciclo siguiente", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const bad1 = await seedCaseWorld(ctx, "1722a");
  const bad2 = await seedCaseWorld(ctx, "1722b");
  const good = await seedCaseWorld(ctx, "1722c");
  const http = await startPlatformHttp(ctx);
  const workerPool = createPool({ connectionString: ctx.urlFor("worker"), max: 2 });
  let clock = 5_000_000;
  const backoff = new RecoveryBackoff(() => clock, 30_000, 3_600_000);
  try {
    for (const w of [bad1, bad2, good]) {
      await recordRh3(admin, http, w);
      await seedConfirmedWithoutApplied(admin, w);
    }
    // Solo esta ejecucion ve a las tres: las demas filas CONFIRMED de la base compartida las aportan otros tests del archivo (ya APPLIED).
    const f1 = await injectOutboxFailure(admin, { name: "f1722a", tenantId: bad1.tenantId, failures: 1_000_000, sqlstate: "40001" });
    const f2 = await injectOutboxFailure(admin, { name: "f1722b", tenantId: bad2.tenantId, failures: 1_000_000, sqlstate: "40001" });
    const uow = new PgUnitOfWork(workerPool);
    const c1 = await recoverConfirmedRevocations(workerPool, uow, 2, () => {}, backoff);
    assert.deepEqual(c1, { applied: 0, failed: 2, skipped: 0 }, "el lote de 2 lo ocupan las dos mas antiguas, que fallan");
    assert.equal((await revocation(admin, good)).status, "CONFIRMED");
    const c2 = await recoverConfirmedRevocations(workerPool, uow, 2, () => {}, backoff);
    assert.deepEqual(c2, { applied: 1, failed: 0, skipped: 2 }, "las fallidas quedan en backoff y la nueva pasa");
    assert.equal((await revocation(admin, good)).status, "APPLIED");
    clock += 31_000;
    const c3 = await recoverConfirmedRevocations(workerPool, uow, 2, () => {}, backoff);
    assert.deepEqual(c3, { applied: 0, failed: 2, skipped: 0 }, "pasado el backoff se reintentan");
    for (const w of [bad1, bad2]) assert.deepEqual(await alerts(admin, w), ["R4_BACKUP_FAILED"], "una sola alerta por fila, no una por ciclo");
    await f1.remove();
    await f2.remove();
  } finally {
    await workerPool.end();
    await http.close();
  }
});
