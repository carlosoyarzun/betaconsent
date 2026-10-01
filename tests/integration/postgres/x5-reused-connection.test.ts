// Gobierna: CA-124 (PR-E), common.spec.yaml INV-CM-02/INV-3, DEC-BR-014 X5 (TEST-CNS-102: 0 accesos
// cross-tenant, incluida la conexion reusada A->B), ADR-006 §1/§4-§6. TEST-CNS-876: cierra el hueco de
// X5 en las tablas de PR-D y del catalogo con un pool de UNA conexion fisica: A escribe, B (misma
// conexion) lee 0 filas en cada tabla de agregado, y sin set_config (fuera de tx) tampoco hay filas ni se
// puede insertar. Requiere Postgres real (harness.ts).

import assert from "node:assert/strict";

import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../../src/infra/adapters/postgres/unit-of-work.ts";
import { syntheticDecision } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const TABLES = ["invitation", "otp_verification", "rights_case", "enrollment", "consent_decision", "revocation", "recovery_token", "idempotency_key"] as const;

pgTest("TEST-CNS-876 pg X5: con una sola conexion A->B->(sin tenant) ninguna tabla de agregado de PR-C/D/E filtra filas ni admite escritura cruzada", async (ctx) => {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 1 });
  try {
    const uow = new PgUnitOfWork(pool, { idempotencyPolicy: { ttlMs: 60_000 } });
    const A = fixtureUuid("tenant-a-876");
    const B = fixtureUuid("tenant-b-876");
    const key = fixtureUuid("k").replaceAll("-", "").padEnd(64, "0");
    await uow.inTenant(A, async (tx) => {
      await tx.invitationRepo.save({ invitationRef: fixtureUuid("inv"), tenantId: A, contextRef: "BETA_2026_01", productRef: "LECTORPRO", subjectRef: fixtureUuid("s"), state: "DRAFT" });
      await tx.otpRepo.save({ verificationRef: fixtureUuid("ver"), tenantId: A, scope: "DECISION", parentRef: fixtureUuid("inv"), channelRef: "x876@example.invalid", codeHash: key, attempts: 0, expiresAt: new Date(Date.now() + 60_000), state: "CODE_SENT", resendCount: 0 });
      await tx.rightsCaseRepo.save({ caseRef: fixtureUuid("case"), tenantId: A, chainRef: "chain-876", revokedDecisionRef: fixtureUuid("d"), status: "OPEN" });
      await tx.enrollmentRepo.save({ enrollmentRef: fixtureUuid("en"), tenantId: A, subjectRef: fixtureUuid("s"), participationRef: fixtureUuid("p"), state: "ACTIVE" });
      await tx.consentDecisionRepo.save({ ...syntheticDecision(A, fixtureUuid("d")), chainRef: "chain-876" });
      await tx.revocationRepo.save({ revocationRef: fixtureUuid("rev"), tenantId: A, chainRef: "chain-876", revokedDecisionRef: fixtureUuid("d"), status: "REQUESTED" });
      await tx.recoveryTokenRepo.save({ tokenHash: key, recoveryRef: "rec-876", tenantId: A, chainRef: "chain-876", revokedDecisionRef: fixtureUuid("d"), expiresAt: new Date(Date.now() + 60_000) });
      await tx.idempotency.store(A, key, { payloadHash: key, status: 201, body: { ok: true } });
    });
    const countRows = async (tenant: string | null): Promise<Record<string, number>> => {
      const read = async (tx: { query: (t: string) => Promise<{ rows: Array<{ n: number }> }> }): Promise<Record<string, number>> => {
        const out: Record<string, number> = {};
        for (const t of TABLES) out[t] = (await tx.query(`SELECT count(*)::int AS n FROM app.${t}`)).rows[0]?.n ?? -1;
        return out;
      };
      if (tenant !== null) return uow.withTenantTx(tenant, read);
      const client = await pool.connect(); // sin set_config: conexion limpia fuera de tx
      try {
        return await read(client);
      } finally {
        client.release();
      }
    };
    const zero = Object.fromEntries(TABLES.map((t) => [t, 0]));
    const one = Object.fromEntries(TABLES.map((t) => [t, 1]));
    assert.deepEqual(await countRows(A), one, "A ve lo suyo");
    assert.deepEqual(await countRows(B), zero, "B (misma conexion fisica) ve 0 filas");
    assert.deepEqual(await countRows(null), zero, "sin tenant: 0 filas");
    assert.deepEqual(await countRows(A), one, "A de nuevo ve lo suyo (B no lo altero)");

    // Escritura cruzada (WITH CHECK) y sin tenant: rechazada.
    await assert.rejects(() => uow.inTenant(B, (tx) => tx.invitationRepo.save({ invitationRef: fixtureUuid("inv-x"), tenantId: A, contextRef: "BETA_2026_01", productRef: "LECTORPRO", subjectRef: fixtureUuid("s2"), state: "DRAFT" })));
    const client = await pool.connect();
    try {
      await assert.rejects(() => client.query("INSERT INTO app.enrollment (tenant_id, enrollment_ref, subject_ref, participation_ref, state) VALUES ($1, 'x', 'x', 'x', 'ACTIVE')", [A]));
    } finally {
      client.release();
    }
    assert.deepEqual(await countRows(A), one);
  } finally {
    await pool.end();
  }
});
