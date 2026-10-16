// Gobierna: ADR-010 rev. 5 (enmienda rev. c, 2026-10-15) §4.2.a, §4.2.d, §6, §10 fila 6d; GRD-RC-10, GRD-RC-12; API-CNS-136/137. SYNTHETIC ONLY. Requiere Postgres real (harness.ts).
// Los tests de un archivo comparten base: cada uno usa su propio mundo (refs y tenant propios).

import assert from "node:assert/strict";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { casePath, seedAttestedStepUp, seedCaseWorld, startPlatformHttp } from "../../helpers/pg-case-world.ts";
import { pgTest } from "./harness.ts";

pgTest("TEST-CNS-1711 pg platform HTTP: RH2 (propuesta + aprobacion con step-up y sesion PLATFORM), RH3 (registro + co-firma con R4 atomica) y cierre; el actor sale de la sesion", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const w = await seedCaseWorld(ctx, "1711");
  const http = await startPlatformHttp(ctx);
  try {
    const p = casePath(w.caseRef);
    const proposalRef = fixtureUuid("proposal-1711");
    await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", proposalRef);
    const proposed = await http.post(p.proposals, w.op1.caseSession.sid, { proposalRef, verificationScriptVersion: "guion-1" });
    assert.equal(proposed.status, 201, proposed.body);
    const afterPropose = (await admin.query("SELECT status, proposed_by_ref FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0];
    assert.deepEqual(afterPropose, { status: "REQUESTED", proposed_by_ref: w.op1.principal }, "el proponente es el principal de la sesion CASE");

    await seedAttestedStepUp(admin, w.approver.principal, "APPROVE_CASE_VERIFICATION", proposalRef);
    const approved = await http.post(p.approval(proposalRef), w.approver.platform.sid, {}, { kind: "PLATFORM" });
    assert.equal(approved.status, 200, approved.body);
    const afterApprove = (await admin.query("SELECT status, second_approver_ref FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0];
    assert.deepEqual(afterApprove, { status: "VERIFIED", second_approver_ref: w.approver.principal });
    assert.equal((await admin.query("SELECT 1 FROM platform.case_verification WHERE tenant_id = $1 AND case_ref = $2 AND proposed_by_ref = $3 AND approved_by_ref = $4", [w.tenantId, w.caseRef, w.op1.principal, w.approver.principal])).rowCount, 1);

    const recorded = await http.post(p.confirmation, w.op1.caseSession.sid, { confirmationGivenOnCasePage: true });
    assert.equal(recorded.status, 200, recorded.body);
    const cosigned = await http.post(p.cosign, w.op2.caseSession.sid, {});
    assert.equal(cosigned.status, 200, cosigned.body);
    assert.deepEqual(JSON.parse(cosigned.body), { cosign: "COSIGNED", revocationState: "APPLIED" });
    const row = (await admin.query("SELECT status, recorded_by_ref, cosigned_by_ref FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef])).rows[0];
    assert.deepEqual(row, { status: "APPLIED", recorded_by_ref: w.op1.principal, cosigned_by_ref: w.op2.principal });

    const closed = await http.post(p.close, w.op1.caseSession.sid, { outcome: "RESOLVED" });
    assert.equal(closed.status, 200, closed.body);
    assert.equal((await admin.query("SELECT status FROM app.rights_case WHERE tenant_id = $1 AND case_ref = $2", [w.tenantId, w.caseRef])).rows[0]?.status, "RESOLVED");
  } finally {
    await http.close();
  }
});
