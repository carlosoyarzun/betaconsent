// Gobierna: CA-128 (X6 P2-7), db/migrations/0016_revocation_rh2_dual_control.sql, DEC-BR-014 §3, INV-CM-09 (refs opacas).
// TEST-CNS-1009: los CHECK de proposal_ref / proposed_by_ref / second_approver_ref exigen el mismo patrón UUIDv4/staff que
// 0014 (no solo largo): un email o un RUT sintéticos se rechazan. Requiere Postgres real (harness.ts); skip sin entorno.

import assert from "node:assert/strict";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const codeOf = (error: unknown): string | undefined => (error as { code?: string }).code;
const constraintOf = (error: unknown): string | undefined => (error as { constraint?: string }).constraint;

pgTest("TEST-CNS-1009 pg: proposal_ref/proposed_by_ref/second_approver_ref rechazan email y RUT; aceptan UUIDv4 y staff-synthetic-NN", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const t = fixtureUuid("t1009");
  const insert = (n: string, cols: string): string =>
    `INSERT INTO app.revocation (revoked_decision_ref, tenant_id, revocation_ref, chain_ref, status, ${cols}) VALUES ('dec-${n}', $1, 'r-${n}', 'ch', 'REQUESTED', ${cols === "proposal_ref, proposed_by_ref, verification_script_version" ? "$2, $3, 'guion-1'" : "$2, $3, 'guion-1', $4"})`;
  const bad = ["padre@x.cl", "12.345.678-5", "12345678-5", "abc", "staff-synthetic-1"];
  const ok = fixtureUuid("ok-1009");
  await admin.query("BEGIN");
  try {
    for (const [i, value] of bad.entries()) {
      for (const [col, args, constraint] of [
        ["proposal_ref", [value, ok], "revocation_proposal_ref_shape"],
        ["proposed_by_ref", [ok, value], "revocation_proposed_by_shape"],
      ] as const) {
        await admin.query("SAVEPOINT s");
        await assert.rejects(
          () => admin.query(insert(`${col}${i}`, "proposal_ref, proposed_by_ref, verification_script_version"), [t, ...args]),
          (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === constraint,
          `${col}=${value}`,
        );
        await admin.query("ROLLBACK TO s");
      }
      await admin.query("SAVEPOINT s");
      await assert.rejects(
        () => admin.query(insert(`sa${i}`, "proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref"), [t, ok, fixtureUuid("op-1009"), value]),
        (e: unknown) => codeOf(e) === "23514" && constraintOf(e) === "revocation_second_approver_shape",
        `second_approver_ref=${value}`,
      );
      await admin.query("ROLLBACK TO s");
    }
    // Positivos: UUIDv4 y staff-synthetic-NN (mismo patrón que actor_ref de 0014).
    await admin.query(insert("okuuid", "proposal_ref, proposed_by_ref, verification_script_version"), [t, ok, fixtureUuid("op-1009")]);
    await admin.query(insert("okstaff", "proposal_ref, proposed_by_ref, verification_script_version, second_approver_ref"), [t, fixtureUuid("p2-1009"), "staff-synthetic-01", "staff-synthetic-02"]);
  } finally {
    await admin.query("ROLLBACK");
  }
});
