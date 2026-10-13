// Gobierna: ADR-010 rev. 4 §4.2 (PR-5b), specs/state-machines/rights-case.spec.yaml `dbEnforcement` (FN-RC-01, FN-RC-02, FN-RC-06, INV-RC-07),
// db/migrations/0038_adr010_case_state_rights_case.sql; src/server/ports/rights-case-transitions.port.ts. ADR-001 §11: solo este adaptador conoce el
// SQL de las funciones `case_state.*` de RightsCase.
//
// Cada metodo llama UNA funcion SECURITY DEFINER dentro de la tx de PgUnitOfWork.inTenant (el tenant sale de app.current_tenant_id(), nunca de
// un parametro), en un SAVEPOINT (un rechazo de guard de la base deja la tx utilizable). Sin SQL dinamico: un texto SQL literal por funcion.

import type { RightsCaseTransitionsPort } from "../../../server/ports/rights-case-transitions.port.ts";
import { mapTransitionError } from "./revocation-transitions.adapter.ts";
import type { TenantTx } from "./unit-of-work.ts";

export function createPgRightsCaseTransitions(tx: TenantTx): RightsCaseTransitionsPort {
  async function run<R>(text: string, values: readonly unknown[]): Promise<R> {
    await tx.query("SAVEPOINT rights_case_transition");
    try {
      const r = await tx.query<{ r: R }>(text, values);
      await tx.query("RELEASE SAVEPOINT rights_case_transition");
      return r.rows[0]?.r as R;
    } catch (error) {
      await tx.query("ROLLBACK TO SAVEPOINT rights_case_transition");
      throw mapTransitionError(error);
    }
  }

  return {
    async open(i) {
      const r = await run<{ caseRef: string; created: boolean; sequence: number }>(
        "SELECT case_state.open_rights_case_bearer($1::text, $2::text, $3::text, $4::text) AS r",
        [i.caseRef, i.chainRef, i.revokedDecisionRef, i.origin],
      );
      return { caseRef: r.caseRef, created: r.created, sequence: Number(r.sequence) };
    },
    async confirmReturn(i) {
      const r = await run<{ sequence: number; changed: boolean }>("SELECT case_state.confirm_case_return($1::text, $2::integer) AS r", [i.caseRef, i.expectedSequence]);
      return { sequence: Number(r.sequence), changed: r.changed };
    },
    async close(i) {
      const r = await run<{ sequence: number }>("SELECT case_state.close_case($1::text, $2::text, $3::integer, $4::text) AS r", [i.caseRef, i.outcome, i.expectedSequence, i.operatorRef]);
      return { sequence: Number(r.sequence) };
    },
  };
}
