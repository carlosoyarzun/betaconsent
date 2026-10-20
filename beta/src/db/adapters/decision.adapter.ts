// Gobierna: plan v2 H1-04. Adaptador PG de DecisionRepo: record_decision (0003) y una lectura de estado.
// origen (ideas): src/infra/adapters/postgres/consent-decision.adapter.ts@9345b78 (forma).
import type { DecisionState, InvitationState } from "../../domain/types.ts";
import type { DecisionPageState, DecisionRepo } from "../../ports/decision.port.ts";
import { translating } from "../map-error.ts";
import type { UnitOfWork } from "../unit-of-work.ts";

export function createPgDecisionRepo(uow: UnitOfWork): DecisionRepo {
  return {
    record: (input) =>
      translating(() =>
        uow.withTransaction(async (tx) => {
          const r = await tx.query<{ consent_id: string; state: DecisionState; deduped: boolean }>("SELECT * FROM app.record_decision($1, $2, $3, $4, $5, $6, $7::jsonb)", [
            input.invitationRef,
            input.verificationRef,
            input.outcome,
            input.consentVersion,
            input.consentTextHash,
            input.idempotencyKey,
            JSON.stringify(input.purposes ?? []),
          ]);
          const row = r.rows[0];
          if (!row) throw new Error("record_decision no devolvió fila.");
          return { consentId: row.consent_id, state: row.state, deduped: row.deduped };
        }),
      ),

    getPageState: (invitationRef) =>
      translating(() =>
        uow.withTransaction(async (tx): Promise<DecisionPageState | null> => {
          const r = await tx.query<{ state: InvitationState; consent_version: string | null; consent_id: string | null; decision_state: DecisionState | null }>(
            `SELECT i.state, i.consent_version, d.consent_id, d.state AS decision_state
               FROM app.invitation i LEFT JOIN app.consent_decision d ON d.tenant_id = i.tenant_id AND d.invitation_ref = i.invitation_ref
              WHERE i.invitation_ref = $1`,
            [invitationRef],
          );
          const row = r.rows[0];
          if (!row) return null;
          return {
            invitationState: row.state,
            consentVersion: row.consent_version,
            decision: row.consent_id && row.decision_state ? { consentId: row.consent_id, state: row.decision_state } : null,
          };
        }),
      ),
  };
}
