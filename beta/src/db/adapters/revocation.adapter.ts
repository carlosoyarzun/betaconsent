// Gobierna: plan v2 H1-04. Adaptador PG de RevocationRepo: revoke_decision (0003) y una lectura de estado.
// origen (ideas): src/infra/adapters/postgres/revocation.adapter.ts@9345b78 (forma).
import type { DecisionState } from "../../domain/types.ts";
import type { RevocationRepo } from "../../ports/revocation.port.ts";
import { translating } from "../map-error.ts";
import type { UnitOfWork } from "../unit-of-work.ts";

export function createPgRevocationRepo(uow: UnitOfWork): RevocationRepo {
  return {
    revoke: (input) =>
      translating(() =>
        uow.withTransaction(async (tx) => {
          const r = await tx.query<{ revocation_ref: string; deduped: boolean }>("SELECT * FROM app.revoke_decision($1, $2, $3)", [input.consentId, input.verificationRef, input.idempotencyKey]);
          const row = r.rows[0];
          if (!row) throw new Error("revoke_decision no devolvió fila.");
          return { revocationRef: row.revocation_ref, deduped: row.deduped };
        }),
      ),

    getManageState: (consentId) =>
      translating(() =>
        uow.withTransaction(async (tx) => {
          const r = await tx.query<{ consent_id: string; state: DecisionState; decided_at: Date; invitation_ref: string }>(
            "SELECT consent_id, state, decided_at, invitation_ref FROM app.consent_decision WHERE consent_id = $1",
            [consentId],
          );
          const row = r.rows[0];
          return row ? { consentId: row.consent_id, state: row.state, decidedAt: row.decided_at, invitationRef: row.invitation_ref } : null;
        }),
      ),
  };
}
