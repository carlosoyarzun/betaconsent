// Gobierna: plan v2 H1-04. Adaptador PG de AuthorizationStatusQuery: authorization_status (0003).
import type { AuthorizationStatus } from "../../domain/types.ts";
import type { AuthorizationStatusQuery } from "../../ports/authorization.port.ts";
import { translating } from "../map-error.ts";
import type { UnitOfWork } from "../unit-of-work.ts";

export function createPgAuthorizationQuery(uow: UnitOfWork): AuthorizationStatusQuery {
  return {
    byStudentRef: (studentRef) =>
      translating(() =>
        uow.withTransaction(async (tx) => {
          const r = await tx.query<{ status: AuthorizationStatus; as_of: Date; decision_ref: string | null }>("SELECT status, as_of, decision_ref FROM app.authorization_status($1)", [studentRef]);
          const row = r.rows[0];
          if (!row) throw new Error("authorization_status no devolvió fila.");
          return { status: row.status, asOf: row.as_of, decisionRef: row.decision_ref };
        }),
      ),
  };
}
