// Gobierna: API-CNS-116 (GET /staff/roster), diseno api-cns-116-staff-list-design.md rev. 2 §2 (orden fijo del GET),
// §3, §5, SEC-CNS-018 rev. 2 (R3, R6, F-7), db/migrations/0018..0020, ADR-001 §11, DEC-BR-014 rev. 8 §3 X6.
// ADR-001 §11: solo este adaptador conoce el SQL de la vista app.staff_roster_invitation_status.
//
// Orden fijo (R3), todo dentro de UNA transaccion de PgUnitOfWork.withTenantTx (BEGIN + GUC de tenant ya fijados):
//   (3) INSERT ops.access_log como app_rw (STAFF_ROSTER_READ, resource_ref = tenant_id; UNA fila por request)
//   (3b) reloj: |clock_timestamp() de la BD - Date.now()| <= 2 s (F-7); si no, 503
//   (4) SET LOCAL ROLE staff_roster_reader  y verificar current_user = staff_roster_reader (si no, 503)
//   (5) SELECT SOLO de la vista (keyset (subject_ref, context_ref) COLLATE "C")
//   (6) si alguna fila trae staff_status NULL o fuera del vocabulario -> 503 (ROLLBACK)
//   (7) COMMIT (lo hace withTenantTx; si falla -> 503). Nada se devuelve antes del COMMIT.
// Cualquier fallo -> StaffRosterUnavailableError sin datos. Este archivo NO resetea el rol ni cambia a otro rol:
// la transaccion termina con el rol reducido (SET LOCAL) y tests/unit/staff-roster verifica estaticamente que
// el unico objeto consultado es la vista y que no hay RESET ROLE ni otro SET ROLE.

import {
  STAFF_INVITATION_STATUSES,
  StaffRosterUnavailableError,
  type StaffInvitationStatus,
  type StaffRosterProjectionRow,
  type StaffRosterReaderPort,
  type StaffRosterReadRequest,
} from "../../../server/ports/staff-roster.port.ts";
import { createPgAccessLogAdapter } from "./access-log.adapter.ts";
import { checkClockSkew } from "./startup-checks.ts";
import type { PgUnitOfWork } from "./unit-of-work.ts";

interface ViewRow {
  subject_ref: string;
  context_ref: string;
  active_enrollment_participation_ref: string | null;
  staff_status: string | null;
}

const VALID_STATUSES: ReadonlySet<string> = new Set(STAFF_INVITATION_STATUSES);

export interface PgStaffRosterReaderOptions {
  /** Reloj del proceso (inyectable en tests); por defecto Date.now. */
  readonly nowMs?: () => number;
}

export function createPgStaffRosterReader(uow: Pick<PgUnitOfWork, "withTenantTx">, options: PgStaffRosterReaderOptions = {}): StaffRosterReaderPort {
  const nowMs = options.nowMs ?? Date.now;
  return {
    async readPage(request: StaffRosterReadRequest): Promise<readonly StaffRosterProjectionRow[]> {
      try {
        return await uow.withTenantTx(request.tenantId, async (tx) => {
          // (3) access_log como app_rw, en la misma tx. Un fallo (CHECK, RLS, permisos) aborta todo.
          await createPgAccessLogAdapter(tx).record({
            tenantId: request.tenantId,
            actorRef: request.principalRef,
            actorRole: request.actorRole,
            action: "STAFF_ROSTER_READ",
            resourceType: "STAFF_ROSTER",
            resourceRef: request.tenantId,
          });
          // (3b) F-7: la vista usa now() de la BD; el dominio, Date.now().
          const skew = await checkClockSkew(tx, nowMs);
          if (!skew.ok) throw new StaffRosterUnavailableError("clock_skew");
          // (4) rol reducido solo para el SELECT de la vista.
          await tx.query("SET LOCAL ROLE staff_roster_reader");
          const who = await tx.query<{ me: string }>("SELECT current_user::text AS me");
          if (who.rows[0]?.me !== "staff_roster_reader") throw new StaffRosterUnavailableError("role_not_applied");
          // (5) SOLO la vista. Keyset (subject_ref, context_ref) con COLLATE "C" (R6).
          const after = request.after;
          const result = await tx.query<ViewRow>(
            `SELECT subject_ref, context_ref, active_enrollment_participation_ref, staff_status
               FROM app.staff_roster_invitation_status
              WHERE ($1::text IS NULL
                     OR (subject_ref COLLATE "C", context_ref COLLATE "C") > ($1::text COLLATE "C", $2::text COLLATE "C"))
              ORDER BY subject_ref COLLATE "C", context_ref COLLATE "C"
              LIMIT $3`,
            [after?.subjectRef ?? null, after?.contextRef ?? null, request.rowLimit],
          );
          // (6) CASE sin ELSE: un estado desconocido llega como NULL -> 503 y ROLLBACK.
          return result.rows.map((row): StaffRosterProjectionRow => {
            if (row.staff_status === null || !VALID_STATUSES.has(row.staff_status)) throw new StaffRosterUnavailableError("unknown_status");
            return {
              subjectRef: row.subject_ref,
              contextRef: row.context_ref,
              activeEnrollmentParticipationRef: row.active_enrollment_participation_ref,
              staffStatus: row.staff_status as StaffInvitationStatus,
            };
          });
        });
      } catch (error) {
        // (7) cualquier fallo, incluido el COMMIT: 503 sin datos. Nunca se propaga el mensaje de la BD.
        if (error instanceof StaffRosterUnavailableError) throw error;
        throw new StaffRosterUnavailableError("database");
      }
    },
  };
}
