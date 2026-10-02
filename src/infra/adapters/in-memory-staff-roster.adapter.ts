// Gobierna: API-CNS-116 (GET /staff/roster), diseno api-cns-116-staff-list-design.md rev. 2 §5 (mapeo y prioridad PC-1/PC-2),
// REQ-CNS-036 AC-05/AC-06, DEC-BR-019 (Notion), invitation.spec projections.staffInvitationStatus (INV-IV-09).
// Adaptador in-memory IT0 (CONSENT_STORE=memory, LOCAL/CI): MISMA semantica de mapeo y prioridad que la vista
// app.staff_roster_invitation_status (db/migrations/0019). Tests de contrato compartidos
// (tests/contract/ports/staff-roster.contract.ts) corren las mismas escenas contra los dos adaptadores.
//
// Cada lectura escribe UNA fila STAFF_ROSTER_READ en el access log dentro de la MISMA unidad de trabajo
// (journal): si el log falla, no hay datos (StaffRosterUnavailableError -> 503). El reloj es el del proceso
// (en memoria no hay segundo reloj). Estado desconocido = StaffRosterUnavailableError (equivale a NULL -> 503).

import type { InvitationRecord } from "../../server/ports/invitation-repository.port.ts";
import {
  StaffRosterUnavailableError,
  type StaffInvitationStatus,
  type StaffRosterProjectionRow,
  type StaffRosterReaderPort,
} from "../../server/ports/staff-roster.port.ts";
import type { UnitOfWorkPort } from "../../server/ports/unit-of-work.port.ts";
import type { EnrollmentListing } from "./in-memory-enrollment-repository.adapter.ts";
import type { InvitationListing } from "./in-memory-invitation-repository.adapter.ts";
import type { FixtureTenantCatalogPort } from "./in-memory-tenant-catalog.adapter.ts";

export interface InMemoryStaffRosterSources {
  /** UoW con el access log del proceso (misma unidad de trabajo que la lectura). */
  readonly uow: UnitOfWorkPort;
  readonly invitations: InvitationListing;
  readonly enrollments: EnrollmentListing;
  readonly catalog: Pick<FixtureTenantCatalogPort, "listSubjects" | "listParticipations">;
  /** Inyectable en tests; por defecto Date.now. */
  readonly nowMs?: () => number;
}

type EffectiveInvitation = Pick<InvitationRecord, "state" | "expiresAt">;

/** Espejo de la rama del CASE de la vista: null = estado sin rama (la vista da NULL y el GET responde 503). */
export function staffStatusOf(inv: EffectiveInvitation | null, nowMs: number): StaffInvitationStatus | null {
  if (inv === null) return "NOT_INVITED";
  const expires = inv.expiresAt === undefined ? null : inv.expiresAt.getTime();
  switch (inv.state) {
    case "COMPLETED":
    case "DECLINED":
      return "DECISION_RECORDED";
    case "DRAFT":
      return "PENDING_SEND";
    case "READY":
      return expires === null || expires > nowMs ? "PENDING_SEND" : "CLOSED_WITHOUT_DECISION";
    case "SENT":
    case "OPENED":
    case "VERIFIED":
      if (expires === null) return null; // sin vencimiento no hay rama (fail-closed, igual que la vista)
      return expires > nowMs ? "SENT" : "CLOSED_WITHOUT_DECISION";
    default:
      return null;
  }
}

/** Prioridad PC-2: 0 = no terminal efectiva, 1 = decision, 2 = cerrada. Espejo del ORDER BY del LATERAL de la vista. */
function rankOf(inv: EffectiveInvitation, nowMs: number): number {
  const expires = inv.expiresAt === undefined ? null : inv.expiresAt.getTime();
  if (inv.state === "DRAFT") return 0;
  if (inv.state === "READY" && (expires === null || expires > nowMs)) return 0;
  if ((inv.state === "SENT" || inv.state === "OPENED" || inv.state === "VERIFIED") && expires !== null && expires > nowMs) return 0;
  if (inv.state === "COMPLETED" || inv.state === "DECLINED") return 1;
  return 2;
}

const byC = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0); // COLLATE "C" para refs ASCII

export function createInMemoryStaffRosterReader(sources: InMemoryStaffRosterSources): StaffRosterReaderPort {
  const nowMs = sources.nowMs ?? Date.now;
  return {
    async readPage(request) {
      try {
        return await sources.uow.inTenant(request.tenantId, async (tx) => {
          await tx.accessLog.record({
            tenantId: request.tenantId,
            actorRef: request.principalRef,
            actorRole: request.actorRole,
            action: "STAFF_ROSTER_READ",
            resourceType: "STAFF_ROSTER",
            resourceRef: request.tenantId,
          });
          const now = nowMs();
          const tenantId = request.tenantId;
          const participations = sources.catalog.listParticipations(tenantId);
          const contexts = [...new Set(participations.map((p) => p.contextRef))];
          const contextOfParticipation = new Map(participations.map((p) => [p.participationRef, p.contextRef]));
          const invitations = sources.invitations.listByTenant(tenantId).map((inv, order) => ({ inv, order }));
          const enrollments = sources.enrollments.listByTenant(tenantId).filter((e) => e.state === "ACTIVE");

          const rows: StaffRosterProjectionRow[] = [];
          for (const subjectRef of sources.catalog.listSubjects(tenantId)) {
            for (const contextRef of contexts) {
              const chosen = invitations
                .filter(({ inv }) => inv.subjectRef === subjectRef && inv.contextRef === contextRef)
                .sort(
                  (a, b) =>
                    rankOf(a.inv, now) - rankOf(b.inv, now) ||
                    b.order - a.order || // created_at DESC (el orden de insercion equivale a created_at)
                    byC(b.inv.invitationRef, a.inv.invitationRef), // invitation_ref COLLATE "C" DESC
                )[0];
              const status = staffStatusOf(chosen ? chosen.inv : null, now);
              if (status === null) throw new StaffRosterUnavailableError("unknown_status");
              const participationRef =
                enrollments
                  .filter((e) => e.subjectRef === subjectRef && contextOfParticipation.get(e.participationRef) === contextRef)
                  .map((e) => e.participationRef)
                  .sort(byC)[0] ?? null;
              rows.push({ subjectRef, contextRef, activeEnrollmentParticipationRef: participationRef, staffStatus: status });
            }
          }
          rows.sort((a, b) => byC(a.subjectRef, b.subjectRef) || byC(a.contextRef, b.contextRef));
          const after = request.after;
          const page = after === null ? rows : rows.filter((r) => byC(r.subjectRef, after.subjectRef) > 0 || (r.subjectRef === after.subjectRef && byC(r.contextRef, after.contextRef) > 0));
          return page.slice(0, request.rowLimit);
        });
      } catch (error) {
        if (error instanceof StaffRosterUnavailableError) throw error;
        throw new StaffRosterUnavailableError("in_memory");
      }
    },
  };
}
