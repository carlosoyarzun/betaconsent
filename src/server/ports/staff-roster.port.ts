// Gobierna: API-CNS-116 (GET /staff/roster), REQ-CNS-036 AC-04..AC-09, UX-CNS-005, DEC-BR-019 (Notion),
// diseno api-cns-116-staff-list-design.md rev. 2 §2/§4/§5, SEC-CNS-018 rev. 2 (R3), invitation.spec
// projections.staffInvitationStatus / INV-IV-09, ADR-001 §11.
//
// Puerto (ADR-001 §11): lectura de la proyeccion COLAPSADA del roster del colegio. El dominio nunca ve `state`
// de la invitacion: el adaptador (Postgres: vista app.staff_roster_invitation_status tras SET LOCAL ROLE
// staff_roster_reader; in-memory: misma semantica de mapeo y prioridad) entrega solo `StaffInvitationStatus`.
// Cada lectura escribe UNA fila STAFF_ROSTER_READ en ops.access_log (resource_ref = tenant_id) dentro de la MISMA
// unidad de trabajo que el SELECT: si el log no se escribe, no hay datos.

import type { TenantId } from "../modules/common/types.ts";

/** Estados operativos que ve el colegio (D1, D9). Vocabulario propio: NO es el de la maquina de estados. */
export const STAFF_INVITATION_STATUSES = ["NOT_INVITED", "PENDING_SEND", "SENT", "DECISION_RECORDED", "CLOSED_WITHOUT_DECISION"] as const;
export type StaffInvitationStatus = (typeof STAFF_INVITATION_STATUSES)[number];

/** Fila de la proyeccion: una por (alumno, contexto). `contextRef` solo sirve de llave del keyset; no sale en la respuesta. */
export interface StaffRosterProjectionRow {
  readonly subjectRef: string;
  readonly contextRef: string;
  /** participation_ref de la matricula ACTIVE del alumno en ese contexto, si existe. */
  readonly activeEnrollmentParticipationRef: string | null;
  readonly staffStatus: StaffInvitationStatus;
}

export interface StaffRosterKeysetAfter {
  readonly subjectRef: string;
  readonly contextRef: string;
}

export interface StaffRosterReadRequest {
  /** Tenant de la sesion STAFF (GRD-CM-01), nunca del cliente. */
  readonly tenantId: TenantId;
  /** principalRef de la sesion (GRD-CM-02): actor_ref del access_log. */
  readonly principalRef: string;
  readonly actorRole: "TENANT_ADMIN";
  /** Keyset (subject_ref, context_ref) con COLLATE "C"; null = primera pagina. */
  readonly after: StaffRosterKeysetAfter | null;
  /** Maximo de filas a devolver (el borde pide limit + 1 para saber si hay mas). */
  readonly rowLimit: number;
}

/** Cualquier fallo de BD, de access_log, de SET ROLE, de reloj o un `staff_status` desconocido: el borde responde 503
 * (ERR-CM-12) sin datos. Nunca lleva datos de filas ni valores de la peticion. */
export class StaffRosterUnavailableError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(`staff roster no disponible (${reason})`);
    this.name = "StaffRosterUnavailableError";
    this.reason = reason;
  }
}

export interface StaffRosterReaderPort {
  /** Orden estable ORDER BY subject_ref COLLATE "C", context_ref COLLATE "C". Lanza StaffRosterUnavailableError si no puede leer. */
  readPage(request: StaffRosterReadRequest): Promise<readonly StaffRosterProjectionRow[]>;
}
