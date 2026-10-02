// Gobierna: API-CNS-116 (GET /staff/roster), diseno api-cns-116-staff-list-design.md rev. 2 §4 (P2-d),
// REQ-CNS-036 AC-04 (etiqueta sintetica del alumno), LEGAL DECISION LD-e (nombres reales post-IT0), ADR-001 §11.
//
// Puerto (ADR-001 §11): directorio de alumnos del colegio. El catalogo (app.subject) NO tiene etiqueta: con datos
// sinteticos IT0 la etiqueta "Alumno de prueba N" y la participacion de un alumno sin matricula la aporta un
// roster inyectado desde el composition root (src/server/entrypoints/dev.ts), solo LOCAL/CI. La clave es SIEMPRE
// (tenantId, subjectRef): un subjectRef compartido entre tenants no cruza datos. Con datos reales Consent App no
// guarda nombres (LEGAL DECISION LD-e).

import type { TenantId } from "../modules/common/types.ts";

export interface SubjectDirectoryEntry {
  /** Etiqueta sintetica; el borde la valida contra SUBJECT_LABEL_PATTERN y, si no cumple, responde null. */
  readonly label: string;
  /** SchoolParticipation sintetica sugerida para invitar al alumno (solo se expone en NOT_INVITED). */
  readonly participationRef: string | null;
}

export interface SubjectDirectoryPort {
  lookup(tenantId: TenantId, subjectRef: string): Promise<SubjectDirectoryEntry | null>;
}

/** Espejo de StaffRosterRow.subjectLabel (api-payloads.schema.json). */
export const SUBJECT_LABEL_PATTERN = /^Alumno de prueba [0-9]{1,4}$/;
