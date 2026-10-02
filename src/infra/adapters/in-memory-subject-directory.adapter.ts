// Gobierna: src/server/ports/subject-directory.port.ts, API-CNS-116 (api-cns-116-staff-list-design.md rev. 2 §4 P2-d),
// REQ-CNS-036 AC-04, LEGAL DECISION LD-e. Directorio SINTETICO IT0: el roster lo inyecta el composition root
// (src/server/entrypoints/dev.ts, LOCAL_ONLY_DEV_STAFF_STUDENTS). Solo LOCAL/CI: la fabrica comprueba el entorno
// declarado (que el arranque ya valido contra ops.catalog_environment() de la BD: startup-checks.ts
// expectedEnvironment) y, si no es LOCAL, el proceso NO arranca (patron ERR-CM-11). La clave es (tenantId, subjectRef).

import type { TenantId } from "../../server/modules/common/types.ts";
import type { SubjectDirectoryEntry, SubjectDirectoryPort } from "../../server/ports/subject-directory.port.ts";

export interface SyntheticDirectoryStudent {
  readonly tenantId: TenantId;
  readonly subjectRef: string;
  readonly label: string;
  readonly participationRef: string | null;
}

export class SubjectDirectoryEnvironmentError extends Error {
  constructor() {
    super("ERR-CM-11: el directorio sintetico de alumnos solo existe en LOCAL (SYNTHETIC DATA ONLY); el proceso no arranca.");
    this.name = "SubjectDirectoryEnvironmentError";
  }
}

export function createInMemorySubjectDirectory(environment: string, students: readonly SyntheticDirectoryStudent[]): SubjectDirectoryPort {
  if (environment !== "LOCAL") throw new SubjectDirectoryEnvironmentError();
  const byKey = new Map<string, SubjectDirectoryEntry>();
  for (const s of students) byKey.set(`${s.tenantId}\u0000${s.subjectRef}`, { label: s.label, participationRef: s.participationRef });
  return {
    async lookup(tenantId, subjectRef) {
      return byKey.get(`${tenantId}\u0000${subjectRef}`) ?? null;
    },
  };
}
