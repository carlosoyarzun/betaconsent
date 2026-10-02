// Gobierna: src/server/ports/tenant-catalog.port.ts. Adaptador in-memory IT0: catálogo sembrado
// por fixture (dev-local-config.ts / tests). Vacío por defecto = fail-closed (todo sujeto y toda
// participación es desconocido). Solo refs opacas sintéticas; cero PII.

import type { SchoolParticipationView, TenantCatalogPort } from "../../server/ports/tenant-catalog.port.ts";

export interface FixtureTenantCatalogPort extends TenantCatalogPort {
  seedSubject(tenantId: string, subjectRef: string): void;
  seedParticipation(tenantId: string, participation: SchoolParticipationView): void;
  /** Listados de LECTURA para la proyeccion in-memory del roster (API-CNS-116); no son parte del puerto del dominio. */
  listSubjects(tenantId: string): readonly string[];
  listParticipations(tenantId: string): readonly SchoolParticipationView[];
}

export function createInMemoryTenantCatalogAdapter(): FixtureTenantCatalogPort {
  const subjects = new Set<string>();
  const participations = new Map<string, SchoolParticipationView>();
  const key = (tenantId: string, ref: string): string => `${tenantId}\u0000${ref}`;

  return {
    async subjectBelongsToTenant(tenantId, subjectRef) {
      return subjects.has(key(tenantId, subjectRef));
    },
    async findParticipation(tenantId, participationRef) {
      return participations.get(key(tenantId, participationRef)) ?? null;
    },
    listSubjects(tenantId) {
      const prefix = `${tenantId}\u0000`;
      return [...subjects].filter((k) => k.startsWith(prefix)).map((k) => k.slice(prefix.length));
    },
    listParticipations(tenantId) {
      return [...participations.entries()].filter(([k]) => k.startsWith(`${tenantId}\u0000`)).map(([, v]) => v);
    },
    seedSubject(tenantId, subjectRef) {
      subjects.add(key(tenantId, subjectRef));
    },
    seedParticipation(tenantId, participation) {
      participations.set(key(tenantId, participation.participationRef), { ...participation });
    },
  };
}
