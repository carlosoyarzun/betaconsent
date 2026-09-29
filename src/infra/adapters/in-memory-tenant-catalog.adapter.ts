// Gobierna: src/server/ports/tenant-catalog.port.ts. Adaptador in-memory IT0: catálogo sembrado
// por fixture (dev-local-config.ts / tests). Vacío por defecto = fail-closed (todo sujeto y toda
// participación es desconocido). Solo refs opacas sintéticas; cero PII.

import type { SchoolParticipationView, TenantCatalogPort } from "../../server/ports/tenant-catalog.port.ts";

export interface FixtureTenantCatalogPort extends TenantCatalogPort {
  seedSubject(tenantId: string, subjectRef: string): void;
  seedParticipation(tenantId: string, participation: SchoolParticipationView): void;
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
    seedSubject(tenantId, subjectRef) {
      subjects.add(key(tenantId, subjectRef));
    },
    seedParticipation(tenantId, participation) {
      participations.set(key(tenantId, participation.participationRef), { ...participation });
    },
  };
}
