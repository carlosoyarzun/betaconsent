// Gobierna: src/server/ports/staff-identity.port.ts. Adaptador in-memory (ADR-001 §11): la
// lista nominal se inyecta en la construcción (dev-local-config.ts LOCAL_ONLY_DEV_STAFF_ROSTER,
// o los fixtures de test); este adaptador nunca decide ni genera identidades por sí mismo, solo
// resuelve contra lo que el llamador le pasó.

import type { StaffIdentityPort, StaffPrincipal } from "../../server/ports/staff-identity.port.ts";

export function createInMemoryStaffIdentityAdapter(roster: readonly StaffPrincipal[]): StaffIdentityPort {
  const byRef = new Map(roster.map((principal) => [principal.principalRef, principal]));
  return {
    async findByPrincipalRef(principalRef) {
      return byRef.get(principalRef) ?? null;
    },
    async listRoster() {
      return roster;
    },
  };
}
