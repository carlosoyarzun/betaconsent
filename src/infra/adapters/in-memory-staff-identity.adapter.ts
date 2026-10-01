// Gobierna: src/server/ports/staff-identity.port.ts. Adaptador in-memory (ADR-001 §11): la
// lista nominal se inyecta en la construcción (dev-local-config.ts LOCAL_ONLY_DEV_STAFF_ROSTER,
// o los fixtures de test); este adaptador nunca decide ni genera identidades por sí mismo, solo
// resuelve contra lo que el llamador le pasó.
// OPEN-TC-06: PRIVACY_LEGAL y SECURITY se modelan como APPROVER en IT0 (Carlos, 2026-10-01).

import type { StaffIdentityPort, StaffPrincipal } from "../../server/ports/staff-identity.port.ts";

export function createInMemoryStaffIdentityAdapter(roster: readonly StaffPrincipal[]): StaffIdentityPort {
  // X6 P2-6: un mismo principalRef en dos entradas (p. ej. en dos roles) rompe la separación de funciones
  // (GRD-RV-09, GRD-RC-15): se rechaza al construir, no al resolver.
  const seen = new Set<string>();
  for (const principal of roster) {
    if (seen.has(principal.principalRef)) throw new Error("staff roster: principalRef duplicado (separación de funciones, GRD-RV-09)");
    seen.add(principal.principalRef);
  }
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
