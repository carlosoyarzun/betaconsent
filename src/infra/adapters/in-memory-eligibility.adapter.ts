// Gobierna: src/server/ports/eligibility.port.ts. Adaptador in-memory IT0: stub controlado
// por fixtures (sin módulo tenant-context real todavía). Por defecto TODO (tenantId,
// contextRef, productRef) es elegible; los tests marcan explícitamente los casos
// inelegibles con `setEligible(..., false)` (fail-closed: solo se declara true lo fijado).

import type { EligibilityPort } from "../../server/ports/eligibility.port.ts";

export interface FixtureEligibilityPort extends EligibilityPort {
  setEligible(tenantId: string, contextRef: string, productRef: string, eligible: boolean): void;
}

export function createInMemoryEligibilityAdapter(defaultEligible = true): FixtureEligibilityPort {
  const overrides = new Map<string, boolean>();

  function key(tenantId: string, contextRef: string, productRef: string): string {
    return `${tenantId}\u0000${contextRef}\u0000${productRef}`;
  }

  return {
    async isEligibleForIssuance(tenantId, contextRef, productRef) {
      const override = overrides.get(key(tenantId, contextRef, productRef));
      return override ?? defaultEligible;
    },
    setEligible(tenantId, contextRef, productRef, eligible) {
      overrides.set(key(tenantId, contextRef, productRef), eligible);
    },
  };
}
