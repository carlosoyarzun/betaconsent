// Gobierna: specs/state-machines/tenant-context.spec.yaml TN1/SP1 (seed sintético),
// specs/state-machines/common.spec.yaml GRD-CM-13/14/15, actorModel.fixture. Alcance IT0 de
// este archivo: solo el guard de fuente/entorno de las funciones de seed (TEST-CNS-472,
// TEST-CNS-473); la creación real de Tenant/SchoolParticipation (catálogo completo) es una
// historia posterior.

import { assertExecutionSourceIsSeed, assertFixtureEnvironment } from "../common/guards.ts";
import type { ExecutionContext } from "../common/types.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";

export interface SeedTenantPorts {
  readonly ledger: LedgerPort;
}

/**
 * TN1 (seed sintético de Tenant). GRD-CM-14: solo la fuente FIXTURE (rol de seed del
 * bootstrap LOCAL) puede ejecutarla; app_rw/platform_rw (fuentes BEARER/STAFF/PLATFORM) se
 * rechazan con ERR-CM-10, como si la base negara EXECUTE a esos roles (TEST-CNS-473),
 * cualquiera sea el campo que la request declare. GRD-CM-13: además exige environment LOCAL.
 * El ledger registra SIEMPRE actorType FIXTURE, nunca HUMAN ni SYSTEM_GUARD (TEST-CNS-472).
 */
export function seedTenant(ctx: ExecutionContext, ports: SeedTenantPorts, tenantId: string): void {
  assertExecutionSourceIsSeed(ctx);
  assertFixtureEnvironment("FIXTURE", ctx.environment);
  ports.ledger.append({
    eventType: "TENANT_SEEDED",
    tenantId,
    aggregateType: "Tenant",
    aggregateId: tenantId,
    actorType: "FIXTURE",
    payload: {},
    idempotencyKey: `${tenantId}:tn1`,
  });
}

/**
 * SP1 (seed sintético de SchoolParticipation). Mismos guards que TN1 (GRD-CM-13/14).
 */
export function seedSchoolParticipation(
  ctx: ExecutionContext,
  ports: SeedTenantPorts,
  tenantId: string,
  participationRef: string,
): void {
  assertExecutionSourceIsSeed(ctx);
  assertFixtureEnvironment("FIXTURE", ctx.environment);
  ports.ledger.append({
    eventType: "SCHOOL_PARTICIPATION_SEEDED",
    tenantId,
    aggregateType: "SchoolParticipation",
    aggregateId: participationRef,
    actorType: "FIXTURE",
    payload: {},
    idempotencyKey: `${participationRef}:sp1`,
  });
}
