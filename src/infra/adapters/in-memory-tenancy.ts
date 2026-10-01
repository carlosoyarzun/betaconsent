// Gobierna: CA-124 (diseño postgres-design.md rev. 2 §5). Cableado in-memory del par
// UnitOfWorkPort + TenantResolverPort sobre los MISMOS adaptadores que ya componen los puertos
// de un módulo (tests y entrypoints IT0): comparten estado, así el journal del UoW deshace
// exactamente lo que el resto del proceso ve.

import type { TenantResolverPort } from "../../server/ports/tenant-resolver.port.ts";
import type { TenantTxPorts, UnitOfWorkPort } from "../../server/ports/unit-of-work.port.ts";
import type { TenantHandlePort } from "../../server/ports/tenant-handle.port.ts";
import { createInMemoryIdempotencyAdapter, LOCAL_ONLY_IN_MEMORY_IDEMPOTENCY_TTL_MS } from "./in-memory-idempotency.adapter.ts";
import { createInMemoryTenantCatalogAdapter } from "./in-memory-tenant-catalog.adapter.ts";
import { createInMemoryConsentDecisionRepository } from "./in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryEnrollmentRepository } from "./in-memory-enrollment-repository.adapter.ts";
import { createInMemoryInvitationRepository } from "./in-memory-invitation-repository.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "./in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryOutboxAdapter } from "./in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "./in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "./in-memory-revocation-repository.adapter.ts";
import { createInMemoryRightsCaseRepository } from "./in-memory-rights-case-repository.adapter.ts";
import { createInMemoryTenantResolver } from "./in-memory-tenant-resolver.adapter.ts";
import { createInMemoryUnitOfWork } from "./in-memory-unit-of-work.adapter.ts";

export interface InMemoryTenancyPorts {
  readonly uow: UnitOfWorkPort;
  readonly tenantResolver: TenantResolverPort;
}

/** Puertos de tenant que un llamador comparte con su módulo. Solo `ledger` es obligatorio (lo
 * comparten todos los módulos); cualquier repo/outbox omitido se sustituye por uno in-memory
 * PRIVADO y vacío (no compartido con nadie): válido para módulos que no lo tocan. */
export type InMemoryTenancySources = Pick<TenantTxPorts, "ledger"> &
  Partial<Omit<TenantTxPorts, "ledger">> & {
    readonly tenantHandle?: Pick<TenantHandlePort, "resolveByHash">;
  };

export function createInMemoryTenancy(ports: InMemoryTenancySources): InMemoryTenancyPorts {
  const invitationRepo = ports.invitationRepo ?? createInMemoryInvitationRepository();
  const recoveryTokenRepo = ports.recoveryTokenRepo ?? createInMemoryRecoveryTokenRepository();
  const full: TenantTxPorts = {
    revocationRepo: ports.revocationRepo ?? createInMemoryRevocationRepository(),
    consentDecisionRepo: ports.consentDecisionRepo ?? createInMemoryConsentDecisionRepository(),
    recoveryTokenRepo,
    invitationRepo,
    otpRepo: ports.otpRepo ?? createInMemoryOtpVerificationRepository(),
    rightsCaseRepo: ports.rightsCaseRepo ?? createInMemoryRightsCaseRepository(),
    enrollmentRepo: ports.enrollmentRepo ?? createInMemoryEnrollmentRepository(),
    ledger: ports.ledger,
    outbox: ports.outbox ?? createInMemoryOutboxAdapter(),
    tenantCatalog: ports.tenantCatalog ?? createInMemoryTenantCatalogAdapter(),
    idempotency: ports.idempotency ?? createInMemoryIdempotencyAdapter({ ttlMs: LOCAL_ONLY_IN_MEMORY_IDEMPOTENCY_TTL_MS }),
  };
  return {
    uow: createInMemoryUnitOfWork(full),
    tenantResolver: createInMemoryTenantResolver({
      recoveryTokenRepo,
      invitationRepo,
      tenantHandle: ports.tenantHandle,
    }),
  };
}

/** `bag` + `uow` + `tenantResolver` (atajo para armar los puertos de un módulo). */
export function withInMemoryTenancy<B extends InMemoryTenancySources>(bag: B): B & InMemoryTenancyPorts {
  return { ...bag, ...createInMemoryTenancy(bag) };
}
