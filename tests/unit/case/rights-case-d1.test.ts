// Gobierna: ADR-010 PR-5b, decision D1 de Carlos (2026-10-13): el dominio sigue al spec en GRD-RC-09 (cierre solo tras R4 APPLIED o R8) y en
// RC3 solo desde CONTACTING (rights-case.spec.yaml RC3/RC3a, RC4/RC5/RC6). TEST-CNS-1389 (in-memory). SYNTHETIC ONLY.

import assert from "node:assert/strict";
import test from "node:test";

import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../src/infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { closeCase, expressRevocationIntentInCase, type RightsCasePorts } from "../../../src/server/modules/rights-case/rights-case.ts";
import type { RevocationStatus } from "../../../src/server/ports/revocation-repository.port.ts";
import type { RightsCaseStatus } from "../../../src/server/ports/rights-case-repository.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const T = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
const CHAIN = fixtureUuid("chain-1389");
const DEC = fixtureUuid("dec-1389");
const CASE = fixtureUuid("case-1389");

async function build(status: RightsCaseStatus, revocationRef?: string): Promise<RightsCasePorts> {
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  await rightsCaseRepo.save({ caseRef: CASE, tenantId: T, chainRef: CHAIN, revokedDecisionRef: DEC, status, ...(revocationRef ? { revocationRef } : {}) });
  return {
    tenantHandle: createInMemoryTenantHandleAdapter([{ handle: "h-1389", tenantId: T, chainRef: CHAIN, revokedDecisionRef: DEC }]),
    rightsCaseRepo,
    revocationRepo,
    ledger,
    uow: createInMemoryTenancy({ ledger, rightsCaseRepo, revocationRepo }).uow,
  };
}

const seedRevocation = (ports: RightsCasePorts, status: RevocationStatus, over: { chainRef?: string; reasonCode?: "WITHDRAWN_BY_REQUESTER"; ref?: string } = {}) =>
  ports.revocationRepo.save({
    revocationRef: over.ref ?? fixtureUuid("rev-1389"),
    tenantId: T,
    chainRef: (over.chainRef ?? CHAIN) as never,
    revokedDecisionRef: DEC,
    status,
    ...(over.reasonCode ? { reasonCode: over.reasonCode } : {}),
  });

const rejectsWith = (run: () => Promise<unknown>, code: string) => assert.rejects(run, (e: unknown) => e instanceof DomainError && e.code === code, code);

test("TEST-CNS-1389: GRD-RC-09 en el dominio: RESOLVED solo con la Revocation del ciclo en APPLIED o posterior; WITHDRAWN solo con FAILED WITHDRAWN_BY_REQUESTER; si no, ERR-RC-03 y el caso sigue abierto", async () => {
  // Sin Revocation: ni RESOLVED ni WITHDRAWN.
  for (const outcome of ["RESOLVED", "WITHDRAWN"] as const) {
    const ports = await build("CONTACTING");
    await rejectsWith(() => closeCase(ports, T, CASE, outcome), "ERR-RC-03");
    assert.equal((await ports.rightsCaseRepo.findByRef(T, CASE))?.status, "CONTACTING");
    assert.equal((await ports.ledger.listByAggregate(T, "RightsCase", CASE)).length, 0, "sin evento");
  }
  // Revocation antes de APPLIED, de otra cadena o FAILED sin retiro: no cierra como RESOLVED.
  for (const status of ["REQUESTED", "VERIFIED", "CONFIRMED", "FAILED"] as const) {
    const ports = await build("CONTACTING");
    await seedRevocation(ports, status);
    await rejectsWith(() => closeCase(ports, T, CASE, "RESOLVED"), "ERR-RC-03");
  }
  {
    const ports = await build("CONTACTING");
    await seedRevocation(ports, "APPLIED", { chainRef: fixtureUuid("otra-cadena") });
    await rejectsWith(() => closeCase(ports, T, CASE, "RESOLVED"), "ERR-RC-03");
  }
  // APPLIED o posterior cierra como RESOLVED (RC5 desde CONTACTING, RC4 desde IN_VERIFICATION).
  for (const status of ["APPLIED", "DOWNSTREAM_PENDING", "DELIVERED", "COMPLETED"] as const) {
    const ports = await build("CONTACTING");
    await seedRevocation(ports, status);
    assert.equal((await closeCase(ports, T, CASE, "RESOLVED")).status, "RESOLVED", status);
  }
  {
    const ports = await build("IN_VERIFICATION", fixtureUuid("rev-1389"));
    await seedRevocation(ports, "APPLIED");
    assert.equal((await closeCase(ports, T, CASE, "RESOLVED")).status, "RESOLVED");
  }
  // WITHDRAWN: solo FAILED con WITHDRAWN_BY_REQUESTER; una APPLIED no sirve.
  {
    const ports = await build("CONTACTING");
    await seedRevocation(ports, "APPLIED");
    await rejectsWith(() => closeCase(ports, T, CASE, "WITHDRAWN"), "ERR-RC-03");
    const ok = await build("CONTACTING");
    await seedRevocation(ok, "FAILED", { reasonCode: "WITHDRAWN_BY_REQUESTER" });
    assert.equal((await closeCase(ok, T, CASE, "WITHDRAWN")).status, "WITHDRAWN");
  }
  // Con la Revocation adjunta al caso, solo esa cuenta (otra APPLIED de la misma decision no cierra).
  {
    const ports = await build("IN_VERIFICATION", fixtureUuid("rev-adjunta"));
    await seedRevocation(ports, "REQUESTED", { ref: fixtureUuid("rev-adjunta") });
    await seedRevocation(ports, "APPLIED", { ref: fixtureUuid("rev-otra") });
    await rejectsWith(() => closeCase(ports, T, CASE, "RESOLVED"), "ERR-RC-03");
  }
});

test("TEST-CNS-1389: RC3 solo desde CONTACTING (y R12 solo sobre un caso IN_VERIFICATION con su Revocation); desde OPEN o terminal, ERR-CM-06 sin efecto", async () => {
  for (const status of ["OPEN", "IN_VERIFICATION", "RESOLVED", "WITHDRAWN"] as const) {
    const ports = await build(status); // sin revocationRef: RC3
    await rejectsWith(() => expressRevocationIntentInCase(ports, "h-1389"), status === "RESOLVED" || status === "WITHDRAWN" ? "ERR-RC-09" : "ERR-CM-06");
    assert.equal((await ports.revocationRepo.findByCase(T, CASE)), null, `${status}: sin Revocation creada`);
  }
  {
    const ports = await build("CONTACTING", fixtureUuid("rev-x")); // R12 con el caso aun CONTACTING: no es el estado del adjunto
    await rejectsWith(() => expressRevocationIntentInCase(ports, "h-1389"), "ERR-CM-06");
  }
  const ok = await build("CONTACTING");
  const result = await expressRevocationIntentInCase(ok, "h-1389");
  assert.equal(result.rightsCase.status, "IN_VERIFICATION");
});
