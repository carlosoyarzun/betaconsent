// Gobierna: API-CNS-116, src/server/ports/staff-roster.port.ts. Registra la suite de contrato de la proyeccion del
// roster (TEST-CNS-1070..1074) contra el adaptador in-memory. El registro contra Postgres (vista 0019) vive en
// tests/integration/postgres/staff-roster.test.ts. Solo datos sinteticos.

import test from "node:test";
import assert from "node:assert/strict";

import { createInMemoryAccessLogAdapter } from "../../../src/infra/adapters/in-memory-access-log.adapter.ts";
import { createInMemoryEnrollmentRepository } from "../../../src/infra/adapters/in-memory-enrollment-repository.adapter.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryStaffRosterReader } from "../../../src/infra/adapters/in-memory-staff-roster.adapter.ts";
import { createInMemoryTenantCatalogAdapter } from "../../../src/infra/adapters/in-memory-tenant-catalog.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { fixtureUuid } from "../uuid-fixture.ts";
import { runStaffRosterContract, type RosterHarness } from "./staff-roster.contract.ts";

function inMemoryHarness(): RosterHarness {
  const ledger = createInMemoryLedgerAdapter();
  const invitationRepo = createInMemoryInvitationRepository();
  const enrollmentRepo = createInMemoryEnrollmentRepository();
  const tenantCatalog = createInMemoryTenantCatalogAdapter();
  const accessLog = createInMemoryAccessLogAdapter();
  const { uow } = createInMemoryTenancy({ ledger, invitationRepo, enrollmentRepo, tenantCatalog, accessLog });
  const reader = createInMemoryStaffRosterReader({ uow, invitations: invitationRepo, enrollments: enrollmentRepo, catalog: tenantCatalog });
  let seq = 0;
  return {
    async seed(scene) {
      for (const subjectRef of scene.subjects) tenantCatalog.seedSubject(scene.tenantId, subjectRef);
      for (const p of scene.participations) {
        tenantCatalog.seedParticipation(scene.tenantId, { participationRef: p.participationRef, contextRef: p.contextRef, productRef: "LECTORPRO", status: "ACTIVE" });
      }
      for (const e of scene.enrollments ?? []) {
        seq += 1;
        await enrollmentRepo.save({ enrollmentRef: fixtureUuid(`enr-${seq}`), tenantId: scene.tenantId, subjectRef: e.subjectRef, participationRef: e.participationRef, state: e.state });
      }
      for (const i of scene.invitations ?? []) {
        seq += 1;
        await invitationRepo.save({
          invitationRef: fixtureUuid(`inv-${seq}`),
          tenantId: scene.tenantId,
          contextRef: i.contextRef,
          productRef: "LECTORPRO",
          subjectRef: i.subjectRef,
          state: i.state,
          ...(i.expiresInMs !== null ? { expiresAt: new Date(Date.now() + i.expiresInMs) } : {}),
        });
      }
    },
    read: (request) =>
      reader.readPage({
        tenantId: request.tenantId,
        principalRef: request.principalRef ?? fixtureUuid("staff-default"),
        actorRole: "TENANT_ADMIN",
        after: request.after ?? null,
        rowLimit: request.rowLimit,
      }),
    async accessLogRows(tenantId) {
      const rows = await accessLog.listByTenant(tenantId);
      return rows.filter((r) => r.action === "STAFF_ROSTER_READ" && r.resourceType === "STAFF_ROSTER").map((r) => ({ actorRef: r.actorRef, resourceRef: r.resourceRef }));
    },
  };
}

runStaffRosterContract("in-memory", (name, body) => {
  test(name, () => body(inMemoryHarness()));
});

test("TEST-CNS-1084 in-memory: si el access log falla, la lectura no devuelve datos (StaffRosterUnavailableError) y no queda fila", async () => {
  const ledger = createInMemoryLedgerAdapter();
  const invitationRepo = createInMemoryInvitationRepository();
  const enrollmentRepo = createInMemoryEnrollmentRepository();
  const tenantCatalog = createInMemoryTenantCatalogAdapter();
  const real = createInMemoryAccessLogAdapter();
  const failing = { ...real, record: async () => { throw new Error("log caido"); } };
  const { uow } = createInMemoryTenancy({ ledger, invitationRepo, enrollmentRepo, tenantCatalog, accessLog: failing });
  const reader = createInMemoryStaffRosterReader({ uow, invitations: invitationRepo, enrollments: enrollmentRepo, catalog: tenantCatalog });
  const tenantId = fixtureUuid("t1084");
  tenantCatalog.seedSubject(tenantId, fixtureUuid("s1084"));
  tenantCatalog.seedParticipation(tenantId, { participationRef: fixtureUuid("p1084"), contextRef: "CTX_A", productRef: "LECTORPRO", status: "ACTIVE" });
  await assert.rejects(
    () => reader.readPage({ tenantId, principalRef: fixtureUuid("staff"), actorRole: "TENANT_ADMIN", after: null, rowLimit: 5 }),
    (e: unknown) => (e as Error).name === "StaffRosterUnavailableError",
  );
  assert.equal((await real.listByTenant(tenantId)).length, 0);
});

// Trazabilidad X8: este archivo ejecuta/agrupa las suites de TEST-CNS-1071, TEST-CNS-1072, TEST-CNS-1073, TEST-CNS-1074 (el texto de cada ID vive en la suite compartida o es fila paraguas de traceability/test-matrix.csv).
