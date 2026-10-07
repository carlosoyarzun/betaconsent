// Gobierna: invitation.spec GRD-IV-14 (I1 STAFF solo para NOT_INVITED), PC-2 (Carlos 2026-10-02), API-CNS-116, ERR-IV-02.
// TEST-CNS-1086: con cualquier invitacion previa (cualquier estado) I1 desde STAFF falla con el MISMO ERR-IV-02 (uniforme: no
// revela el estado previo). TEST-CNS-1091: el directorio sintetico solo existe en LOCAL.

import test from "node:test";
import assert from "node:assert/strict";

import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { createInMemorySubjectDirectory, SubjectDirectoryEnvironmentError } from "../../../src/infra/adapters/in-memory-subject-directory.adapter.ts";
import { LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG } from "../../../src/server/entrypoints/dev-local-config.ts";
import { createDefaultConsentFlowPorts, createDefaultStaffConsolePorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { staffCreateInvitation } from "../../../src/server/modules/invitation/staff-issuance.ts";
import type { InvitationState } from "../../../src/server/ports/invitation-repository.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY } from "../../helpers/test-ref-keys.ts";

const TENANT = fixtureUuid("t1086");
const CONTEXT = "BETA_2026_01";

test("TEST-CNS-1086 GRD-IV-14: I1 STAFF con invitacion previa en CUALQUIER estado -> ERR-IV-02 identico; sin previa, 201", async () => {
  const states: Array<InvitationState | null> = ["DRAFT", "READY", "SENT", "OPENED", "VERIFIED", "COMPLETED", "DECLINED"];
  const errors = new Set<string>();
  for (const state of states) {
    const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY);
    const staff = createDefaultStaffConsolePorts(ports.invitation, createInMemoryStaffIdentityAdapter([]));
    const subjectRef = fixtureUuid("s1086");
    const participationRef = fixtureUuid("p1086");
    staff.catalog.seedSubject(TENANT, subjectRef);
    staff.catalog.seedParticipation(TENANT, { participationRef, contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });
    const enrollmentRef = fixtureUuid("e1086");
    await staff.issuance.enrollmentRepo.save({ enrollmentRef, tenantId: TENANT, subjectRef, participationRef, state: "ACTIVE" });
    const input = { subjectRef, enrollmentRef, participationRef, contextRef: CONTEXT };
    if (state !== null) {
      await ports.invitation.invitationRepo.save({ invitationRef: fixtureUuid(`i1086-${state}`), tenantId: TENANT, contextRef: CONTEXT, productRef: "LECTORPRO", subjectRef, state });
      await assert.rejects(
        () => staffCreateInvitation({ ...staff.issuance, invitation: { ...ports.invitation, uow: staff.uow } }, TENANT, "INVITER", input),
        (e: unknown) => {
          assert.ok(e instanceof DomainError);
          errors.add(`${e.code}|${e.message}`);
          return e.code === "ERR-IV-02";
        },
        state,
      );
    }
  }
  assert.equal(errors.size, 1, "mismo codigo y mismo mensaje para cualquier estado previo");
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY);
  const staff = createDefaultStaffConsolePorts(ports.invitation, createInMemoryStaffIdentityAdapter([]));
  const subjectRef = fixtureUuid("s1086-free");
  const participationRef = fixtureUuid("p1086");
  staff.catalog.seedSubject(TENANT, subjectRef);
  staff.catalog.seedParticipation(TENANT, { participationRef, contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });
  await staff.issuance.enrollmentRepo.save({ enrollmentRef: fixtureUuid("e1086-free"), tenantId: TENANT, subjectRef, participationRef, state: "ACTIVE" });
  const created = await staffCreateInvitation({ ...staff.issuance, invitation: { ...ports.invitation, uow: staff.uow } }, TENANT, "INVITER", { subjectRef, enrollmentRef: fixtureUuid("e1086-free"), participationRef, contextRef: CONTEXT });
  assert.equal(created.record.state, "DRAFT");
});

test("TEST-CNS-1091 el directorio sintetico (etiquetas/participacion) solo se crea en LOCAL, con clave (tenant, sujeto)", async () => {
  const entry = { tenantId: TENANT, subjectRef: fixtureUuid("s1091"), label: "Alumno de prueba 1", participationRef: null };
  for (const env of ["DEV", "STAGING", "PRODUCTION", "", "local"]) {
    assert.throws(() => createInMemorySubjectDirectory(env, [entry]), SubjectDirectoryEnvironmentError, env);
  }
  const dir = createInMemorySubjectDirectory("LOCAL", [entry]);
  assert.equal((await dir.lookup(TENANT, entry.subjectRef))?.label, "Alumno de prueba 1");
  assert.equal(await dir.lookup(fixtureUuid("otro-tenant"), entry.subjectRef), null, "mismo subjectRef en otro tenant: sin etiqueta");
});
