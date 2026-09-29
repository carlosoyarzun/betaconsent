// Gobierna: tenant-context.spec.yaml EN0 (GRD-TC-03, GRD-CM-07), invitation.spec.yaml I1/I2/I3
// (GRD-CM-03/04/05, GRD-IV-01/02/03/11/12), contracts/schemas/ledger-event-payloads.schema.json
// (ENROLLMENT_STATUS_CHANGED, INVITATION_CREATED/READY/SENT), CA-125. Dominio de la API de staff,
// sin HTTP: SYNTHETIC DATA ONLY (refs UUIDv4 vía fixtureUuid, sin PII).
// TEST-CNS-710..TEST-CNS-713 (traceability/test-matrix.csv).

import test from "node:test";
import assert from "node:assert/strict";

import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryEnrollmentRepository } from "../../../src/infra/adapters/in-memory-enrollment-repository.adapter.ts";
import { createInMemoryInvitationLinkChannelSink } from "../../../src/infra/adapters/in-memory-invitation-link-channel-sink.adapter.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryTenantCatalogAdapter } from "../../../src/infra/adapters/in-memory-tenant-catalog.adapter.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY } from "../../../src/server/entrypoints/dev-local-config.ts";
import { openEnrollment } from "../../../src/server/modules/tenant-context/enrollment.ts";
import {
  staffCreateInvitation,
  staffMarkInvitationReady,
  staffSendInvitation,
  type StaffIssuancePorts,
} from "../../../src/server/modules/invitation/staff-issuance.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { validateLedgerEventPayload } from "../../contract/schema-lite.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const TENANT_A = fixtureUuid("tenant-a-710");
const TENANT_B = fixtureUuid("tenant-b-710");
const SUBJECT = fixtureUuid("subject-710");
const PARTICIPATION = fixtureUuid("participation-710");
const CHANNEL = fixtureUuid("channel-710");
const CONTEXT = "BETA_2026_01";

function build(withPolicy = true) {
  const ledger = createInMemoryLedgerAdapter();
  const catalog = createInMemoryTenantCatalogAdapter();
  const enrollmentRepo = createInMemoryEnrollmentRepository();
  const sink = createInMemoryInvitationLinkChannelSink();
  catalog.seedSubject(TENANT_A, SUBJECT);
  catalog.seedParticipation(TENANT_A, { participationRef: PARTICIPATION, contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });
  const issuance: StaffIssuancePorts = {
    invitation: { invitationRepo: createInMemoryInvitationRepository(), eligibility: createInMemoryEligibilityAdapter(), ledger },
    enrollmentRepo,
    tenantCatalog: catalog,
    invitationLinkChannel: sink,
    ...(withPolicy ? { policy: loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY) } : {}),
  };
  return { ledger, catalog, enrollmentRepo, sink, issuance, enrollment: { enrollmentRepo, tenantCatalog: catalog, ledger } };
}

async function expectCode(fn: () => unknown, code: string): Promise<void> {
  await assert.rejects(async () => fn(), (err: unknown) => err instanceof DomainError && err.code === code, `se esperaba ${code}`);
}

test("TEST-CNS-710: EN0 abre el Enrollment ACTIVE con ref UUIDv4, evento válido contra el schema, un solo ACTIVE por (sujeto, participación) y sujeto ajeno = ERR-CM-01", async () => {
  const { ledger, enrollment } = build();
  const { record, sequence } = await openEnrollment(enrollment, TENANT_A, "INVITER", { subjectRef: SUBJECT, participationRef: PARTICIPATION });
  assert.equal(record.state, "ACTIVE");
  assert.equal(sequence, 1);
  const events = await ledger.listByAggregate(TENANT_A, "Enrollment", record.enrollmentRef);
  assert.equal(events.length, 1);
  assert.equal(events[0]!.eventType, "ENROLLMENT_STATUS_CHANGED");
  assert.equal(events[0]!.actorType, "HUMAN");
  assert.equal(events[0]!.actorRole, "INVITER");
  const verdict = validateLedgerEventPayload("ENROLLMENT_STATUS_CHANGED", events[0]!.payload);
  assert.ok(verdict.ok, verdict.errors.join("\n"));

  await expectCode(() => openEnrollment(enrollment, TENANT_A, "INVITER", { subjectRef: SUBJECT, participationRef: PARTICIPATION }), "ERR-TC-03");
  // El mismo sujeto/participación desde OTRO tenant es indistinguible de uno inexistente.
  await expectCode(() => openEnrollment(enrollment, TENANT_B, "INVITER", { subjectRef: SUBJECT, participationRef: PARTICIPATION }), "ERR-CM-01");
  // GRD-CM-07: solo el rol INVITER (TENANT_ADMIN en la consola) abre Enrollments.
  await expectCode(() => openEnrollment(enrollment, TENANT_A, "RIGHTS_OPERATOR", { subjectRef: SUBJECT, participationRef: PARTICIPATION }), "ERR-CM-10");
});

test("TEST-CNS-711: I1 -> I2 -> I3 emiten INVITATION_CREATED/READY/SENT válidos contra el schema, sequence 1..3, tokenHash persistido y el token solo llega al sink", async () => {
  const { ledger, enrollment, issuance, sink } = build();
  const en = (await openEnrollment(enrollment, TENANT_A, "INVITER", { subjectRef: SUBJECT, participationRef: PARTICIPATION })).record;

  const created = await staffCreateInvitation(issuance, TENANT_A, "INVITER", {
    subjectRef: SUBJECT,
    enrollmentRef: en.enrollmentRef,
    participationRef: PARTICIPATION,
    contextRef: CONTEXT,
  });
  const ref = created.record.invitationRef;
  assert.equal(created.record.state, "DRAFT");
  assert.equal(created.record.productRef, "LECTORPRO", "productRef sale de la SchoolParticipation, no del body");
  assert.equal(created.sequence, 1);

  const ready = await staffMarkInvitationReady(issuance, TENANT_A, "INVITER", ref, {
    consentVersion: "v1-test",
    recipientBinding: "RECIPIENT_CHANNEL",
    recipientChannelRef: CHANNEL,
  });
  assert.equal(ready.sequence, 2);
  assert.ok(ready.record.expiresAt && ready.record.expiresAt.getTime() > Date.now(), "expiresAt lo fija el servidor");

  const sent = await staffSendInvitation(issuance, TENANT_A, "INVITER", ref);
  assert.equal(sent.sequence, 3);
  assert.equal(sent.record.state, "SENT");
  assert.match(sent.record.tokenHash ?? "", /^[0-9a-f]{64}$/);

  const events = await ledger.listByAggregate(TENANT_A, "Invitation", ref);
  assert.deepEqual(events.map((e) => e.eventType), ["INVITATION_CREATED", "INVITATION_READY", "INVITATION_SENT"]);
  for (const event of events) {
    const verdict = validateLedgerEventPayload(event.eventType, event.payload);
    assert.ok(verdict.ok, `${event.eventType}: ${verdict.errors.join("\n")}`);
  }
  assert.equal(sink.sent.length, 1);
  const message = sink.sent[0]!;
  assert.match(message.invitationPath, /^\/i\/[0-9a-f]{64}$/);
  const token = message.invitationPath.slice("/i/".length);
  assert.equal(JSON.stringify(events).includes(token), false, "el token no aparece en ningún evento del ledger");
  assert.equal(JSON.stringify(sent.record).includes(token), false, "el token no persiste en el registro");
});

test("TEST-CNS-712: I1 falla cerrado: refs de otro tenant o inexistentes (ERR-CM-01), Guard P (ERR-CM-03), Guard E (ERR-CM-04), reemisión sin P-11 (ERR-IV-07) y segunda invitación no terminal (ERR-IV-02)", async () => {
  const { enrollment, enrollmentRepo, catalog, issuance } = build();
  const en = (await openEnrollment(enrollment, TENANT_A, "INVITER", { subjectRef: SUBJECT, participationRef: PARTICIPATION })).record;
  const input = { subjectRef: SUBJECT, enrollmentRef: en.enrollmentRef, participationRef: PARTICIPATION, contextRef: CONTEXT };

  await expectCode(() => staffCreateInvitation(issuance, TENANT_B, "INVITER", input), "ERR-CM-01"); // GRD-IV-02: enrollment de otro tenant
  await expectCode(() => staffCreateInvitation(issuance, TENANT_A, "INVITER", { ...input, enrollmentRef: fixtureUuid("nope-712") }), "ERR-CM-01");
  await expectCode(() => staffCreateInvitation(issuance, TENANT_A, "INVITER", { ...input, subjectRef: fixtureUuid("otro-712") }), "ERR-CM-01");
  await expectCode(() => staffCreateInvitation(issuance, TENANT_A, "RIGHTS_OPERATOR", input), "ERR-CM-10");
  await expectCode(() => staffCreateInvitation(issuance, TENANT_A, "INVITER", { ...input, contextRef: "OTHER_CONTEXT" }), "ERR-CM-03");
  await expectCode(() => staffCreateInvitation(issuance, TENANT_A, "INVITER", { ...input, reissueOfRef: fixtureUuid("reissue-712") }), "ERR-IV-07");

  catalog.seedParticipation(TENANT_A, { participationRef: PARTICIPATION, contextRef: CONTEXT, productRef: "LECTORPRO", status: "SUSPENDED" });
  await expectCode(() => staffCreateInvitation(issuance, TENANT_A, "INVITER", input), "ERR-CM-03");
  catalog.seedParticipation(TENANT_A, { participationRef: PARTICIPATION, contextRef: CONTEXT, productRef: "LECTORPRO", status: "ACTIVE" });

  await staffCreateInvitation(issuance, TENANT_A, "INVITER", input);
  await expectCode(() => staffCreateInvitation(issuance, TENANT_A, "INVITER", input), "ERR-IV-02"); // GRD-IV-01

  await enrollmentRepo.save({ ...en, state: "CLOSED" });
  await expectCode(() => staffCreateInvitation(issuance, TENANT_A, "INVITER", input), "ERR-CM-04");
});

test("TEST-CNS-713: sin política P-10/deliveryChannel I2 e I3 fallan cerrado (ERR-CM-12) sin cambiar estado; UNBOUND no admite recipientChannelRef y RECIPIENT_CHANNEL sí lo exige (GRD-IV-03)", async () => {
  const closed = build(false);
  const en = (await openEnrollment(closed.enrollment, TENANT_A, "INVITER", { subjectRef: SUBJECT, participationRef: PARTICIPATION })).record;
  const created = await staffCreateInvitation(closed.issuance, TENANT_A, "INVITER", {
    subjectRef: SUBJECT,
    enrollmentRef: en.enrollmentRef,
    participationRef: PARTICIPATION,
    contextRef: CONTEXT,
  });
  const ref = created.record.invitationRef;
  await expectCode(
    () => staffMarkInvitationReady(closed.issuance, TENANT_A, "INVITER", ref, { consentVersion: "v1", recipientBinding: "UNBOUND" }),
    "ERR-CM-12",
  );
  await expectCode(() => staffSendInvitation(closed.issuance, TENANT_A, "INVITER", ref), "ERR-CM-12");
  assert.equal((await closed.issuance.invitation.invitationRepo.findByRef(TENANT_A, ref))?.state, "DRAFT");
  assert.equal(closed.sink.sent.length, 0);

  const open = build(true);
  const en2 = (await openEnrollment(open.enrollment, TENANT_A, "INVITER", { subjectRef: SUBJECT, participationRef: PARTICIPATION })).record;
  const ref2 = (await staffCreateInvitation(open.issuance, TENANT_A, "INVITER", {
    subjectRef: SUBJECT,
    enrollmentRef: en2.enrollmentRef,
    participationRef: PARTICIPATION,
    contextRef: CONTEXT,
  })).record.invitationRef;
  await expectCode(
    () => staffMarkInvitationReady(open.issuance, TENANT_A, "INVITER", ref2, { consentVersion: "v1", recipientBinding: "UNBOUND", recipientChannelRef: CHANNEL }),
    "ERR-IV-03",
  );
  await expectCode(
    () => staffMarkInvitationReady(open.issuance, TENANT_A, "INVITER", ref2, { consentVersion: "v1", recipientBinding: "RECIPIENT_CHANNEL" }),
    "ERR-IV-03",
  );
  const ready = await staffMarkInvitationReady(open.issuance, TENANT_A, "INVITER", ref2, { consentVersion: "v1", recipientBinding: "UNBOUND" });
  assert.equal(ready.record.recipientBinding, "UNBOUND");
  assert.equal(ready.record.recipientChannelRef, undefined);
  const readyEvent = (await open.ledger.listByAggregate(TENANT_A, "Invitation", ref2)).find((e) => e.eventType === "INVITATION_READY")!;
  assert.ok(validateLedgerEventPayload("INVITATION_READY", readyEvent.payload).ok);
  assert.equal((readyEvent.payload as { recipientBinding: string }).recipientBinding, "UNBOUND");
});
