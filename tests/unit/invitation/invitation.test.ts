// Gobierna: specs/state-machines/invitation.spec.yaml I1 (CreateInvitation), I2
// (MarkInvitationReady), I3 (SendInvitation), I4 (OpenInvitation); GRD-CM-02, GRD-CM-05,
// GRD-CM-07, GRD-IV-01, GRD-IV-03, GRD-IV-04, GRD-IV-05, GRD-IV-07, GRD-IV-08.
// TEST-CNS-475..TEST-CNS-482.

import test from "node:test";
import assert from "node:assert/strict";

import {
  createInvitation,
  markInvitationReady,
  openInvitation,
  sendInvitation,
} from "../../../src/server/modules/invitation/invitation.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import type { InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";

function makePorts(): InvitationPorts {
  return {
    invitationRepo: createInMemoryInvitationRepository(),
    eligibility: createInMemoryEligibilityAdapter(),
    ledger: createInMemoryLedgerAdapter(),
  };
}

async function readyInvitation(ports: InvitationPorts, overrides: Partial<{ tenantId: string }> = {}) {
  const tenantId = overrides.tenantId ?? "tenant-1";
  await createInvitation(ports, tenantId, "INVITER", {
    invitationRef: "inv-1",
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef: "test+subject-1@example.invalid",
  });
  return markInvitationReady(ports, tenantId, "INVITER", "inv-1", {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: "test+channel-1@example.invalid",
  });
}

test("TEST-CNS-475: I1 crea Invitation DRAFT y emite INVITATION_CREATED (GRD-CM-05, GRD-CM-07)", async () => {
  const ports = makePorts();
  const created = await createInvitation(ports, "tenant-1", "INVITER", {
    invitationRef: "inv-1",
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef: "test+subject-1@example.invalid",
  });
  assert.equal(created.state, "DRAFT");
  const events = await ports.ledger.listByAggregate("tenant-1", "Invitation", "inv-1");
  assert.equal(events.length, 1);
  assert.equal(events[0]?.eventType, "INVITATION_CREATED");
});

test("TEST-CNS-476: I1 con contexto no elegible (GRD-CM-05) -> ERR-CM-05, sin evento", async () => {
  const ports = makePorts();
  (ports.eligibility as ReturnType<typeof createInMemoryEligibilityAdapter>).setEligible(
    "tenant-1",
    "BETA_2026_01",
    "LECTORPRO",
    false,
  );
  await assert.rejects(
    () =>
      createInvitation(ports, "tenant-1", "INVITER", {
        invitationRef: "inv-1",
        contextRef: "BETA_2026_01",
        productRef: "LECTORPRO",
        subjectRef: "test+subject-1@example.invalid",
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-05",
  );
  assert.equal((await ports.ledger.listByAggregate("tenant-1", "Invitation", "inv-1")).length, 0);
});

test("TEST-CNS-477: I1 con actorRole distinto de INVITER -> ERR-CM-10 (GRD-CM-07)", async () => {
  const ports = makePorts();
  await assert.rejects(
    () =>
      createInvitation(ports, "tenant-1", "DECISION_MAKER", {
        invitationRef: "inv-1",
        contextRef: "BETA_2026_01",
        productRef: "LECTORPRO",
        subjectRef: "test+subject-1@example.invalid",
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-CM-10",
  );
});

test("TEST-CNS-478: segunda I1 no terminal para el mismo (tenant, contexto, sujeto) -> ERR-IV-02 (GRD-IV-01)", async () => {
  const ports = makePorts();
  await createInvitation(ports, "tenant-1", "INVITER", {
    invitationRef: "inv-1",
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef: "test+subject-1@example.invalid",
  });
  await assert.rejects(
    () =>
      createInvitation(ports, "tenant-1", "INVITER", {
        invitationRef: "inv-2",
        contextRef: "BETA_2026_01",
        productRef: "LECTORPRO",
        subjectRef: "test+subject-1@example.invalid",
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-IV-02",
  );
});

test("TEST-CNS-479: I2 sin consentVersion/expiresAt/recipientChannelRef -> ERR-IV-03 (GRD-IV-03)", async () => {
  const ports = makePorts();
  await createInvitation(ports, "tenant-1", "INVITER", {
    invitationRef: "inv-1",
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO",
    subjectRef: "test+subject-1@example.invalid",
  });
  await assert.rejects(
    () =>
      markInvitationReady(ports, "tenant-1", "INVITER", "inv-1", {
        consentVersion: "",
        expiresAt: new Date(Date.now() + 1000),
        recipientChannelRef: "test+channel-1@example.invalid",
      }),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-IV-03",
  );
});

test("TEST-CNS-480: I3 genera un token opaco (solo tokenHash persiste) y transiciona a SENT (GRD-IV-05)", async () => {
  const ports = makePorts();
  await readyInvitation(ports);
  const { record, token } = await sendInvitation(ports, "tenant-1", "INVITER", "inv-1");
  assert.equal(record.state, "SENT");
  assert.ok(record.tokenHash);
  assert.notEqual(record.tokenHash, token);
  const events = await ports.ledger.listByAggregate("tenant-1", "Invitation", "inv-1");
  const sentEvent = events.find((e) => e.eventType === "INVITATION_SENT");
  assert.ok(sentEvent);
  assert.equal(JSON.stringify(sentEvent?.payload).includes(token), false);
});

test("TEST-CNS-481: I4 con token de otro tenant o inexistente -> 404 uniforme ERR-IV-01 (GRD-IV-07)", async () => {
  const ports = makePorts();
  await readyInvitation(ports);
  const { token } = await sendInvitation(ports, "tenant-1", "INVITER", "inv-1");

  await assert.rejects(
    () => openInvitation(ports, "tenant-2", token),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-IV-01",
  );
  await assert.rejects(
    () => openInvitation(ports, "tenant-1", "token-que-no-existe"),
    (err: unknown) => err instanceof DomainError && err.code === "ERR-IV-01",
  );
});

test("TEST-CNS-482: I4 transiciona una sola vez a OPENED; un segundo POST no duplica el evento (GRD-IV-08, INV-IV-04)", async () => {
  const ports = makePorts();
  await readyInvitation(ports);
  const { token } = await sendInvitation(ports, "tenant-1", "INVITER", "inv-1");

  const first = await openInvitation(ports, "tenant-1", token);
  const second = await openInvitation(ports, "tenant-1", token);
  assert.equal(first.state, "OPENED");
  assert.equal(second.state, "OPENED");

  const opened = (await ports.ledger
    .listByAggregate("tenant-1", "Invitation", "inv-1"))
    .filter((e) => e.eventType === "INVITATION_OPENED");
  assert.equal(opened.length, 1);
});
