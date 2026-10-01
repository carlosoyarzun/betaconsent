// Gobierna: src/server/ports/access-log.port.ts, CA-128, DEC-BR-014 rev. 8 §3 X6, rights-case.spec
// INV-RC-04 (ops.access_log append-only, sin PII, no ledger). Suite de contrato compartida
// memoria/Postgres. TEST-CNS-918. Solo datos sinteticos.

import assert from "node:assert/strict";

import { AccessLogValidationError, type AccessLogEntry, type AccessLogPort } from "../../../src/server/ports/access-log.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

export interface AccessLogHarness {
  inTenant<T>(tenantId: string, work: (ports: { readonly accessLog: AccessLogPort }) => Promise<T>): Promise<T>;
}

export type RegisterAccessLogTest = (name: string, body: (h: AccessLogHarness) => Promise<void>) => void;

function entry(tenantId: string, over: Partial<AccessLogEntry> = {}): AccessLogEntry {
  return {
    tenantId,
    actorRef: fixtureUuid("staff-synthetic-01"),
    actorRole: "RIGHTS_OPERATOR",
    action: "RIGHTS_CASE_READ",
    resourceType: "RIGHTS_CASE",
    resourceRef: fixtureUuid("case-918"),
    ...over,
  };
}

export function runAccessLogContract(adapterName: string, register: RegisterAccessLogTest): void {
  const name = (text: string): string => `TEST-CNS-918 AccessLogPort contract (${adapterName}): ${text}`;

  register(name("record + listByTenant en orden, SYNTHETIC; aislamiento por tenant (B no ve lo de A, escribir con tenant ajeno se rechaza)"), async (h) => {
    const a = fixtureUuid("t918-a");
    const b = fixtureUuid("t918-b");
    await h.inTenant(a, async ({ accessLog }) => {
      await accessLog.record(entry(a, { resourceRef: fixtureUuid("c1") }));
      await accessLog.record(entry(a, { actorRef: fixtureUuid("staff-synthetic-03"), actorRole: "APPROVER", resourceRef: fixtureUuid("c2") }));
    });
    const seen = await h.inTenant(a, ({ accessLog }) => accessLog.listByTenant(a));
    assert.deepEqual(seen.map((r) => [r.actorRef, r.actorRole, r.resourceRef]), [
      [fixtureUuid("staff-synthetic-01"), "RIGHTS_OPERATOR", fixtureUuid("c1")],
      [fixtureUuid("staff-synthetic-03"), "APPROVER", fixtureUuid("c2")],
    ]);
    assert.equal(seen[0]?.dataClass, "SYNTHETIC");
    assert.equal(seen[0]?.environment, "LOCAL");
    assert.ok(seen[0]?.accessedAt instanceof Date);

    assert.deepEqual(await h.inTenant(b, ({ accessLog }) => accessLog.listByTenant(b)), []);
    assert.deepEqual(await h.inTenant(b, ({ accessLog }) => accessLog.listByTenant(a)), [], "bajo B no se lee lo de A");
    await assert.rejects(() => h.inTenant(b, ({ accessLog }) => accessLog.record(entry(a))));
    assert.equal((await h.inTenant(a, ({ accessLog }) => accessLog.listByTenant(a))).length, 2, "la escritura ajena no dejo rastro");
  });

  register(name("sin PII: un actorRef/resourceRef con forma de email, espacios o texto libre, o un rol/accion fuera del vocabulario, se rechaza sin escribir"), async (h) => {
    const t = fixtureUuid("t918-pii");
    await h.inTenant(t, async ({ accessLog }) => {
      const bad: Array<Partial<AccessLogEntry>> = [
        { actorRef: "operadora@example.invalid" },
        { actorRef: "Nombre Apellido" },
        { actorRef: "12.345.678-5" }, // RUT
        { actorRef: "Juan Perez" },
        { resourceRef: "12345678-5" }, // RUT
        { resourceRef: "Juan Perez" },
        { resourceRef: "case-1" }, // no es Ref UUIDv4
        { actorRef: "" },
        { resourceRef: "caso de Pedro" },
        { resourceRef: "x".repeat(101) },
        { actorRole: "ADMIN" as never },
        { action: "RIGHTS_CASE_EXPORT" as never },
        { resourceType: "PERSON" as never },
      ];
      for (const over of bad) {
        await assert.rejects(() => accessLog.record(entry(t, over)), (e: unknown) => e instanceof AccessLogValidationError, JSON.stringify(Object.keys(over)));
      }
      assert.deepEqual(await accessLog.listByTenant(t), []);
    });
  });

  register(name("atomicidad: si la unidad de trabajo falla no queda registro; el reintento confirma"), async (h) => {
    const t = fixtureUuid("t918-atom");
    await assert.rejects(() =>
      h.inTenant(t, async ({ accessLog }) => {
        await accessLog.record(entry(t));
        throw new Error("fallo sintetico");
      }),
    );
    assert.deepEqual(await h.inTenant(t, ({ accessLog }) => accessLog.listByTenant(t)), []);
    await h.inTenant(t, ({ accessLog }) => accessLog.record(entry(t)));
    assert.equal((await h.inTenant(t, ({ accessLog }) => accessLog.listByTenant(t))).length, 1);
  });
}
