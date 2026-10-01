// Gobierna: CA-128, DEC-BR-014 rev. 8 §3 X6 (subconjunto IT0 de ADR-011 / S4-16: cadena SHA-256
// por tenant, recomputacion y lista blanca), common.spec.yaml ledgerEnvelope. Suite de contrato
// compartida memoria/Postgres sobre LedgerPort. TEST-CNS-910 y TEST-CNS-911. Solo datos sinteticos.

import assert from "node:assert/strict";

import {
  computeEventHash,
  computePayloadHash,
  LEDGER_GENESIS_HASH,
  verifyLedgerChain,
} from "../../../src/server/modules/common/ledger-chain.ts";
import { LedgerVocabularyViolationError } from "../../../src/server/modules/common/ledger-event-types.ts";
import type { LedgerEventInput } from "../../../src/server/ports/ledger.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";
import type { RegisterContractTest } from "./ledger-outbox-tx.contract.ts";

function event(tenantId: string, aggregateId: string, extra: Partial<LedgerEventInput> = {}): LedgerEventInput {
  return {
    eventType: "REVOCATION_REQUESTED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId,
    actorType: "HUMAN",
    payload: { reasonCode: "SYNTHETIC" },
    expectedSequence: 0,
    ...extra,
  };
}

export function runLedgerChainContract(adapterName: string, register: RegisterContractTest): void {
  const name = (id: string, text: string): string => `${id} Ledger chain contract (${adapterName}): ${text}`;

  register(
    name("TEST-CNS-910", "cadena SHA-256 por tenant: genesis, chainSeq 1..n entre agregados, hashes recomputables, tenants independientes, dedupe no extiende y verifyLedgerChain recomputa"),
    async (h) => {
      const ta = fixtureUuid("t910-a");
      const tb = fixtureUuid("t910-b");
      const agg1 = fixtureUuid("agg910-1");
      const agg2 = fixtureUuid("agg910-2");
      const idemKey = "idem-910";

      const records = await h.inTenant(ta, async ({ ledger }) => {
        const a = await ledger.append(event(ta, agg1, { payload: { z: 1, a: { y: true, b: null } }, idempotencyKey: idemKey }));
        const b = await ledger.append(event(ta, agg2, { actorRole: "UNVERIFIED_BEARER", recordedByRef: fixtureUuid("rec910") }));
        const c = await ledger.append(event(ta, agg1, { eventType: "REVOCATION_CONFIRMED", expectedSequence: 1 }));
        const dup = await ledger.append(event(ta, agg1, { payload: { z: 1, a: { y: true, b: null } }, idempotencyKey: idemKey }));
        return { a, b, c, dup };
      });
      assert.deepEqual([records.a.chainSeq, records.b.chainSeq, records.c.chainSeq], [1, 2, 3]);
      assert.equal(records.a.previousEventHash, LEDGER_GENESIS_HASH);
      assert.equal(records.b.previousEventHash, records.a.eventHash);
      assert.equal(records.c.previousEventHash, records.b.eventHash);
      assert.equal(records.dup.eventHash, records.a.eventHash, "el dedupe devuelve el eslabon existente");
      // El orden de claves del payload no cambia el hash (canonicalizacion determinista).
      assert.equal(records.a.payloadHash, computePayloadHash({ a: { b: null, y: true }, z: 1 }));
      assert.equal(
        records.a.eventHash,
        computeEventHash({
          tenantId: ta,
          chainSeq: 1,
          aggregateType: "Revocation",
          aggregateId: agg1,
          sequence: 1,
          eventType: "REVOCATION_REQUESTED",
          actorType: "HUMAN",
          actorRole: null,
          recordedByRef: null,
          cosignedByRef: null,
          idempotencyKeyHash: (await import("node:crypto")).createHash("sha256").update(idemKey, "utf8").digest("hex"),
          payloadHash: records.a.payloadHash,
          previousEventHash: LEDGER_GENESIS_HASH,
        }),
      );

      // Otro tenant: cadena propia desde el genesis; el de A no se ve alterado.
      const other = await h.inTenant(tb, ({ ledger }) => ledger.append(event(tb, agg1)));
      assert.equal(other.chainSeq, 1);
      assert.equal(other.previousEventHash, LEDGER_GENESIS_HASH);
      assert.notEqual(other.eventHash, records.a.eventHash, "el hash cubre tenantId");

      const reports = await h.inTenant(ta, async ({ ledger }) => ({
        report: await verifyLedgerChain(ledger, ta),
        rows: await ledger.readChain(ta),
        foreign: await ledger.readChain(tb),
      }));
      assert.deepEqual(reports.report, { ok: true, verified: 3 });
      assert.deepEqual(reports.rows.map((r) => r.chainSeq), [1, 2, 3]);
      assert.deepEqual(reports.foreign, [], "bajo la tx de A no se lee la cadena de B (RLS / scope)");
      assert.deepEqual(await h.inTenant(tb, ({ ledger }) => verifyLedgerChain(ledger, tb)), { ok: true, verified: 1 });
      assert.deepEqual(await h.inTenant(fixtureUuid("t910-empty"), (p) => verifyLedgerChain(p.ledger, fixtureUuid("t910-empty"))), { ok: true, verified: 0 });
    },
  );

  register(
    name("TEST-CNS-911", "lista blanca de eventType: un tipo fuera de la lista se rechaza (ERR-RV-13) sin escribir ni avanzar la cadena; los tipos de la spec pasan"),
    async (h) => {
      const t = fixtureUuid("t911");
      const agg = fixtureUuid("agg911");
      await h.inTenant(t, async ({ ledger }) => {
        await ledger.append(event(t, agg));
        for (const bad of ["consent.revoked", "revocation_requested", "FOREIGN_UNIT_EVENT", "", "REVOCATION_REQUESTED "]) {
          await assert.rejects(
            () => ledger.append(event(t, agg, { eventType: bad, expectedSequence: 1 })),
            (e: unknown) => e instanceof LedgerVocabularyViolationError,
            `eventType ${JSON.stringify(bad)}`,
          );
        }
        assert.equal(await ledger.currentSequence(t, agg), 1, "nada escrito por los rechazos");
        const next = await ledger.append(event(t, agg, { eventType: "REVOCATION_VERIFIED", expectedSequence: 1 }));
        assert.equal(next.chainSeq, 2, "la cadena no avanzo con los rechazos");
        assert.deepEqual(await verifyLedgerChain(ledger, t), { ok: true, verified: 2 });
      });
    },
  );
}
