// Gobierna: ADR-010 rev. 5 §4.2.c (conciliacion; exit code != 0 y log sin PII), §10 fila 6e, G-9, INV-DBR-08; specs/ledger-derivation.spec.yaml (oraculo: pares ledgerWriter 19 / transitionOwner 14).
// TEST-CNS-1600 (particion de pares), TEST-CNS-1601 (ledger y estado coherentes: sin divergencias), TEST-CNS-1602 (cadena rota: payload, hash, previous_hash),
// TEST-CNS-1603 (huecos: chain_seq y sequence por agregado), TEST-CNS-1604 (par fuera de la particion), TEST-CNS-1605 (estado <-> ledger en ambos sentidos: CANCELLED, REVOKED, fila sin evento, evento sin fila),
// TEST-CNS-1606 (salida sin PII y exit codes). Funcion pura: sin Postgres. SYNTHETIC ONLY.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { computeEventHash, computePayloadHash, LEDGER_GENESIS_HASH } from "../../../src/server/modules/common/ledger-chain.ts";
import { LEDGER_DERIVATION_EDGES } from "../../../src/server/modules/common/ledger-derivation.ts";
import {
  LEDGER_WRITER_PAIRS,
  reconcileTenant,
  summarizeReconciliation,
  TRANSITION_OWNER_PAIRS,
} from "../../../src/server/modules/integrity/ledger-reconciliation.ts";
import type { ReconciledEvent, TenantReconciliationInput } from "../../../src/server/modules/integrity/ledger-reconciliation.ts";
import { exitCodeFor, formatReport, MAX_LOGGED_DIVERGENCES, RECONCILER_EXIT } from "../../../src/server/entrypoints/reconciler/reconciler-process.ts";

const T = "00000000-0000-4000-8000-0000000000a1";
const SPEC = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "specs", "ledger-derivation.spec.yaml");

interface Spec { type: string; id: string; seq: number; payload?: Record<string, unknown> }

/** Construye una cadena VALIDA (hashes reales con ledger-chain.ts, la misma canonicalizacion que escriben las funciones de la base). */
function chain(tenantId: string, specs: readonly Spec[]): ReconciledEvent[] {
  const out: ReconciledEvent[] = [];
  let prev = LEDGER_GENESIS_HASH;
  specs.forEach((s, i) => {
    const [aggregateType, eventType] = s.type.split(":") as [string, string];
    const payload = s.payload ?? { ref: s.id };
    const base = {
      tenantId, chainSeq: i + 1, aggregateType, aggregateId: s.id, sequence: s.seq, eventType, actorType: "HUMAN", actorRole: "INVITER", recordedByRef: null, cosignedByRef: null,
      idempotencyKeyHash: null, occurredAt: `2030-01-01T00:00:${String(i).padStart(2, "0")}.000000Z`, environment: "LOCAL", payloadHash: computePayloadHash(payload), previousEventHash: prev,
    };
    const eventHash = computeEventHash(base);
    out.push({ ...base, payload, eventHash });
    prev = eventHash;
  });
  return out;
}

const INV_PATH = ["INVITATION_CREATED", "INVITATION_READY", "INVITATION_SENT", "INVITATION_OPENED", "INVITATION_VERIFIED"];
const invEvents = (id: string, types: readonly string[]): Spec[] => types.map((t, i) => ({ type: `Invitation:${t}`, id, seq: i + 1 }));
const input = (events: ReconciledEvent[], invitations: Array<[string, string]> = [], decisions: Array<[string, string]> = []): TenantReconciliationInput => ({
  tenantId: T,
  events,
  invitations: invitations.map(([invitationRef, state]) => ({ tenantId: T, invitationRef, state })),
  decisions: decisions.map(([consentId, state]) => ({ tenantId: T, consentId, state })),
});
const kinds = (r: readonly { kind: string; detail?: string }[]): string[] => r.map((d) => (d.detail === undefined ? d.kind : `${d.kind}:${d.detail}`));

test("TEST-CNS-1600: los pares de ledger_writer (19) y transition_owner (14) coinciden con la spec, son disjuntos y cubren toda emision de la tabla OLD->NEW", () => {
  const spec = readFileSync(SPEC, "utf-8");
  assert.match(spec, /ledgerWriter: 19/);
  assert.match(spec, /transitionOwner: 14/);
  assert.equal(LEDGER_WRITER_PAIRS.size, 19);
  assert.equal(TRANSITION_OWNER_PAIRS.size, 14);
  for (const p of LEDGER_WRITER_PAIRS) assert.ok(!TRANSITION_OWNER_PAIRS.has(p), `${p} solapa`);
  for (const e of LEDGER_DERIVATION_EDGES) {
    if (e.emitter !== "ledger_writer") continue;
    for (const pair of e.emits) assert.ok(pair.includes("<stepKind>") || LEDGER_WRITER_PAIRS.has(pair), `${e.id}: ${pair} fuera de ledger_writer`);
  }
});

test("TEST-CNS-1601: ledger y estado coherentes (Invitation hasta COMPLETED, ConsentDecision GRANTED y REVOKED, I9 CANCELLED) no producen divergencias", () => {
  const events = chain(T, [
    ...invEvents("inv-ok", [...INV_PATH, "INVITATION_COMPLETED"]),
    { type: "ConsentDecision:CONSENT_VERSION_VIEWED", id: "dec-ok", seq: 1 },
    { type: "ConsentDecision:PURPOSE_DECISION_RECORDED", id: "dec-ok", seq: 2 },
    { type: "ConsentDecision:CONSENT_GRANTED", id: "dec-ok", seq: 3 },
    { type: "ConsentDecision:RECEIPT_CREATED", id: "dec-ok", seq: 4 },
    { type: "ConsentDecision:PURPOSE_DECISION_RECORDED", id: "dec-rev", seq: 1 },
    { type: "ConsentDecision:CONSENT_GRANTED", id: "dec-rev", seq: 2 },
    { type: "ConsentDecision:RECEIPT_CREATED", id: "dec-rev", seq: 3 },
    { type: "Revocation:CONSENT_REVOKED", id: "rev-1", seq: 1, payload: { revocationRef: "rev-1", revokedDecisionRef: "dec-rev" } },
    ...invEvents("inv-can", [...INV_PATH, "INVITATION_CANCELLED"]),
    { type: "ConsentDecision:CONSENT_VERSION_VIEWED", id: "dec-pend", seq: 1 },
  ]);
  const r = reconcileTenant(input(events, [["inv-ok", "COMPLETED"], ["inv-can", "CANCELLED"]], [["dec-ok", "GRANTED"], ["dec-rev", "REVOKED"], ["dec-pend", "PENDING"]]));
  assert.deepEqual(r, []);
  assert.equal(summarizeReconciliation([input(events, [["inv-ok", "COMPLETED"], ["inv-can", "CANCELLED"]], [["dec-ok", "GRANTED"], ["dec-rev", "REVOKED"], ["dec-pend", "PENDING"]])]).ok, true);
});

test("TEST-CNS-1602: detecta cadena rota: payload mutado, eventHash mutado y previous_hash roto (primer eslabon roto, con motivo)", () => {
  const good = chain(T, invEvents("inv-1", INV_PATH.slice(0, 3)));
  const tamperedPayload = good.map((e, i) => (i === 1 ? { ...e, payload: { ref: "otro" } } : e));
  assert.deepEqual(kinds(reconcileTenant(input(tamperedPayload, [["inv-1", "SENT"]]))), ["CHAIN_BROKEN:PAYLOAD_HASH_MISMATCH"]);
  const tamperedHash = good.map((e, i) => (i === 2 ? { ...e, eventHash: "f".repeat(64) } : e));
  assert.deepEqual(kinds(reconcileTenant(input(tamperedHash, [["inv-1", "SENT"]]))), ["CHAIN_BROKEN:EVENT_HASH_MISMATCH"]);
  const tamperedEnvelope = good.map((e, i) => (i === 0 ? { ...e, actorRole: "PLATFORM_ADMIN" } : e));
  assert.deepEqual(kinds(reconcileTenant(input(tamperedEnvelope, [["inv-1", "SENT"]]))), ["CHAIN_BROKEN:EVENT_HASH_MISMATCH"]);
  const brokenLink = good.map((e, i) => (i === 1 ? { ...e, previousEventHash: "e".repeat(64) } : e));
  assert.deepEqual(kinds(reconcileTenant(input(brokenLink, [["inv-1", "SENT"]]))), ["CHAIN_BROKEN:PREVIOUS_HASH_MISMATCH"]);
  const r = reconcileTenant(input(tamperedPayload, [["inv-1", "SENT"]]));
  assert.equal(r[0]?.chainSeq, 2);
});

test("TEST-CNS-1603: detecta huecos: chain_seq de la cadena (fila borrada) y sequence por agregado; un evento sin eslabon posterior al inicio evade el verificador", () => {
  const good = chain(T, invEvents("inv-1", INV_PATH.slice(0, 4)));
  const withoutMiddle = good.filter((_, i) => i !== 1);
  const r = kinds(reconcileTenant(input(withoutMiddle, [["inv-1", "OPENED"]])));
  assert.ok(r.includes("CHAIN_BROKEN:CHAIN_SEQ_GAP"), r.join(","));
  assert.ok(r.includes("AGGREGATE_SEQUENCE_GAP"), r.join(","));
  assert.ok(r.includes("STATE_EVENT_MISMATCH:MISSING:INVITATION_READY"), r.join(","));
  const unchained: ReconciledEvent = { ...good[3]!, chainSeq: null, payloadHash: "", previousEventHash: "", eventHash: "", sequence: 5, occurredAt: "2031-01-01T00:00:00.000000Z" };
  const u = kinds(reconcileTenant(input([...good, unchained], [["inv-1", "OPENED"]])));
  assert.ok(u.includes("UNCHAINED_EVENT:INVITATION_OPENED"), u.join(","));
  const legacy: ReconciledEvent = { ...unchained, occurredAt: "2020-01-01T00:00:00.000000Z", sequence: 5 };
  assert.ok(!kinds(reconcileTenant(input([...good, legacy], [["inv-1", "OPENED"]]))).some((k) => k.startsWith("UNCHAINED_EVENT")), "el legado previo a la cadena no cuenta");
});

test("TEST-CNS-1604: un par Agregado:EVENTO fuera de la particion (ni ledger_writer ni transition_owner) es una divergencia, aunque la cadena sea valida", () => {
  const events = chain(T, [
    ...invEvents("inv-1", INV_PATH.slice(0, 1)),
    { type: "Invitation:INVITATION_TOKEN_ROTATED", id: "inv-1", seq: 2 }, // evento valido en la lista blanca de la base, sin productor ni par
    { type: "Tenant:TENANT_STATUS_CHANGED", id: "tenant-x", seq: 1 },
  ]);
  const r = reconcileTenant(input(events, [["inv-1", "DRAFT"]]));
  assert.ok(kinds(r).includes("PAIR_OUTSIDE_PARTITION:INVITATION_TOKEN_ROTATED"));
  assert.ok(kinds(r).includes("PAIR_OUTSIDE_PARTITION:TENANT_STATUS_CHANGED"));
  assert.ok(!r.some((d) => d.kind === "CHAIN_BROKEN"));
});

test("TEST-CNS-1605: estado <-> ledger en ambos sentidos: CANCELLED <-> INVITATION_CANCELLED, REVOKED <-> CONSENT_REVOKED, fila sin evento y evento sin fila", () => {
  // CANCELLED sin evento / evento sin CANCELLED.
  let r = kinds(reconcileTenant(input(chain(T, invEvents("i1", INV_PATH.slice(0, 2))), [["i1", "CANCELLED"]])));
  assert.deepEqual(r, ["STATE_EVENT_MISMATCH:MISSING:INVITATION_CANCELLED"]);
  r = kinds(reconcileTenant(input(chain(T, invEvents("i2", [...INV_PATH.slice(0, 2), "INVITATION_CANCELLED"])), [["i2", "READY"]])));
  assert.deepEqual(r, ["STATE_EVENT_MISMATCH:UNEXPECTED:INVITATION_CANCELLED"]);
  // Estado adelantado respecto del ledger y ledger adelantado respecto del estado.
  r = kinds(reconcileTenant(input(chain(T, invEvents("i3", INV_PATH.slice(0, 3))), [["i3", "OPENED"]])));
  assert.deepEqual(r, ["STATE_EVENT_MISMATCH:MISSING:INVITATION_OPENED"]);
  r = kinds(reconcileTenant(input(chain(T, invEvents("i4", INV_PATH.slice(0, 4))), [["i4", "SENT"]])));
  assert.deepEqual(r, ["STATE_EVENT_MISMATCH:UNEXPECTED:INVITATION_OPENED"]);
  // Fila sin evento y evento sin fila (Invitation y ConsentDecision).
  r = kinds(reconcileTenant(input(chain(T, invEvents("i5", INV_PATH.slice(0, 1))), [["i5", "DRAFT"], ["i-sin-evento", "DRAFT"]])));
  assert.deepEqual(r, ["ROW_WITHOUT_EVENT:DRAFT"]);
  r = kinds(reconcileTenant(input(chain(T, invEvents("i-huerfano", INV_PATH.slice(0, 1))), [])));
  assert.deepEqual(r, ["EVENT_WITHOUT_ROW"]);
  const granted = [
    { type: "ConsentDecision:PURPOSE_DECISION_RECORDED", id: "d1", seq: 1 },
    { type: "ConsentDecision:CONSENT_GRANTED", id: "d1", seq: 2 },
    { type: "ConsentDecision:RECEIPT_CREATED", id: "d1", seq: 3 },
  ];
  assert.deepEqual(kinds(reconcileTenant(input(chain(T, granted), [], []))), ["EVENT_WITHOUT_ROW"]);
  // REVOKED sin CONSENT_REVOKED; CONSENT_REVOKED con la decision aun GRANTED; CONSENT_REVOKED de una decision inexistente.
  assert.deepEqual(kinds(reconcileTenant(input(chain(T, granted), [], [["d1", "REVOKED"]]))), ["STATE_EVENT_MISMATCH:MISSING:CONSENT_REVOKED"]);
  const revoked = chain(T, [...granted, { type: "Revocation:CONSENT_REVOKED", id: "r1", seq: 1, payload: { revocationRef: "r1", revokedDecisionRef: "d1" } }]);
  assert.deepEqual(kinds(reconcileTenant(input(revoked, [], [["d1", "GRANTED"]]))), ["STATE_EVENT_MISMATCH:UNEXPECTED:CONSENT_REVOKED"]);
  assert.deepEqual(kinds(reconcileTenant(input(revoked, [], [["d1", "REVOKED"]]))), []);
  const ghost = chain(T, [{ type: "Revocation:CONSENT_REVOKED", id: "r2", seq: 1, payload: { revocationRef: "r2", revokedDecisionRef: "d-fantasma" } }]);
  assert.deepEqual(kinds(reconcileTenant(input(ghost, [], []))), ["EVENT_WITHOUT_ROW:CONSENT_REVOKED"]);
  // Valores distintos: GRANTED con CONSENT_DECLINED; DECLINED sin recibo; PENDING con evento terminal.
  const mixed = chain(T, [
    { type: "ConsentDecision:PURPOSE_DECISION_RECORDED", id: "d2", seq: 1 },
    { type: "ConsentDecision:CONSENT_DECLINED", id: "d2", seq: 2 },
    { type: "ConsentDecision:RECEIPT_CREATED", id: "d2", seq: 3 },
  ]);
  assert.deepEqual(kinds(reconcileTenant(input(mixed, [], [["d2", "GRANTED"]]))), ["STATE_EVENT_MISMATCH:MISSING:CONSENT_GRANTED", "STATE_EVENT_MISMATCH:UNEXPECTED:CONSENT_DECLINED"]);
  assert.deepEqual(kinds(reconcileTenant(input(mixed, [], [["d2", "PENDING"]]))), [
    "STATE_EVENT_MISMATCH:UNEXPECTED:CONSENT_DECLINED", "STATE_EVENT_MISMATCH:UNEXPECTED:PURPOSE_DECISION_RECORDED", "STATE_EVENT_MISMATCH:UNEXPECTED:RECEIPT_CREATED",
  ]);
});

test("TEST-CNS-1606: la salida no contiene PII (ni payloads ni hashes), enmascara ids con forma de texto libre, acota las lineas y el exit code es 0/2", () => {
  const events = chain(T, [
    { type: "Invitation:INVITATION_CREATED", id: "inv-1", seq: 1, payload: { subjectRef: "PII-ALUMNA-NOMBRE", email: "padre@example.invalid" } },
    { type: "Invitation:INVITATION_READY", id: "inv-1", seq: 2 },
  ]);
  const tampered = events.map((e, i) => (i === 0 ? { ...e, payload: { subjectRef: "PII-OTRO", email: "otro@example.invalid" } } : e));
  const weird: TenantReconciliationInput = { ...input(tampered, [["inv-1", "READY"], ["correo@ejemplo.cl", "DRAFT"]]) };
  const report = summarizeReconciliation([weird]);
  const text = formatReport(report).join("\n");
  assert.equal(report.ok, false);
  assert.equal(exitCodeFor(report), RECONCILER_EXIT.DIVERGENCE);
  assert.match(text, /^reconciler_run ok=false tenants=1 events=2 divergences=\d+ kinds=/);
  assert.match(text, /kind=CHAIN_BROKEN tenant=00000000-0000-4000-8000-0000000000a1 .*detail=PAYLOAD_HASH_MISMATCH chainSeq=1/);
  for (const secret of ["PII-ALUMNA", "PII-OTRO", "example.invalid", "correo@ejemplo.cl", events[0]!.eventHash, events[0]!.payloadHash]) assert.ok(!text.includes(secret), `la salida filtra ${secret.slice(0, 8)}`);
  assert.match(text, /aggregate=\?/, "un ref con forma de correo se enmascara");
  const clean = summarizeReconciliation([input(chain(T, invEvents("inv-ok", INV_PATH.slice(0, 1))), [["inv-ok", "DRAFT"]])]);
  assert.equal(exitCodeFor(clean), RECONCILER_EXIT.OK);
  assert.deepEqual(formatReport(clean), ["reconciler_run ok=true tenants=1 events=1 divergences=0"]);
  const many = Array.from({ length: MAX_LOGGED_DIVERGENCES + 5 }, (_, i) => ({ tenantId: T, invitationRef: `i-${i}`, state: "DRAFT" }));
  const big = formatReport(summarizeReconciliation([{ tenantId: T, events: [], invitations: many, decisions: [] }]));
  assert.equal(big.length, MAX_LOGGED_DIVERGENCES + 2);
  assert.match(big[big.length - 1]!, /reconciler_divergences_truncated shown=200 total=205/);
});
