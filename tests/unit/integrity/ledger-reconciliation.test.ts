// Gobierna: ADR-010 rev. 5 §2 (reconciler: columnas SIN PII), §4.2.c (conciliacion; exit code != 0 y log sin PII; el verifier conserva el recomputo de la cadena), §10 fila 6e, G-9, INV-DBR-08;
// specs/ledger-derivation.spec.yaml (oraculo: pares ledgerWriter 19 / transitionOwner 14). Seguridad PR #99 (P1-1, P2-1, P2-2).
// TEST-CNS-1600 (particion de pares), TEST-CNS-1601 (ledger y estado coherentes: sin divergencias), TEST-CNS-1602 (hueco de chain_seq, eventos sin eslabon y tenant malformado sin abortar),
// TEST-CNS-1603 (huecos de sequence por agregado y ocurrencias duplicadas), TEST-CNS-1604 (par fuera de la particion), TEST-CNS-1605 (estado <-> ledger en ambos sentidos: CANCELLED, REVOKED via app.revocation, fila sin evento, evento sin fila),
// TEST-CNS-1606 (salida sin PII y exit codes). Funcion pura: sin Postgres. SYNTHETIC ONLY.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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

interface Spec { type: string; id: string; seq: number }

/** Ledger tal como lo ve el reconciler: SOLO columnas sin PII (sin payload, hashes ni refs de actor). */
function chain(tenantId: string, specs: readonly Spec[]): ReconciledEvent[] {
  return specs.map((s, i) => {
    const [aggregateType, eventType] = s.type.split(":") as [string, string];
    return { tenantId, chainSeq: i + 1, aggregateType, aggregateId: s.id, sequence: s.seq, eventType, occurredAt: `2030-01-01T00:00:${String(i).padStart(2, "0")}.000000` };
  });
}

const INV_PATH = ["INVITATION_CREATED", "INVITATION_READY", "INVITATION_SENT", "INVITATION_OPENED", "INVITATION_VERIFIED"];
const invEvents = (id: string, types: readonly string[]): Spec[] => types.map((t, i) => ({ type: `Invitation:${t}`, id, seq: i + 1 }));
const input = (
  events: ReconciledEvent[],
  invitations: Array<[string, string]> = [],
  decisions: Array<[string, string]> = [],
  revocations: Array<[string, string | null]> = [],
): TenantReconciliationInput => ({
  tenantId: T,
  events,
  invitations: invitations.map(([invitationRef, state]) => ({ tenantId: T, invitationRef, state })),
  decisions: decisions.map(([consentId, state]) => ({ tenantId: T, consentId, state })),
  revocations: revocations.map(([revocationRef, revokedDecisionRef]) => ({ tenantId: T, revocationRef, revokedDecisionRef })),
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

const GRANTED = (id: string): Spec[] => [
  { type: "ConsentDecision:PURPOSE_DECISION_RECORDED", id, seq: 1 },
  { type: "ConsentDecision:CONSENT_GRANTED", id, seq: 2 },
  { type: "ConsentDecision:RECEIPT_CREATED", id, seq: 3 },
];

test("TEST-CNS-1601: ledger y estado coherentes (Invitation hasta COMPLETED, ConsentDecision GRANTED y REVOKED con su Revocation, I9 CANCELLED) no producen divergencias", () => {
  const events = chain(T, [
    ...invEvents("inv-ok", [...INV_PATH, "INVITATION_COMPLETED"]),
    { type: "ConsentDecision:CONSENT_VERSION_VIEWED", id: "dec-ok", seq: 1 },
    { type: "ConsentDecision:PURPOSE_DECISION_RECORDED", id: "dec-ok", seq: 2 },
    { type: "ConsentDecision:CONSENT_GRANTED", id: "dec-ok", seq: 3 },
    { type: "ConsentDecision:RECEIPT_CREATED", id: "dec-ok", seq: 4 },
    ...GRANTED("dec-rev"),
    { type: "Revocation:CONSENT_REVOKED", id: "rev-1", seq: 1 },
    ...invEvents("inv-can", [...INV_PATH, "INVITATION_CANCELLED"]),
    { type: "ConsentDecision:CONSENT_VERSION_VIEWED", id: "dec-pend", seq: 1 },
  ]);
  const inp = input(events, [["inv-ok", "COMPLETED"], ["inv-can", "CANCELLED"]], [["dec-ok", "GRANTED"], ["dec-rev", "REVOKED"], ["dec-pend", "PENDING"]], [["rev-1", "dec-rev"]]);
  assert.deepEqual(reconcileTenant(inp), []);
  assert.equal(summarizeReconciliation([inp]).ok, true);
});

test("TEST-CNS-1602: detecta hueco de chain_seq (fila borrada), eventos sin eslabon posteriores al inicio y un tenant malformado reporta divergencia SIN abortar la corrida", () => {
  const good = chain(T, invEvents("inv-1", INV_PATH.slice(0, 4)));
  const r = kinds(reconcileTenant(input(good.filter((_, i) => i !== 1), [["inv-1", "OPENED"]])));
  assert.ok(r.includes("CHAIN_SEQ_GAP"), r.join(","));
  const unchained: ReconciledEvent = { ...good[3]!, chainSeq: null, sequence: 5, occurredAt: "2031-01-01T00:00:00.000000" };
  assert.ok(kinds(reconcileTenant(input([...good, unchained], [["inv-1", "OPENED"]]))).includes("UNCHAINED_EVENT:INVITATION_OPENED"));
  const legacy: ReconciledEvent = { ...unchained, occurredAt: "2020-01-01T00:00:00.000000" };
  assert.ok(!kinds(reconcileTenant(input([...good, legacy], [["inv-1", "OPENED"]]))).some((k) => k.startsWith("UNCHAINED_EVENT")), "el legado previo a la cadena no cuenta");
  // P2-1: un tenant cuyos datos hacen lanzar a la conciliacion (aqui, un estado no-string) no aborta la corrida: el resto se concilia.
  const poisoned = { ...input(good, [["inv-1", "OPENED"]]), invitations: null as unknown as TenantReconciliationInput["invitations"] };
  const ok2 = input(chain("00000000-0000-4000-8000-0000000000b2", invEvents("inv-2", INV_PATH.slice(0, 1))), [["inv-2", "DRAFT"]]);
  const report = summarizeReconciliation([poisoned, { ...ok2, tenantId: "00000000-0000-4000-8000-0000000000b2" }]);
  assert.deepEqual(kinds(report.divergences), ["TENANT_UNPROCESSABLE:TypeError"]);
  assert.equal(report.tenants, 2);
  assert.equal(report.ok, false);
});

test("TEST-CNS-1603: detecta huecos de sequence por agregado y ocurrencias duplicadas de eventos que deben aparecer una sola vez (CONSENT_GRANTED, INVITATION_CREATED, CONSENT_REVOKED)", () => {
  const holes = chain(T, [{ type: "Invitation:INVITATION_CREATED", id: "i1", seq: 1 }, { type: "Invitation:INVITATION_READY", id: "i1", seq: 3 }]);
  assert.ok(kinds(reconcileTenant(input(holes, [["i1", "READY"]]))).includes("AGGREGATE_SEQUENCE_GAP"));
  const dupInv = chain(T, [...invEvents("i2", INV_PATH.slice(0, 1)), { type: "Invitation:INVITATION_CREATED", id: "i2", seq: 2 }]);
  assert.deepEqual(kinds(reconcileTenant(input(dupInv, [["i2", "DRAFT"]]))), ["STATE_EVENT_MISMATCH:DUPLICATE:INVITATION_CREATED"]);
  const dupGranted = chain(T, [...GRANTED("d1"), { type: "ConsentDecision:CONSENT_GRANTED", id: "d1", seq: 4 }]);
  assert.deepEqual(kinds(reconcileTenant(input(dupGranted, [], [["d1", "GRANTED"]]))), ["STATE_EVENT_MISMATCH:DUPLICATE:CONSENT_GRANTED"]);
  const dupRevoked = chain(T, [...GRANTED("d2"), { type: "Revocation:CONSENT_REVOKED", id: "r1", seq: 1 }, { type: "Revocation:CONSENT_REVOKED", id: "r2", seq: 1 }]);
  assert.deepEqual(kinds(reconcileTenant(input(dupRevoked, [], [["d2", "REVOKED"]], [["r1", "d2"], ["r2", "d2"]]))), ["STATE_EVENT_MISMATCH:DUPLICATE:CONSENT_REVOKED"]);
});

test("TEST-CNS-1604: un par Agregado:EVENTO fuera de la particion (ni ledger_writer ni transition_owner) es una divergencia", () => {
  const events = chain(T, [
    ...invEvents("inv-1", INV_PATH.slice(0, 1)),
    { type: "Invitation:INVITATION_TOKEN_ROTATED", id: "inv-1", seq: 2 }, // valido en la lista blanca de la base, sin productor ni par
    { type: "Tenant:TENANT_STATUS_CHANGED", id: "tenant-x", seq: 1 },
  ]);
  const r = kinds(reconcileTenant(input(events, [["inv-1", "DRAFT"]])));
  assert.ok(r.includes("PAIR_OUTSIDE_PARTITION:INVITATION_TOKEN_ROTATED"));
  assert.ok(r.includes("PAIR_OUTSIDE_PARTITION:TENANT_STATUS_CHANGED"));
});

test("TEST-CNS-1605: estado <-> ledger en ambos sentidos: CANCELLED <-> INVITATION_CANCELLED, REVOKED <-> CONSENT_REVOKED (via app.revocation), fila sin evento y evento sin fila", () => {
  let r = kinds(reconcileTenant(input(chain(T, invEvents("i1", INV_PATH.slice(0, 2))), [["i1", "CANCELLED"]])));
  assert.deepEqual(r, ["STATE_EVENT_MISMATCH:MISSING:INVITATION_CANCELLED"]);
  r = kinds(reconcileTenant(input(chain(T, invEvents("i2", [...INV_PATH.slice(0, 2), "INVITATION_CANCELLED"])), [["i2", "READY"]])));
  assert.deepEqual(r, ["STATE_EVENT_MISMATCH:UNEXPECTED:INVITATION_CANCELLED"]);
  r = kinds(reconcileTenant(input(chain(T, invEvents("i3", INV_PATH.slice(0, 3))), [["i3", "OPENED"]])));
  assert.deepEqual(r, ["STATE_EVENT_MISMATCH:MISSING:INVITATION_OPENED"]);
  r = kinds(reconcileTenant(input(chain(T, invEvents("i4", INV_PATH.slice(0, 4))), [["i4", "SENT"]])));
  assert.deepEqual(r, ["STATE_EVENT_MISMATCH:UNEXPECTED:INVITATION_OPENED"]);
  r = kinds(reconcileTenant(input(chain(T, invEvents("i5", INV_PATH.slice(0, 1))), [["i5", "DRAFT"], ["i-sin-evento", "DRAFT"]])));
  assert.deepEqual(r, ["ROW_WITHOUT_EVENT:DRAFT"]);
  assert.deepEqual(kinds(reconcileTenant(input(chain(T, invEvents("i-huerfano", INV_PATH.slice(0, 1))), []))), ["EVENT_WITHOUT_ROW"]);
  assert.deepEqual(kinds(reconcileTenant(input(chain(T, GRANTED("d1")), [], []))), ["EVENT_WITHOUT_ROW"]);
  // REVOKED sin CONSENT_REVOKED; CONSENT_REVOKED con la decision aun GRANTED; CONSENT_REVOKED de una Revocation sin fila / de una decision inexistente.
  assert.deepEqual(kinds(reconcileTenant(input(chain(T, GRANTED("d1")), [], [["d1", "REVOKED"]]))), ["STATE_EVENT_MISMATCH:MISSING:CONSENT_REVOKED"]);
  const revoked = chain(T, [...GRANTED("d1"), { type: "Revocation:CONSENT_REVOKED", id: "r1", seq: 1 }]);
  assert.deepEqual(kinds(reconcileTenant(input(revoked, [], [["d1", "GRANTED"]], [["r1", "d1"]]))), ["STATE_EVENT_MISMATCH:UNEXPECTED:CONSENT_REVOKED"]);
  assert.deepEqual(kinds(reconcileTenant(input(revoked, [], [["d1", "REVOKED"]], [["r1", "d1"]]))), []);
  assert.deepEqual(kinds(reconcileTenant(input(revoked, [], [["d1", "REVOKED"]], []))), ["EVENT_WITHOUT_ROW:CONSENT_REVOKED", "STATE_EVENT_MISMATCH:MISSING:CONSENT_REVOKED"]);
  const ghost = chain(T, [{ type: "Revocation:CONSENT_REVOKED", id: "r2", seq: 1 }]);
  assert.deepEqual(kinds(reconcileTenant(input(ghost, [], [], [["r2", "d-fantasma"]]))), ["EVENT_WITHOUT_ROW:CONSENT_REVOKED"]);
  // CONSENT_REVOKED cuya Revocation tiene revoked_decision_ref NULL: no se puede vincular a ninguna decision.
  const nullRef = chain(T, [{ type: "Revocation:CONSENT_REVOKED", id: "r3", seq: 1 }]);
  assert.deepEqual(kinds(reconcileTenant(input(nullRef, [], [], [["r3", null]]))), ["STATE_EVENT_MISMATCH:MISSING:REVOKED_DECISION_REF"]);
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

test("TEST-CNS-1606: la salida no contiene PII, enmascara ids con forma de texto libre, acota las lineas y el exit code es 0/2", () => {
  const events = chain(T, invEvents("inv-1", INV_PATH.slice(0, 3)));
  const weird = input(events.filter((_, i) => i !== 1), [["inv-1", "SENT"], ["correo@ejemplo.cl", "DRAFT"]]);
  const report = summarizeReconciliation([weird]);
  const text = formatReport(report).join("\n");
  assert.equal(report.ok, false);
  assert.equal(exitCodeFor(report), RECONCILER_EXIT.DIVERGENCE);
  assert.match(text, /^reconciler_run ok=false tenants=1 events=2 divergences=\d+ kinds=/);
  assert.match(text, /kind=CHAIN_SEQ_GAP tenant=00000000-0000-4000-8000-0000000000a1 .*chainSeq=3/);
  assert.ok(!text.includes("correo@ejemplo.cl"), "un ref con forma de correo no se imprime");
  assert.match(text, /aggregate=\?/);
  const clean = summarizeReconciliation([input(chain(T, invEvents("inv-ok", INV_PATH.slice(0, 1))), [["inv-ok", "DRAFT"]])]);
  assert.equal(exitCodeFor(clean), RECONCILER_EXIT.OK);
  assert.deepEqual(formatReport(clean), ["reconciler_run ok=true tenants=1 events=1 divergences=0"]);
  const many = Array.from({ length: MAX_LOGGED_DIVERGENCES + 5 }, (_, i) => ({ tenantId: T, invitationRef: `i-${i}`, state: "DRAFT" }));
  const big = formatReport(summarizeReconciliation([{ tenantId: T, events: [], invitations: many, decisions: [], revocations: [] }]));
  assert.equal(big.length, MAX_LOGGED_DIVERGENCES + 2);
  assert.match(big[big.length - 1]!, /reconciler_divergences_truncated shown=200 total=205/);
});
