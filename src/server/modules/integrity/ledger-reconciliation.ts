// Gobierna: ADR-010 rev. 5 §4.2.c (conciliacion; P6-8: exit code + log sin PII), §10 fila 6e, G-9 (proceso/rol `reconciler`/`integrity_reconciler`), specs/db-roles.spec.yaml INV-DBR-08,
// specs/ledger-derivation.spec.yaml (tabla OLD->NEW como oraculo; pares: ledgerWriter 19, transitionOwner 14, disjuntos) y DEC-BR-014 rev. 8 §3 X6 (recomputacion de la cadena SHA-256 por tenant).
//
// Funcion PURA (sin Postgres, sin reloj, sin I/O): recibe lo que el proceso `reconciler` leyo (eventos del ledger y estado de las tablas con ledger derivado) y devuelve las DIVERGENCIAS.
// Cubre:
//   * cadena SHA-256 por tenant: hash roto, hueco de chain_seq, bifurcacion/previous_hash, payload mutado, tipo fuera de la lista blanca (verifyChainRows, la misma canonicalizacion que escriben
//     ledger_gen.ledger_append y case_state.ledger_append);
//   * eventos sin eslabon (chain_seq NULL) posteriores al inicio de la cadena;
//   * hueco de `sequence` por agregado (debe ser 1..n: max+1 bajo el lock por tenant);
//   * pares `Agregado:EVENTO` fuera de la particion (ledger_writer 19 U transition_owner 14);
//   * estado <-> ledger de Invitation (incluye CANCELLED <-> INVITATION_CANCELLED, I9) y ConsentDecision (incluye REVOKED <-> CONSENT_REVOKED), en ambos sentidos (fila sin evento, evento sin fila,
//     valores distintos), con LEDGER_DERIVATION_EDGES como oraculo de lo que cada estado exige.
// No decide si hubo consentimiento, si el OTP es valido ni la autorizacion del tenant (Master Plan §32): detecta incoherencias entre el estado y la evidencia; no corrige nada.
// Cero PII: la salida contiene SOLO ids opacos (tenant_id, refs de agregado), tipos de evento y enums. Nunca payloads ni hashes.
// FUERA de esta funcion (FINDING F-PR6E-01/02): Revocation/RightsCase por estado, sesiones CASE/PLATFORM (6c), Enrollment, DecisionMakerVerification, siembras de catalogo.

import { LEDGER_DERIVATION_EDGES } from "../common/ledger-derivation.ts";
import { verifyChainRows } from "../common/ledger-chain.ts";
import type { ChainRow } from "../common/ledger-chain.ts";

/** Pares `Agregado:EVENTO` que puede escribir ledger_writer (policy audit_event_ledger_insert; specs/ledger-derivation.spec.yaml pairs.ledgerWriter = 19). */
export const LEDGER_WRITER_PAIRS: ReadonlySet<string> = new Set([
  "Enrollment:ENROLLMENT_STATUS_CHANGED",
  "Invitation:INVITATION_CREATED", "Invitation:INVITATION_READY", "Invitation:INVITATION_SENT", "Invitation:INVITATION_OPENED", "Invitation:INVITATION_VERIFIED",
  "Invitation:INVITATION_COMPLETED", "Invitation:INVITATION_DECLINED",
  "DecisionMakerVerification:DECISION_MAKER_CHANNEL_VERIFIED",
  "ConsentDecision:CONTEXT_INFORMATION_VIEWED", "ConsentDecision:CONSENT_VERSION_VIEWED", "ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED", "ConsentDecision:SUBJECT_CONFIRMED",
  "ConsentDecision:PURPOSE_DECISION_RECORDED", "ConsentDecision:CONSENT_GRANTED", "ConsentDecision:CONSENT_DECLINED", "ConsentDecision:RECEIPT_CREATED",
  "Tenant:TENANT_SEEDED", "SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED",
]);

/** Pares que puede escribir transition_owner (policy audit_event_transition_insert; pairs.transitionOwner = 14). Disjuntos de los de ledger_writer. */
export const TRANSITION_OWNER_PAIRS: ReadonlySet<string> = new Set([
  "Revocation:REVOCATION_REQUESTED", "Revocation:REVOCATION_VERIFIED", "Revocation:REVOCATION_CONFIRMED", "Revocation:CONSENT_REVOKED", "Revocation:RECEIPT_CREATED",
  "Revocation:REVOCATION_DOWNSTREAM_EMITTED", "Revocation:REVOCATION_DELIVERED", "Revocation:DOWNSTREAM_ERASURE_ATTESTED", "Revocation:REVOCATION_FAILED",
  "Revocation:REVOCATION_PROPOSAL_WITHDRAWN", "RightsCase:RIGHTS_CASE_OPENED", "RightsCase:RIGHTS_CASE_CONTACTING", "RightsCase:RIGHTS_CASE_CLOSED", "Invitation:INVITATION_CANCELLED",
]);

/** Evento del ledger leido por el reconciler (sin escribir nunca payload ni hashes en la salida). `chainSeq` null = sin eslabon. */
export interface ReconciledEvent extends Omit<ChainRow, "chainSeq"> {
  readonly chainSeq: number | null;
}

export interface InvitationStateRow { readonly tenantId: string; readonly invitationRef: string; readonly state: string }
export interface ConsentDecisionStateRow { readonly tenantId: string; readonly consentId: string; readonly state: string }

export interface TenantReconciliationInput {
  readonly tenantId: string;
  /** Todos los eventos del tenant (con y sin eslabon). Se ordenan aqui. */
  readonly events: readonly ReconciledEvent[];
  readonly invitations: readonly InvitationStateRow[];
  readonly decisions: readonly ConsentDecisionStateRow[];
}

export type DivergenceKind =
  | "CHAIN_BROKEN" // detail = ChainBreakReason; chainSeq = primer eslabon roto
  | "UNCHAINED_EVENT" // evento sin eslabon posterior al inicio de la cadena (evade el verificador)
  | "AGGREGATE_SEQUENCE_GAP" // sequence del agregado no es 1..n
  | "PAIR_OUTSIDE_PARTITION" // Agregado:EVENTO fuera de ledger_writer U transition_owner
  | "ROW_WITHOUT_EVENT" // fila de estado sin ningun evento de su agregado
  | "EVENT_WITHOUT_ROW" // evento de un agregado sin fila de origen
  | "STATE_EVENT_MISMATCH"; // detail = MISSING:<EVENTO> | UNEXPECTED:<EVENTO>

export interface Divergence {
  readonly kind: DivergenceKind;
  /** UUID opaco del tenant. */
  readonly tenantId: string;
  readonly aggregateType?: string;
  /** Ref opaca del agregado. */
  readonly aggregateId?: string;
  /** Enum o tipo de evento; nunca valores de payload. */
  readonly detail?: string;
  readonly chainSeq?: number;
}

export interface ReconciliationReport {
  readonly ok: boolean;
  readonly tenants: number;
  readonly events: number;
  readonly divergences: readonly Divergence[];
  readonly byKind: Readonly<Record<string, number>>;
}

const pairOf = (e: { aggregateType: string; eventType: string }): string => `${e.aggregateType}:${e.eventType}`;
const stripAggregate = (pair: string): string => pair.slice(pair.indexOf(":") + 1);

/** Eventos que el oraculo exige para llegar a `state` desde el INSERT (aristas de ledger_writer de la tabla OLD->NEW). */
function requiredEventsByState(aggregate: string): ReadonlyMap<string, ReadonlySet<string>> {
  const edges = LEDGER_DERIVATION_EDGES.filter((e) => e.aggregate === aggregate);
  const out = new Map<string, Set<string>>();
  const walk = (from: string | null, acc: ReadonlySet<string>, seen: ReadonlySet<string>): void => {
    for (const e of edges) {
      if (e.from !== from || e.emitter === "transition_owner") continue;
      const emits = e.emits.filter((p) => !p.includes("<stepKind>")).map(stripAggregate);
      const next = new Set([...acc, ...emits]);
      // Una arista PENDING->PENDING (C2) no cambia el estado: no es un paso del camino.
      if (e.to === from) continue;
      const prev = out.get(e.to);
      // Para cada estado, lo exigido es la INTERSECCION de los caminos (con un solo camino, el propio camino).
      out.set(e.to, prev === undefined ? next : new Set([...prev].filter((x) => next.has(x))));
      if (!seen.has(e.to)) walk(e.to, next, new Set([...seen, e.to]));
    }
  };
  walk(null, new Set(), new Set());
  return out;
}

const INVITATION_REQUIRED = requiredEventsByState("Invitation");
const DECISION_REQUIRED = requiredEventsByState("ConsentDecision");
const INVITATION_EVENTS = new Set([...LEDGER_WRITER_PAIRS].filter((p) => p.startsWith("Invitation:")).map(stripAggregate).concat(["INVITATION_CANCELLED"]));
/** Eventos de paso del agregado ConsentDecision (C2: `<stepKind>`), validos en cualquier estado. */
const DECISION_STEP_EVENTS: ReadonlySet<string> = new Set(["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"]);
const DECISION_TERMINAL_EVENTS: ReadonlySet<string> = new Set(["PURPOSE_DECISION_RECORDED", "CONSENT_GRANTED", "CONSENT_DECLINED", "RECEIPT_CREATED"]);

function groupBy<T>(items: readonly T[], key: (t: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const it of items) {
    const k = key(it);
    const arr = m.get(k);
    if (arr === undefined) m.set(k, [it]);
    else arr.push(it);
  }
  return m;
}

function checkChain(tenantId: string, events: readonly ReconciledEvent[], out: Divergence[]): void {
  const chained = events.filter((e): e is ChainRow => e.chainSeq !== null).sort((a, b) => a.chainSeq - b.chainSeq);
  const report = verifyChainRows(chained);
  if (!report.ok) {
    const b = report.brokenAt;
    out.push({ kind: "CHAIN_BROKEN", tenantId, aggregateId: b.aggregateId, detail: b.reason, chainSeq: b.chainSeq });
  }
  // Filas previas a 0013 (sin eslabon) son legado fuera de la cadena; las POSTERIORES al primer eslabon evaden el verificador.
  const first = chained[0];
  if (first !== undefined) {
    for (const e of events) {
      if (e.chainSeq === null && e.occurredAt > first.occurredAt) out.push({ kind: "UNCHAINED_EVENT", tenantId, aggregateType: e.aggregateType, aggregateId: e.aggregateId, detail: e.eventType });
    }
  }
}

function checkSequencesAndPairs(tenantId: string, events: readonly ReconciledEvent[], out: Divergence[]): void {
  for (const [, group] of groupBy(events, (e) => e.aggregateId)) {
    const seqs = group.map((e) => e.sequence).sort((a, b) => a - b);
    const gap = seqs.some((s, i) => s !== i + 1);
    const g = group[0];
    if (gap && g !== undefined) out.push({ kind: "AGGREGATE_SEQUENCE_GAP", tenantId, aggregateType: g.aggregateType, aggregateId: g.aggregateId });
  }
  for (const e of events) {
    const pair = pairOf(e);
    if (!LEDGER_WRITER_PAIRS.has(pair) && !TRANSITION_OWNER_PAIRS.has(pair)) {
      out.push({ kind: "PAIR_OUTSIDE_PARTITION", tenantId, aggregateType: e.aggregateType, aggregateId: e.aggregateId, detail: e.eventType });
    }
  }
}

function checkInvitations(input: TenantReconciliationInput, out: Divergence[]): void {
  const { tenantId } = input;
  const byAgg = groupBy(input.events.filter((e) => e.aggregateType === "Invitation"), (e) => e.aggregateId);
  const known = new Set(input.invitations.map((r) => r.invitationRef));
  for (const row of input.invitations) {
    const types = new Set((byAgg.get(row.invitationRef) ?? []).map((e) => e.eventType));
    const base = { tenantId, aggregateType: "Invitation", aggregateId: row.invitationRef } as const;
    if (types.size === 0) {
      out.push({ kind: "ROW_WITHOUT_EVENT", ...base, detail: row.state });
      continue;
    }
    if (row.state === "CANCELLED") {
      // I9: la cancelacion la emite transition_owner; la fila nace con INVITATION_CREATED. Eventos intermedios dependen de desde donde se cancelo.
      if (!types.has("INVITATION_CREATED")) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "MISSING:INVITATION_CREATED" });
      if (!types.has("INVITATION_CANCELLED")) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "MISSING:INVITATION_CANCELLED" });
      for (const t of types) if (!INVITATION_EVENTS.has(t)) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `UNEXPECTED:${t}` });
      continue;
    }
    const required = INVITATION_REQUIRED.get(row.state);
    if (required === undefined) {
      out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "UNEXPECTED:STATE" });
      continue;
    }
    for (const t of [...required].sort()) if (!types.has(t)) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `MISSING:${t}` });
    for (const t of [...types].sort()) if (!required.has(t)) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `UNEXPECTED:${t}` });
  }
  for (const id of [...byAgg.keys()].sort()) if (!known.has(id)) out.push({ kind: "EVENT_WITHOUT_ROW", tenantId, aggregateType: "Invitation", aggregateId: id });
}

function checkDecisions(input: TenantReconciliationInput, out: Divergence[]): void {
  const { tenantId } = input;
  const byAgg = groupBy(input.events.filter((e) => e.aggregateType === "ConsentDecision"), (e) => e.aggregateId);
  const known = new Set(input.decisions.map((r) => r.consentId));
  // REVOKED <-> CONSENT_REVOKED: el evento vive en el agregado Revocation y nombra la decision en payload.revokedDecisionRef.
  const revokedRefs = new Set<string>();
  for (const e of input.events) {
    if (e.aggregateType === "Revocation" && e.eventType === "CONSENT_REVOKED") {
      const ref = e.payload.revokedDecisionRef;
      if (typeof ref === "string") revokedRefs.add(ref);
    }
  }
  for (const row of input.decisions) {
    const types = new Set((byAgg.get(row.consentId) ?? []).map((e) => e.eventType));
    const base = { tenantId, aggregateType: "ConsentDecision", aggregateId: row.consentId } as const;
    const revoked = revokedRefs.has(row.consentId);
    if (row.state === "PENDING") {
      for (const t of [...types].sort()) if (!DECISION_STEP_EVENTS.has(t)) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `UNEXPECTED:${t}` });
      if (revoked) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "UNEXPECTED:CONSENT_REVOKED" });
      continue;
    }
    // GRANTED / DECLINED exigen lo que emite C3 / C5; REVOKED exige lo de C3 (viene de GRANTED, C6) mas CONSENT_REVOKED.
    const required = DECISION_REQUIRED.get(row.state === "REVOKED" ? "GRANTED" : row.state);
    if (required === undefined) {
      out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "UNEXPECTED:STATE" });
      continue;
    }
    for (const t of [...required].sort()) if (!types.has(t)) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `MISSING:${t}` });
    for (const t of [...types].sort()) {
      if (!required.has(t) && !DECISION_STEP_EVENTS.has(t) && DECISION_TERMINAL_EVENTS.has(t)) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `UNEXPECTED:${t}` });
    }
    if (row.state === "REVOKED" && !revoked) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "MISSING:CONSENT_REVOKED" });
    if (row.state !== "REVOKED" && revoked) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "UNEXPECTED:CONSENT_REVOKED" });
  }
  for (const id of [...byAgg.keys()].sort()) if (!known.has(id)) out.push({ kind: "EVENT_WITHOUT_ROW", tenantId, aggregateType: "ConsentDecision", aggregateId: id });
  for (const id of [...revokedRefs].sort()) if (!known.has(id)) out.push({ kind: "EVENT_WITHOUT_ROW", tenantId, aggregateType: "ConsentDecision", aggregateId: id, detail: "CONSENT_REVOKED" });
}

/** Concilia UN tenant. Pura y determinista (mismo input -> mismas divergencias, mismo orden). */
export function reconcileTenant(input: TenantReconciliationInput): readonly Divergence[] {
  const out: Divergence[] = [];
  checkChain(input.tenantId, input.events, out);
  checkSequencesAndPairs(input.tenantId, input.events, out);
  checkInvitations(input, out);
  checkDecisions(input, out);
  return out;
}

export function summarizeReconciliation(tenants: readonly TenantReconciliationInput[]): ReconciliationReport {
  const divergences = tenants.flatMap((t) => reconcileTenant(t));
  const byKind: Record<string, number> = {};
  for (const d of divergences) byKind[d.kind] = (byKind[d.kind] ?? 0) + 1;
  return { ok: divergences.length === 0, tenants: tenants.length, events: tenants.reduce((n, t) => n + t.events.length, 0), divergences, byKind };
}
