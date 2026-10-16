// Gobierna: ADR-010 rev. 5 §2 (fila `integrity_reconciler`: SELECT cross-tenant de columnas SIN PII), §4.2.c (conciliacion de estado <-> ledger; P6-8: exit code + log sin PII; "el verifier conserva el
// recomputo de la cadena y los checkpoints"; ADR-010 rev. 6 §2: el recomputo es del `chain-verifier`), §10 fila 6e, G-9, INV-DBR-08; specs/ledger-derivation.spec.yaml (tabla OLD->NEW como oraculo; pares ledgerWriter 19 / transitionOwner 14, disjuntos).
// Fix de seguridad PR #99 (P1-1): el reconciler NO lee payload, hashes ni refs de actor, asi que NO recomputa la cadena SHA-256 (eso es del chain-verifier, rev. 6; OI-DBR-10 / F-PR6E-06).
//
// Funcion PURA (sin Postgres, sin reloj, sin I/O): recibe lo que el proceso `reconciler` leyo y devuelve las DIVERGENCIAS. Cubre, sin payload:
//   * huecos de chain_seq por tenant (1..n) y eventos sin eslabon (chain_seq NULL) posteriores al inicio de la cadena;
//   * hueco de `sequence` por agregado (debe ser 1..n);
//   * pares `Agregado:EVENTO` fuera de la particion (ledger_writer 19 U transition_owner 14);
//   * estado <-> ledger de Invitation (incluye CANCELLED <-> INVITATION_CANCELLED) y ConsentDecision (incluye REVOKED <-> CONSENT_REVOKED, vinculado por app.revocation.revoked_decision_ref),
//     en ambos sentidos (fila sin evento, evento sin fila, valores distintos) y con cuenta de ocurrencias (eventos que deben aparecer UNA sola vez).
// No decide si hubo consentimiento, si el OTP es valido ni la autorizacion del tenant (Master Plan §32). No corrige nada.
// Cero PII: la salida contiene SOLO ids opacos, tipos de evento y enums.
// FUERA (FINDING F-PR6E-01/02/06): recomputo de hashes, Revocation/RightsCase por estado, sesiones CASE/PLATFORM (6c), Enrollment, DecisionMakerVerification, siembras de catalogo.

import { LEDGER_DERIVATION_EDGES } from "../common/ledger-derivation.ts";

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

/** Evento del ledger leido por el reconciler: SOLO las 7 columnas sin PII concedidas en 0057. `chainSeq` null = sin eslabon. */
export interface ReconciledEvent {
  readonly tenantId: string;
  readonly chainSeq: number | null;
  readonly aggregateType: string;
  readonly aggregateId: string;
  readonly sequence: number;
  readonly eventType: string;
  /** `YYYY-MM-DDTHH24:MI:SS.US` UTC con microsegundos (orden lexicografico = orden temporal). */
  readonly occurredAt: string;
}

export interface InvitationStateRow { readonly tenantId: string; readonly invitationRef: string; readonly state: string }
export interface ConsentDecisionStateRow { readonly tenantId: string; readonly consentId: string; readonly state: string }
/** app.revocation (0058): solo la ref y la decision revocada; vincula Revocation:CONSENT_REVOKED con la decision sin leer payload. */
export interface RevocationLinkRow { readonly tenantId: string; readonly revocationRef: string; readonly revokedDecisionRef: string | null }

export interface TenantReconciliationInput {
  readonly tenantId: string;
  /** Todos los eventos del tenant (con y sin eslabon). Se ordenan aqui. */
  readonly events: readonly ReconciledEvent[];
  readonly invitations: readonly InvitationStateRow[];
  readonly decisions: readonly ConsentDecisionStateRow[];
  readonly revocations: readonly RevocationLinkRow[];
}

export type DivergenceKind =
  | "CHAIN_SEQ_GAP" // chain_seq del tenant no es 1..n (fila borrada); chainSeq = primer eslabon fuera de lugar
  | "UNCHAINED_EVENT" // evento sin eslabon posterior al inicio de la cadena (evade el verificador)
  | "AGGREGATE_SEQUENCE_GAP" // sequence del agregado no es 1..n
  | "PAIR_OUTSIDE_PARTITION" // Agregado:EVENTO fuera de ledger_writer U transition_owner
  | "ROW_WITHOUT_EVENT" // fila de estado sin ningun evento de su agregado
  | "EVENT_WITHOUT_ROW" // evento de un agregado sin fila de origen
  | "STATE_EVENT_MISMATCH" // detail = MISSING:<EVENTO> | UNEXPECTED:<EVENTO> | DUPLICATE:<EVENTO>
  | "TENANT_UNPROCESSABLE"; // el tenant no se pudo conciliar (datos malformados); detail = nombre del error

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
/** Eventos de ConsentDecision que deben aparecer UNA sola vez (PURPOSE_DECISION_RECORDED es uno por finalidad; los pasos pueden repetirse). */
const DECISION_ONCE: readonly string[] = ["CONSENT_GRANTED", "CONSENT_DECLINED", "RECEIPT_CREATED"];

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

const countTypes = (events: readonly { eventType: string }[]): Map<string, number> => {
  const m = new Map<string, number>();
  for (const e of events) m.set(e.eventType, (m.get(e.eventType) ?? 0) + 1);
  return m;
};

function checkChainSequence(tenantId: string, events: readonly ReconciledEvent[], out: Divergence[]): void {
  const chained = events.filter((e) => e.chainSeq !== null).sort((a, b) => (a.chainSeq as number) - (b.chainSeq as number));
  for (let i = 0; i < chained.length; i += 1) {
    const e = chained[i] as ReconciledEvent;
    if (e.chainSeq !== i + 1) {
      out.push({ kind: "CHAIN_SEQ_GAP", tenantId, aggregateId: e.aggregateId, chainSeq: e.chainSeq as number });
      break;
    }
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
    const evs = byAgg.get(row.invitationRef) ?? [];
    const counts = countTypes(evs);
    const types = new Set(counts.keys());
    const base = { tenantId, aggregateType: "Invitation", aggregateId: row.invitationRef } as const;
    if (types.size === 0) {
      out.push({ kind: "ROW_WITHOUT_EVENT", ...base, detail: row.state });
      continue;
    }
    // Cada evento de Invitation ocurre a lo sumo UNA vez por agregado (cada arista se recorre una vez; CANCELLED es terminal).
    for (const [t, n] of [...counts].sort(([a], [b]) => a.localeCompare(b))) if (n > 1 && INVITATION_EVENTS.has(t)) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `DUPLICATE:${t}` });
    if (row.state === "CANCELLED") {
      if (!types.has("INVITATION_CREATED")) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "MISSING:INVITATION_CREATED" });
      if (!types.has("INVITATION_CANCELLED")) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "MISSING:INVITATION_CANCELLED" });
      for (const t of [...types].sort()) if (!INVITATION_EVENTS.has(t)) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `UNEXPECTED:${t}` });
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
  // REVOKED <-> CONSENT_REVOKED: el evento vive en el agregado Revocation (aggregate_id = revocation_ref); la decision revocada sale de app.revocation.revoked_decision_ref (sin payload).
  const decisionOfRevocation = new Map(input.revocations.map((r) => [r.revocationRef, r.revokedDecisionRef]));
  const revokedCount = new Map<string, number>();
  for (const e of input.events) {
    if (e.aggregateType !== "Revocation" || e.eventType !== "CONSENT_REVOKED") continue;
    const dec = decisionOfRevocation.get(e.aggregateId);
    if (dec === undefined) out.push({ kind: "EVENT_WITHOUT_ROW", tenantId, aggregateType: "Revocation", aggregateId: e.aggregateId, detail: "CONSENT_REVOKED" });
    else if (dec === null) out.push({ kind: "STATE_EVENT_MISMATCH", tenantId, aggregateType: "Revocation", aggregateId: e.aggregateId, detail: "MISSING:REVOKED_DECISION_REF" });
    else revokedCount.set(dec, (revokedCount.get(dec) ?? 0) + 1);
  }
  for (const row of input.decisions) {
    const counts = countTypes(byAgg.get(row.consentId) ?? []);
    const types = new Set(counts.keys());
    const base = { tenantId, aggregateType: "ConsentDecision", aggregateId: row.consentId } as const;
    const revoked = revokedCount.get(row.consentId) ?? 0;
    for (const t of DECISION_ONCE) if ((counts.get(t) ?? 0) > 1) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `DUPLICATE:${t}` });
    if (revoked > 1) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "DUPLICATE:CONSENT_REVOKED" });
    if (row.state === "PENDING") {
      for (const t of [...types].sort()) if (!DECISION_STEP_EVENTS.has(t)) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: `UNEXPECTED:${t}` });
      if (revoked > 0) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "UNEXPECTED:CONSENT_REVOKED" });
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
    if (row.state === "REVOKED" && revoked === 0) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "MISSING:CONSENT_REVOKED" });
    if (row.state !== "REVOKED" && revoked > 0) out.push({ kind: "STATE_EVENT_MISMATCH", ...base, detail: "UNEXPECTED:CONSENT_REVOKED" });
  }
  for (const id of [...byAgg.keys()].sort()) if (!known.has(id)) out.push({ kind: "EVENT_WITHOUT_ROW", tenantId, aggregateType: "ConsentDecision", aggregateId: id });
  for (const [dec] of [...revokedCount].sort(([a], [b]) => a.localeCompare(b))) if (!known.has(dec)) out.push({ kind: "EVENT_WITHOUT_ROW", tenantId, aggregateType: "ConsentDecision", aggregateId: dec, detail: "CONSENT_REVOKED" });
}

/** Concilia UN tenant. Pura y determinista. Un tenant con datos malformados NO lanza: reporta TENANT_UNPROCESSABLE (la corrida sigue con los demas). */
export function reconcileTenant(input: TenantReconciliationInput): readonly Divergence[] {
  const out: Divergence[] = [];
  try {
    checkChainSequence(input.tenantId, input.events, out);
    checkSequencesAndPairs(input.tenantId, input.events, out);
    checkInvitations(input, out);
    checkDecisions(input, out);
  } catch (error) {
    return [{ kind: "TENANT_UNPROCESSABLE", tenantId: input.tenantId, detail: (error as Error).name }];
  }
  return out;
}

export function summarizeReconciliation(tenants: readonly TenantReconciliationInput[]): ReconciliationReport {
  const divergences = tenants.flatMap((t) => reconcileTenant(t));
  const byKind: Record<string, number> = {};
  for (const d of divergences) byKind[d.kind] = (byKind[d.kind] ?? 0) + 1;
  return { ok: divergences.length === 0, tenants: tenants.length, events: tenants.reduce((n, t) => n + t.events.length, 0), divergences, byKind };
}
