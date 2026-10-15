// Gobierna: ADR-010 rev. 5 §4.2.b (LG-1..LG-10), specs/ledger-derivation.spec.yaml (tabla OLD->NEW, unica fuente de la emision), src/server/modules/common/ledger-derivation.ts.
// TEST-CNS-1465: la tabla de la spec coincide con LEDGER_DERIVATION_EDGES (id, agregado, from, to, emits, emitter); las aristas "sin emision" (I9, C6) tienen emisor transition_owner;
// toda arista emisora de ledger_writer emite pares dentro de los 19 de ledger_writer; los pares de ledger_writer y transition_owner no se solapan.
// TEST-CNS-1466: el oraculo TS deriva exactamente los eventos de cada arista (tipos, orden, actor, clave) y nada para las aristas sin emision ni para filas fuera de la tabla.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { parseYaml } from "../../../tools/spec-checks/yaml-lite.ts";
import {
  deriveConsentDecisionEvents,
  deriveEnrollmentEvents,
  deriveInvitationEvents,
  deriveOtpEvents,
  LEDGER_DERIVATION_EDGES,
} from "../../../src/server/modules/common/ledger-derivation.ts";
import type { ConsentDecisionRecord } from "../../../src/server/ports/consent-decision-repository.port.ts";
import type { InvitationRecord } from "../../../src/server/ports/invitation-repository.port.ts";
import type { OtpVerificationRecord } from "../../../src/server/ports/otp-verification-repository.port.ts";

const SPEC = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "specs", "ledger-derivation.spec.yaml");
const spec = parseYaml(readFileSync(SPEC, "utf-8")) as { edges: Array<Record<string, unknown>>; pairs: Record<string, unknown>; notEdges: Array<Record<string, unknown>> };

const LEDGER_WRITER_PAIRS = new Set([
  "Enrollment:ENROLLMENT_STATUS_CHANGED",
  "Invitation:INVITATION_CREATED", "Invitation:INVITATION_READY", "Invitation:INVITATION_SENT", "Invitation:INVITATION_OPENED", "Invitation:INVITATION_VERIFIED",
  "Invitation:INVITATION_COMPLETED", "Invitation:INVITATION_DECLINED",
  "DecisionMakerVerification:DECISION_MAKER_CHANNEL_VERIFIED",
  "ConsentDecision:CONTEXT_INFORMATION_VIEWED", "ConsentDecision:CONSENT_VERSION_VIEWED", "ConsentDecision:DECISION_MAKER_AUTHORITY_DECLARED", "ConsentDecision:SUBJECT_CONFIRMED",
  "ConsentDecision:PURPOSE_DECISION_RECORDED", "ConsentDecision:CONSENT_GRANTED", "ConsentDecision:CONSENT_DECLINED", "ConsentDecision:RECEIPT_CREATED",
  "Tenant:TENANT_SEEDED", "SchoolParticipation:SCHOOL_PARTICIPATION_SEEDED",
]);
const TRANSITION_PAIRS = new Set([
  "Revocation:REVOCATION_REQUESTED", "Revocation:REVOCATION_VERIFIED", "Revocation:REVOCATION_CONFIRMED", "Revocation:CONSENT_REVOKED", "Revocation:RECEIPT_CREATED",
  "Revocation:REVOCATION_DOWNSTREAM_EMITTED", "Revocation:REVOCATION_DELIVERED", "Revocation:DOWNSTREAM_ERASURE_ATTESTED", "Revocation:REVOCATION_FAILED",
  "Revocation:REVOCATION_PROPOSAL_WITHDRAWN", "RightsCase:RIGHTS_CASE_OPENED", "RightsCase:RIGHTS_CASE_CONTACTING", "RightsCase:RIGHTS_CASE_CLOSED", "Invitation:INVITATION_CANCELLED",
]);

test("TEST-CNS-1465: la tabla OLD->NEW de la spec coincide con LEDGER_DERIVATION_EDGES; I9 y C6 son aristas sin emision de transition_owner; los pares de ledger_writer (19) y transition_owner (14) son disjuntos", () => {
  const fromSpec = spec.edges.map((e) => ({ id: e.id, aggregate: e.aggregate, from: e.from, to: e.to, emits: e.emits, emitter: e.emitter }));
  const fromTs = LEDGER_DERIVATION_EDGES.map((e) => ({ id: e.id, aggregate: e.aggregate, from: e.from, to: e.to, emits: [...e.emits], emitter: e.emitter }));
  assert.deepEqual(fromSpec, fromTs);
  for (const e of LEDGER_DERIVATION_EDGES) {
    if (e.id === "C6" || e.id.startsWith("I9")) {
      assert.deepEqual([e.emits.length, e.emitter], [0, "transition_owner"], e.id);
    }
    if (e.emitter === "ledger_writer") {
      for (const pair of e.emits) assert.ok(pair.includes("<stepKind>") || LEDGER_WRITER_PAIRS.has(pair), `${e.id}: ${pair} fuera de los pares de ledger_writer`);
    }
  }
  assert.equal(LEDGER_WRITER_PAIRS.size, (spec.pairs as { ledgerWriter: number }).ledgerWriter);
  assert.equal(TRANSITION_PAIRS.size, (spec.pairs as { transitionOwner: number }).transitionOwner);
  for (const p of LEDGER_WRITER_PAIRS) assert.ok(!TRANSITION_PAIRS.has(p), `${p} solapa`);
  // ACTIVE->CLOSED (F-PRB-03) y el retiro de seed_local_revoke_decision (F-PRB-02) quedan declarados como no-aristas.
  assert.ok(spec.notEdges.some((n) => n.id === "EN1-CLOSE") && spec.notEdges.some((n) => n.id === "SEED-REVOKE"));
  assert.ok(!LEDGER_DERIVATION_EDGES.some((e) => e.aggregate === "Enrollment" && e.to === "CLOSED"));
});

const T = "11111111-1111-4111-8111-111111111111";

test("TEST-CNS-1466: el oraculo TS deriva los eventos de cada arista (tipos, orden, actor, clave) y nada para I9, C6, C1 ni para filas fuera de la tabla", () => {
  // Enrollment: INSERT ACTIVE emite; CLOSED no (no es arista).
  const en = { enrollmentRef: "e", tenantId: T, subjectRef: "s", participationRef: "p", state: "ACTIVE" as const };
  assert.deepEqual(deriveEnrollmentEvents(null, en).map((e) => [e.eventType, e.actorRole, e.idempotencyKey]), [["ENROLLMENT_STATUS_CHANGED", "INVITER", `${T}:s:p:en0`]]);
  assert.deepEqual(deriveEnrollmentEvents(en, { ...en, state: "CLOSED" }), []);
  // OTP: CODE_SENT->VERIFIED emite DMV; el resto no.
  const otp: OtpVerificationRecord = { verificationRef: "v", tenantId: T, scope: "REVOCATION", parentRef: "c", channelRef: "mgmt:x", codeHash: "a".repeat(64), attempts: 0, expiresAt: new Date(), state: "CODE_SENT", resendCount: 0 };
  const verified = { ...otp, attempts: 1, state: "VERIFIED" as const, decisionMakerRef: "dm", dmRefKeyVersion: 2 };
  const dmv = deriveOtpEvents(otp, verified);
  assert.deepEqual(dmv.map((e) => [e.eventType, e.aggregateType, e.payload.scope, e.idempotencyKey]), [["DECISION_MAKER_CHANNEL_VERIFIED", "DecisionMakerVerification", "REVOCATION", "v:verified"]]);
  assert.deepEqual(deriveOtpEvents(otp, { ...otp, attempts: 1 }), []);
  // Invitation: cadena completa, e I9 sin emision.
  const base: InvitationRecord = { invitationRef: "i", tenantId: T, contextRef: "c", productRef: "p", subjectRef: "s", state: "DRAFT", enrollmentRef: "e", participationRef: "p" };
  const ready: InvitationRecord = { ...base, state: "READY", consentVersion: "v1", expiresAt: new Date("2030-01-01T00:00:00.000Z"), recipientBinding: "UNBOUND" };
  const sent: InvitationRecord = { ...ready, state: "SENT", tokenHash: "a".repeat(64), deliveryChannel: "SCHOOL_CHANNEL" };
  const opened: InvitationRecord = { ...sent, state: "OPENED" };
  const verifiedInv: InvitationRecord = { ...opened, state: "VERIFIED", boundDecisionMakerRef: "dm", verifiedByRef: "v", dmRefKeyVersion: 2 };
  const done: InvitationRecord = { ...verifiedInv, state: "COMPLETED", closedByConsentId: "c1" };
  const types = [[null, base], [base, ready], [ready, sent], [sent, opened], [opened, verifiedInv], [verifiedInv, done], [verifiedInv, { ...verifiedInv, state: "DECLINED" as const, closedByConsentId: "c1" }]] as const;
  assert.deepEqual(types.map(([p, n]) => deriveInvitationEvents(p, n).map((e) => e.eventType)), [
    ["INVITATION_CREATED"], ["INVITATION_READY"], ["INVITATION_SENT"], ["INVITATION_OPENED"], ["INVITATION_VERIFIED"], ["INVITATION_COMPLETED"], ["INVITATION_DECLINED"],
  ]);
  for (const from of [base, ready, sent, opened, verifiedInv]) assert.deepEqual(deriveInvitationEvents(from, { ...from, state: "CANCELLED" }), [], `I9 desde ${from.state}`);
  assert.deepEqual(deriveInvitationEvents(verifiedInv, { ...verifiedInv, state: "OPENED" }), [], "arista fuera de la tabla");
  // ConsentDecision: C1 no emite; C2 un evento por paso; C3 finalidades + GRANTED + RECEIPT; C5 DECLINED; C6 no emite.
  const pending: ConsentDecisionRecord = { consentId: "c1", tenantId: T, contextRef: "c", productRef: "p", subjectRef: "s", decisionMakerRef: "dm", invitationRef: "i", verificationRef: "v", chainRef: "ch", state: "PENDING", purposes: [], priorStepsComplete: false, stepsRecorded: [] };
  assert.deepEqual(deriveConsentDecisionEvents(null, pending), []);
  const s1: ConsentDecisionRecord = { ...pending, stepsRecorded: ["SUBJECT_CONFIRMED"] };
  assert.deepEqual(deriveConsentDecisionEvents(pending, s1).map((e) => [e.eventType, e.payload.subjectRef]), [["SUBJECT_CONFIRMED", "s"]]);
  const purposes = [{ purpose: "A", choice: "GRANT" as const }, { purpose: "B", choice: "GRANT" as const }];
  const granted: ConsentDecisionRecord = { ...pending, state: "GRANTED", purposes, receiptRef: "r", consentVersion: "v", consentTextHash: "a".repeat(64), privacyNoticeVersion: "p", managementLinkIssued: true };
  assert.deepEqual(deriveConsentDecisionEvents(pending, granted).map((e) => e.eventType), ["PURPOSE_DECISION_RECORDED", "PURPOSE_DECISION_RECORDED", "CONSENT_GRANTED", "RECEIPT_CREATED"]);
  assert.equal(deriveConsentDecisionEvents(pending, granted).at(-1)?.payload.managementLinkIssued, true);
  const declined: ConsentDecisionRecord = { ...granted, state: "DECLINED", managementLinkIssued: true };
  assert.equal(deriveConsentDecisionEvents(pending, declined).at(-1)?.payload.managementLinkIssued, false, "C5 nunca emite enlace");
  assert.deepEqual(deriveConsentDecisionEvents(granted, { ...granted, state: "REVOKED" }), [], "C6 no emite en ledger_gen");
});
