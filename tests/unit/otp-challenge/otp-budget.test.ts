// Gobierna: SEC-CNS-021 PR-4 (CA-146 / DF-10), otp-challenge.spec V1/V2/V3/V2r/V6/V6r/V6a, GRD-OT-03/06/09/14, INV-21-11/12/13/14/15/17.
// In-memory, sintetico. TEST-CNS-162 (V6 al agotar P-04), 163 (acierto no consume), 156 (V6 ERR-OT-06 + FAILED), 157 (V6r ERR-OT-07), 393/394 (V6a),
// 410 (orden de locks invitacion -> challenge), 1317 (P-05), 1319 (subclave HKDF, cero PII), 152/1321 (P-06 3/h con el inicial; ventana de 1 h).
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { createInvitation, markInvitationReady, openInvitation, sendInvitation, type InvitationPorts } from "../../../src/server/modules/invitation/invitation.ts";
import { requestOtp, requestRightsOtp, resendOtp, submitOtp, submitRightsOtp, deriveOtpChannelRefKey, type OtpChallengePorts } from "../../../src/server/modules/otp-challenge/otp-challenge.ts";
import { deriveOtpBudgetKey } from "../../../src/server/modules/otp-challenge/otp-budget.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryInvitationRepository } from "../../../src/infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOtpBudget } from "../../../src/infra/adapters/in-memory-otp-budget.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemorySecurityEventLog } from "../../../src/infra/adapters/in-memory-security-event.adapter.ts";
import { createInMemoryTenancy } from "../../../src/infra/adapters/in-memory-tenancy.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const T = "tenant-budget";
const CH = "test+budget@example.invalid";

function setup(policy: Partial<OtpChallengePorts["policy"]> = {}) {
  const ledger = createInMemoryLedgerAdapter();
  const invitationRepo = createInMemoryInvitationRepository();
  const otpRepo = createInMemoryOtpVerificationRepository();
  const securityEvents = createInMemorySecurityEventLog();
  const otpBudget = createInMemoryOtpBudget();
  const tenancy = createInMemoryTenancy({ ledger, invitationRepo, otpRepo, securityEvents, otpBudget });
  const invitation: InvitationPorts = { invitationRepo, eligibility: createInMemoryEligibilityAdapter(), ledger, ...tenancy };
  const channel = createInMemoryOtpChannelSink();
  const clock = { ms: Date.now() };
  const otp: OtpChallengePorts = {
    otpRepo, channel, ledger, invitation, uow: tenancy.uow, secret: randomBytes(32), now: () => clock.ms,
    policy: { codeLength: 6, maxAttempts: 100, ttlMs: 7_200_000, ...policy },
  };
  return { otp, invitation, channel, securityEvents, otpBudget, invitationRepo, otpRepo, clock };
}

async function open(inv: InvitationPorts, n: string): Promise<string> {
  const ref = fixtureUuid(`inv-${n}`);
  await createInvitation(inv, T, "INVITER", { enrollmentRef: fixtureUuid(`enr-${n}`), participationRef: fixtureUuid(`part-${n}`), invitationRef: ref, contextRef: "BETA_2026_01", productRef: "LECTORPRO", subjectRef: fixtureUuid(`sub-${n}`) });
  await markInvitationReady(inv, T, "INVITER", ref, { consentVersion: "v1", expiresAt: new Date(Date.now() + 60_000), recipientChannelRef: CH });
  const { token } = await sendInvitation(inv, T, "INVITER", ref, { deliveryChannel: "CONSENT_APP_EMAIL" });
  await openInvitation(inv, T, token);
  return ref;
}
const code = (e: unknown): string | undefined => (e instanceof DomainError ? e.code : undefined);
const wrongOf = (c: string): string => (c === "000000" ? "111111" : "000000");

test("TEST-CNS-162/156: V6 DECISION: la 11.a reserva falla -> ERR-OT-06 sin comparar (aun con codigo correcto), challenge FAILED y OTP_BUDGET_EXHAUSTED; sin PII", async () => {
  const s = setup();
  const inv = await open(s.invitation, "162");
  const ver = fixtureUuid("ver-162");
  await requestOtp(s.otp, T, ver, inv, CH);
  const good = s.channel.sent[0]!.code;
  for (let i = 0; i < 10; i += 1) await assert.rejects(() => submitOtp(s.otp, T, ver, wrongOf(good), fixtureUuid("dm"), 2), (e) => code(e) === "ERR-OT-02");
  await assert.rejects(() => submitOtp(s.otp, T, ver, good, fixtureUuid("dm"), 2), (e) => code(e) === "ERR-OT-06");
  assert.equal((await s.otpRepo.findByRef(T, ver))?.state, "FAILED");
  const ev = s.securityEvents.listAll(T).filter((e) => e.eventType === "OTP_BUDGET_EXHAUSTED");
  assert.equal(ev.length, 1);
  assert.equal(JSON.stringify(s.otpBudget.rows(T)).includes(CH), false, "cero correo en ops.otp_budget (INV-21-15)");
  assert.equal(JSON.stringify(ev).includes(CH), false);
  const sent = s.channel.sent.length;
  await assert.rejects(() => requestOtp(s.otp, T, fixtureUuid("ver-162b"), inv, CH), (e) => code(e) === "ERR-OT-06");
  assert.equal(s.channel.sent.length, sent);
});

test("TEST-CNS-163: el acierto no consume presupuesto y la ventana es fija desde el primer fallo; reinicia a las 24 h", async () => {
  const s = setup();
  const inv = await open(s.invitation, "163");
  const ver = fixtureUuid("ver-163");
  await requestOtp(s.otp, T, ver, inv, CH);
  const good = s.channel.sent[0]!.code;
  await assert.rejects(() => submitOtp(s.otp, T, ver, wrongOf(good), fixtureUuid("dm"), 2));
  assert.deepEqual(s.otpBudget.rows(T).map((r) => r.failures), [1, 1]);
  const start = s.otpBudget.rows(T)[0]!.windowStart.getTime();
  s.clock.ms += 3_600_000;
  await assert.rejects(() => submitOtp(s.otp, T, ver, wrongOf(good), fixtureUuid("dm"), 2));
  assert.equal(s.otpBudget.rows(T)[0]!.windowStart.getTime(), start, "no se desliza");
  assert.deepEqual(s.otpBudget.rows(T).map((r) => r.failures), [2, 2]);
  await submitOtp(s.otp, T, ver, good, fixtureUuid("dm"), 2);
  assert.deepEqual(s.otpBudget.rows(T).map((r) => r.failures), [2, 2], "acierto: reserva y reversion netas 0");
  const inv2 = await open(s.invitation, "163b");
  const ver2 = fixtureUuid("ver-163b");
  s.clock.ms += 24 * 3_600_000; // el challenge se emite con la ventana anterior ya vencida
  await requestOtp(s.otp, T, ver2, inv2, CH);
  await assert.rejects(() => submitOtp(s.otp, T, ver2, wrongOf(s.channel.sent.at(-1)!.code), fixtureUuid("dm"), 2));
  assert.equal(s.otpBudget.rows(T).find((r) => r.keyKind === "CHANNEL")!.failures, 1, "ventana nueva");
});

test("TEST-CNS-157/1317: V6r RIGHTS -> ERR-OT-07 y FAILED; agotar RIGHTS no toca DECISION (P-05); DAYS_30 nunca se reserva (D6)", async () => {
  const s = setup({ budgetMaxFailures: 2 });
  const chain = fixtureUuid("chain-157");
  const ver = fixtureUuid("ver-157");
  await requestRightsOtp(s.otp, T, ver, "REVOCATION", chain, `mgmt:${chain}`);
  const good = s.channel.sent[0]!.code;
  for (let i = 0; i < 2; i += 1) await assert.rejects(() => submitRightsOtp(s.otp, T, ver, "REVOCATION", wrongOf(good), fixtureUuid("dm"), 2), (e) => code(e) === "ERR-OT-02");
  await assert.rejects(() => submitRightsOtp(s.otp, T, ver, "REVOCATION", good, fixtureUuid("dm"), 2), (e) => code(e) === "ERR-OT-07");
  assert.equal((await s.otpRepo.findByRef(T, ver))?.state, "FAILED");
  assert.ok(s.otpBudget.rows(T).every((r) => r.windowKind === "DAY_1" && ["CHANNEL", "CHAIN"].includes(r.keyKind)));
  const inv = await open(s.invitation, "157");
  await requestOtp(s.otp, T, fixtureUuid("ver-157d"), inv, CH);
});

test("TEST-CNS-393/394: V6a: el 3.er LOCKED marca otpExhausted + OTP_BUDGET_EXHAUSTED(INVITATION); el 1.o y 2.o no; V1 posterior -> ERR-OT-06", async () => {
  const s = setup({ maxAttempts: 1, budgetMaxFailures: 1000 });
  const inv = await open(s.invitation, "393");
  for (let i = 0; i < 3; i += 1) {
    const ver = fixtureUuid(`ver-393-${i}`);
    await requestOtp(s.otp, T, ver, inv, CH);
    await assert.rejects(() => submitOtp(s.otp, T, ver, wrongOf(s.channel.sent.at(-1)!.code), fixtureUuid("dm"), 2), (e) => code(e) === "ERR-OT-04");
    assert.equal((await s.invitationRepo.findByRef(T, inv))?.otpExhausted === true, i === 2, `tras el LOCKED ${i + 1}`);
  }
  const ev = s.securityEvents.listAll(T).filter((e) => e.eventType === "OTP_BUDGET_EXHAUSTED");
  assert.equal(ev.length, 1);
  assert.equal((ev[0] as unknown as { keyKind: string }).keyKind, "INVITATION");
  await assert.rejects(() => requestOtp(s.otp, T, fixtureUuid("ver-393-x"), inv, CH), (e) => code(e) === "ERR-OT-06");
});

test("TEST-CNS-152/1321: P-06: reenvio < 60 s -> ERR-OT-09 sin cambiar el codigo; V1 + 2 reenvios caben (D8), el 3.o no; a la hora +1 la ventana reinicia", async () => {
  const s = setup();
  const inv = await open(s.invitation, "152");
  const ver = fixtureUuid("ver-152");
  await requestOtp(s.otp, T, ver, inv, CH);
  const hash0 = (await s.otpRepo.findByRef(T, ver))!.codeHash;
  s.clock.ms += 59_000;
  await assert.rejects(() => resendOtp(s.otp, T, ver), (e) => code(e) === "ERR-OT-09");
  assert.equal((await s.otpRepo.findByRef(T, ver))!.codeHash, hash0);
  s.clock.ms += 1_000;
  await resendOtp(s.otp, T, ver);
  s.clock.ms += 60_000;
  await resendOtp(s.otp, T, ver);
  s.clock.ms += 60_000;
  await assert.rejects(() => resendOtp(s.otp, T, ver), (e) => code(e) === "ERR-OT-09");
  s.clock.ms += 3_600_000;
  const r = await resendOtp(s.otp, T, ver);
  assert.equal(r.sendsInWindow, 1, "ventana reiniciada");
});

test("TEST-CNS-410: orden de locks F-4: invitacion antes que challenge en V2 y V2r", async () => {
  const s = setup();
  const calls: string[] = [];
  const inv = await open(s.invitation, "410");
  const ver = fixtureUuid("ver-410");
  const origInv = s.invitationRepo.findByRefForUpdate.bind(s.invitationRepo);
  s.invitationRepo.findByRefForUpdate = async (t, r) => { calls.push("inv"); return origInv(t, r); };
  const origOtp = s.otpRepo.findByRefForUpdate.bind(s.otpRepo);
  s.otpRepo.findByRefForUpdate = async (t, r) => { calls.push("otp"); return origOtp(t, r); };
  await requestOtp(s.otp, T, ver, inv, CH);
  assert.equal(calls[0], "inv", `V1: ${calls.join(",")}`);
  s.clock.ms += 60_000;
  calls.length = 0;
  await assert.rejects(() => submitOtp(s.otp, T, ver, wrongOf(s.channel.sent[0]!.code), fixtureUuid("dm"), 2));
  assert.ok(calls.indexOf("inv") >= 0 && calls.indexOf("inv") < calls.indexOf("otp"), `submit: ${calls.join(",")}`);
  calls.length = 0;
  await resendOtp(s.otp, T, ver);
  assert.ok(calls.indexOf("inv") >= 0 && calls.indexOf("inv") < calls.indexOf("otp"), `resend: ${calls.join(",")}`);
});

test("TEST-CNS-1319: la subclave HKDF del presupuesto es distinta de la de channelRef", () => {
  const k = randomBytes(32);
  assert.notDeepEqual(deriveOtpBudgetKey(k), deriveOtpChannelRefKey(k));
});
