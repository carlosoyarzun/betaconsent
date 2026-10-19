// Gobierna: plan v2 H1-04. Suite de contrato de los puertos: los MISMOS casos corren contra el adaptador PG (Postgres temporal) y el de memoria.
// origen (patrón): tests/contract/ports/*.contract.ts@9345b78 (función que recibe una fábrica y registra los casos).
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { test } from "node:test";

import { generateInvitationToken } from "../../src/domain/crypto.ts";
import { DomainError } from "../../src/domain/errors.ts";
import type { DomainErrorCode } from "../../src/domain/errors.ts";
import type { Ports } from "../../src/ports/index.ts";

export interface ContractEnv {
  readonly ports: Ports;
  /** Hora actual del entorno en ms (reloj falso en memoria; Date.now en PG). */
  now(): number;
  /** Deja pasar `ms`: avanza el reloj falso (memoria) o duerme (PG). */
  advance(ms: number): Promise<void>;
  /** Vence el OTP indicado (la base fija P-02 = 10 min, sin parámetro del llamador). */
  expireOtp(verificationRef: string): Promise<void>;
}

const uniq = (): string => randomBytes(5).toString("hex");
const DM = "dm-contract-test";
const TEXT_HASH = createHash("sha256").update("texto-sintetico").digest("hex");

async function rejectsWith(p: Promise<unknown>, code: DomainErrorCode): Promise<void> {
  await assert.rejects(p, (e: unknown) => e instanceof DomainError && e.code === code, `se esperaba DomainError ${code}`);
}
const wrong = (code: string): string => (code === "000000" ? "111111" : "000000");

export function runPortsContract(label: string, makeEnv: () => Promise<ContractEnv>): void {
  async function openedInvitation(env: ContractEnv): Promise<{ inv: string; student: string; tokenHash: string }> {
    const student = `stu-${uniq()}`;
    const { invitationRef } = await env.ports.invitations.import({ studentRef: student, studentFirstName: "Ana", guardianEmail: `g-${uniq()}@example.test`, batchRef: "batch-001" });
    const { tokenHash } = generateInvitationToken();
    await env.ports.invitations.armToken({ invitationRef, tokenHash, expiresAt: new Date(env.now() + 9 * 60_000), consentVersion: "v-test" });
    const opened = await env.ports.invitations.openByTokenHash(tokenHash);
    assert.equal(opened?.state, "OPENED");
    return { inv: invitationRef, student, tokenHash };
  }
  async function verifiedDecision(env: ContractEnv): Promise<{ inv: string; student: string; ver: string }> {
    const { inv, student } = await openedInvitation(env);
    const otp = await env.ports.otp.issue({ parentRef: inv, scope: "DECISION" });
    assert.equal((await env.ports.otp.verify({ verificationRef: otp.verificationRef, code: otp.code, decisionMakerRef: DM })).outcome, "VERIFIED");
    return { inv, student, ver: otp.verificationRef };
  }

  test(`[${label}] import idempotente, arm y open (open no consume; token desconocido = null)`, async () => {
    const env = await makeEnv();
    const student = `stu-${uniq()}`;
    const input = { studentRef: student, studentFirstName: "Ana", guardianEmail: "g@example.test", batchRef: "batch-001" };
    const a = await env.ports.invitations.import(input);
    const b = await env.ports.invitations.import(input);
    assert.equal(a.created, true);
    assert.deepEqual(b, { invitationRef: a.invitationRef, created: false });
    const { tokenHash } = generateInvitationToken();
    await rejectsWith(env.ports.invitations.armToken({ invitationRef: a.invitationRef, tokenHash, expiresAt: new Date(env.now() - 1000), consentVersion: "v" }), "TOKEN_EXPIRY_IN_PAST");
    await rejectsWith(env.ports.invitations.armToken({ invitationRef: "inv-no-existe", tokenHash, expiresAt: new Date(env.now() + 60_000), consentVersion: "v" }), "INVITATION_NOT_FOUND");
    await env.ports.invitations.armToken({ invitationRef: a.invitationRef, tokenHash, expiresAt: new Date(env.now() + 60_000), consentVersion: "v-test" });
    for (let i = 0; i < 2; i++) {
      const o = await env.ports.invitations.openByTokenHash(tokenHash);
      assert.deepEqual(o, { invitationRef: a.invitationRef, studentRef: student, consentVersion: "v-test", state: "OPENED" });
    }
    assert.equal(await env.ports.invitations.openByTokenHash(generateInvitationToken().tokenHash), null);
    // Abierta ya no se puede rearmar (solo READY/SENT).
    await rejectsWith(env.ports.invitations.armToken({ invitationRef: a.invitationRef, tokenHash: generateInvitationToken().tokenHash, expiresAt: new Date(env.now() + 60_000), consentVersion: "v" }), "INVITATION_NOT_ARMABLE");
    // Rotación en SENT: el token anterior queda muerto.
    const b2 = await env.ports.invitations.import({ studentRef: `stu-${uniq()}`, studentFirstName: "Ana", guardianEmail: "g2@example.test", batchRef: "batch-001" });
    const t1 = generateInvitationToken().tokenHash;
    const t2 = generateInvitationToken().tokenHash;
    for (const h of [t1, t2]) await env.ports.invitations.armToken({ invitationRef: b2.invitationRef, tokenHash: h, expiresAt: new Date(env.now() + 60_000), consentVersion: "v-test" });
    assert.equal(await env.ports.invitations.openByTokenHash(t1), null);
    assert.equal((await env.ports.invitations.openByTokenHash(t2))?.invitationRef, b2.invitationRef);
  });

  test(`[${label}] issue -> verify: código malo, luego bueno; OTP de otro padre no existe; el padre debe ser elegible`, async () => {
    const env = await makeEnv();
    await rejectsWith(env.ports.otp.issue({ parentRef: "inv-inexistente", scope: "DECISION" }), "PARENT_NOT_ELIGIBLE");
    const { inv } = await openedInvitation(env);
    const otp = await env.ports.otp.issue({ parentRef: inv, scope: "DECISION" });
    assert.match(otp.code, /^\d{6}$/);
    assert.deepEqual(await env.ports.otp.verify({ verificationRef: otp.verificationRef, code: wrong(otp.code), decisionMakerRef: DM }), { outcome: "WRONG_CODE", attemptsLeft: 4 });
    assert.deepEqual(await env.ports.otp.verify({ verificationRef: otp.verificationRef, code: otp.code, decisionMakerRef: DM }), { outcome: "VERIFIED", attemptsLeft: 3 });
    assert.equal((await env.ports.otp.verify({ verificationRef: otp.verificationRef, code: otp.code, decisionMakerRef: DM })).outcome, "NOT_ACTIVE");
    assert.equal((await env.ports.otp.verify({ verificationRef: "ver-no-existe", code: "123456", decisionMakerRef: DM })).outcome, "NOT_ACTIVE");
    assert.equal((await env.ports.decisions.getPageState(inv))?.invitationState, "VERIFIED");
  });

  test(`[${label}] 5 fallos -> LOCKED; el código correcto después ya no sirve`, async () => {
    const env = await makeEnv();
    const { inv } = await openedInvitation(env);
    const otp = await env.ports.otp.issue({ parentRef: inv, scope: "DECISION" });
    const outs: string[] = [];
    for (let i = 0; i < 5; i++) outs.push((await env.ports.otp.verify({ verificationRef: otp.verificationRef, code: wrong(otp.code), decisionMakerRef: DM })).outcome);
    assert.deepEqual(outs, ["WRONG_CODE", "WRONG_CODE", "WRONG_CODE", "WRONG_CODE", "LOCKED"]);
    assert.equal((await env.ports.otp.verify({ verificationRef: otp.verificationRef, code: otp.code, decisionMakerRef: DM })).outcome, "NOT_ACTIVE");
  });

  test(`[${label}] OTP vencido -> EXPIRED; reenvío antes de 60 s -> OTP_RESEND_TOO_SOON; reenvío tras 60 s expira el anterior`, async () => {
    const env = await makeEnv();
    const { inv } = await openedInvitation(env);
    const first = await env.ports.otp.issue({ parentRef: inv, scope: "DECISION" });
    assert.ok(Math.abs(first.expiresAt.getTime() - env.now() - 10 * 60_000) < 5_000, "P-02: 10 min fijados por la base");
    await rejectsWith(env.ports.otp.resend({ parentRef: inv, scope: "DECISION" }), "OTP_RESEND_TOO_SOON");
    await env.expireOtp(first.verificationRef);
    assert.equal((await env.ports.otp.verify({ verificationRef: first.verificationRef, code: first.code, decisionMakerRef: DM })).outcome, "EXPIRED");
    assert.equal((await env.ports.otp.verify({ verificationRef: first.verificationRef, code: first.code, decisionMakerRef: DM })).outcome, "NOT_ACTIVE");
    // Un OTP vivo por padre: un envío nuevo (>= 60 s después) deja el anterior inservible. Solo se comprueba en memoria con reloj falso (en PG tardaría 60 s).
    if (env.advance.name === "advanceFake") {
      await env.advance(61_000);
      const a = await env.ports.otp.issue({ parentRef: inv, scope: "DECISION" });
      await env.advance(61_000);
      const b = await env.ports.otp.resend({ parentRef: inv, scope: "DECISION" });
      assert.equal((await env.ports.otp.verify({ verificationRef: a.verificationRef, code: a.code, decisionMakerRef: DM })).outcome, "NOT_ACTIVE");
      assert.equal((await env.ports.otp.verify({ verificationRef: b.verificationRef, code: b.code, decisionMakerRef: DM })).outcome, "VERIFIED");
    }
  });

  test(`[${label}] record: sin OTP verificado falla; misma clave idempotente; otra clave ALREADY_DECIDED`, async () => {
    const env = await makeEnv();
    const { inv } = await openedInvitation(env);
    const base = { invitationRef: inv, outcome: "GRANTED" as const, consentVersion: "v-test", consentTextHash: TEXT_HASH };
    const unverified = await env.ports.otp.issue({ parentRef: inv, scope: "DECISION" });
    await rejectsWith(env.ports.decisions.record({ ...base, verificationRef: unverified.verificationRef, idempotencyKey: "idem-key-0001" }), "VERIFICATION_REQUIRED");
    await env.ports.otp.verify({ verificationRef: unverified.verificationRef, code: unverified.code, decisionMakerRef: DM });
    await rejectsWith(env.ports.decisions.record({ ...base, verificationRef: unverified.verificationRef, idempotencyKey: "corta" }), "INVALID_IDEMPOTENCY_KEY");
    const d1 = await env.ports.decisions.record({ ...base, verificationRef: unverified.verificationRef, idempotencyKey: "idem-key-0001" });
    assert.deepEqual([d1.state, d1.deduped], ["GRANTED", false]);
    const d2 = await env.ports.decisions.record({ ...base, verificationRef: unverified.verificationRef, idempotencyKey: "idem-key-0001" });
    assert.deepEqual([d2.consentId, d2.deduped], [d1.consentId, true]);
    await rejectsWith(env.ports.decisions.record({ ...base, verificationRef: unverified.verificationRef, idempotencyKey: "idem-key-0002" }), "ALREADY_DECIDED");
    const page = await env.ports.decisions.getPageState(inv);
    assert.deepEqual(page, { invitationState: "COMPLETED", consentVersion: "v-test", decision: { consentId: d1.consentId, state: "GRANTED" } });
    assert.equal(await env.ports.decisions.getPageState("inv-no-existe"), null);
  });

  test(`[${label}] DECLINED: NOT_AUTHORIZED y no revocable`, async () => {
    const env = await makeEnv();
    const { inv, student, ver } = await verifiedDecision(env);
    const d = await env.ports.decisions.record({ invitationRef: inv, verificationRef: ver, outcome: "DECLINED", consentVersion: "v-test", consentTextHash: TEXT_HASH, idempotencyKey: "idem-decline-1" });
    assert.equal(d.state, "DECLINED");
    assert.equal((await env.ports.authorization.byStudentRef(student)).status, "NOT_AUTHORIZED");
    await rejectsWith(env.ports.revocations.revoke({ consentId: d.consentId, verificationRef: ver, idempotencyKey: "rev-key-0009" }), "NOT_REVOCABLE_DECLINED");
    assert.equal((await env.ports.authorization.byStudentRef(`nunca-visto-${uniq()}`)).status, "NOT_AUTHORIZED");
  });

  test(`[${label}] revoke: AUTHORIZED -> NOT_AUTHORIZED, idempotente, ALREADY_REVOKED, exige OTP de revocación`, async () => {
    const env = await makeEnv();
    const { inv, student, ver } = await verifiedDecision(env);
    assert.deepEqual((await env.ports.authorization.byStudentRef(student)).status, "NOT_AUTHORIZED"); // aún sin decisión
    const d = await env.ports.decisions.record({ invitationRef: inv, verificationRef: ver, outcome: "GRANTED", consentVersion: "v-test", consentTextHash: TEXT_HASH, idempotencyKey: "idem-grant-01" });
    const auth = await env.ports.authorization.byStudentRef(student);
    assert.deepEqual([auth.status, auth.decisionRef], ["AUTHORIZED", d.consentId]);

    const manage = await env.ports.revocations.getManageState(d.consentId);
    assert.deepEqual([manage?.state, manage?.decisionMakerRef], ["GRANTED", DM]);
    // El OTP de decisión no sirve para revocar.
    await rejectsWith(env.ports.revocations.revoke({ consentId: d.consentId, verificationRef: ver, idempotencyKey: "rev-key-0001" }), "VERIFICATION_REQUIRED");
    const rotp = await env.ports.otp.issue({ parentRef: d.consentId, scope: "REVOCATION" });
    await rejectsWith(env.ports.revocations.revoke({ consentId: d.consentId, verificationRef: rotp.verificationRef, idempotencyKey: "rev-key-0001" }), "VERIFICATION_REQUIRED"); // sin verificar
    assert.equal((await env.ports.otp.verify({ verificationRef: rotp.verificationRef, code: rotp.code, decisionMakerRef: DM })).outcome, "VERIFIED");
    const rev = await env.ports.revocations.revoke({ consentId: d.consentId, verificationRef: rotp.verificationRef, idempotencyKey: "rev-key-0001" });
    assert.equal(rev.deduped, false);
    const after = await env.ports.authorization.byStudentRef(student);
    assert.deepEqual([after.status, after.decisionRef], ["NOT_AUTHORIZED", null]);
    assert.deepEqual(await env.ports.revocations.revoke({ consentId: d.consentId, verificationRef: rotp.verificationRef, idempotencyKey: "rev-key-0001" }), { revocationRef: rev.revocationRef, deduped: true });
    await rejectsWith(env.ports.revocations.revoke({ consentId: d.consentId, verificationRef: rotp.verificationRef, idempotencyKey: "rev-key-0002" }), "ALREADY_REVOKED");
    assert.equal((await env.ports.revocations.getManageState(d.consentId))?.state, "REVOKED");
    assert.equal(await env.ports.revocations.getManageState("con-no-existe"), null);
    await rejectsWith(env.ports.revocations.revoke({ consentId: "con-no-existe", verificationRef: rotp.verificationRef, idempotencyKey: "rev-key-0003" }), "DECISION_NOT_FOUND");
  });

  test(`[${label}] F-SB-03: reimportar tras decidir no crea otra invitación ni cambia el correo`, async () => {
    const env = await makeEnv();
    const { inv, student, ver } = await verifiedDecision(env);
    await env.ports.decisions.record({ invitationRef: inv, verificationRef: ver, outcome: "GRANTED", consentVersion: "v-test", consentTextHash: TEXT_HASH, idempotencyKey: "idem-reimp-01" });
    const again = await env.ports.invitations.import({ studentRef: student, studentFirstName: "Ana", guardianEmail: "otro@example.test", batchRef: "batch-002" });
    assert.deepEqual(again, { invitationRef: inv, created: false });
  });

  test(`[${label}] F-SB-05: purposes solo admite códigos de la lista cerrada`, async () => {
    const env = await makeEnv();
    const { inv, ver } = await verifiedDecision(env);
    const base = { invitationRef: inv, verificationRef: ver, outcome: "GRANTED" as const, consentVersion: "v-test", consentTextHash: TEXT_HASH };
    await rejectsWith(env.ports.decisions.record({ ...base, idempotencyKey: "idem-purp-001", purposes: [1 as unknown as string] }), "INVALID_PURPOSES");
    await rejectsWith(env.ports.decisions.record({ ...base, idempotencyKey: "idem-purp-002", purposes: ["OTRO_FIN"] }), "INVALID_PURPOSES");
    await rejectsWith(env.ports.decisions.record({ ...base, idempotencyKey: "idem-purp-003", purposes: ["AUDIO_RECORDING", "AUDIO_RECORDING"] }), "INVALID_PURPOSES");
    const d = await env.ports.decisions.record({ ...base, idempotencyKey: "idem-purp-004", purposes: ["STUDY_PARTICIPATION", "AUDIO_RECORDING"] });
    assert.equal(d.state, "GRANTED");
  });

  test(`[${label}] F-SB-04: con la verificación vencida se puede reemitir el OTP de decisión (solo con reloj falso)`, async () => {
    const env = await makeEnv();
    if (env.advance.name !== "advanceFake") return; // en PG el paso del tiempo se cubre en tests/integration/functions.test.ts
    const { inv, ver } = await verifiedDecision(env);
    await env.advance(10 * 60_000 + 1000);
    const base = { invitationRef: inv, outcome: "GRANTED" as const, consentVersion: "v-test", consentTextHash: TEXT_HASH };
    await rejectsWith(env.ports.decisions.record({ ...base, verificationRef: ver, idempotencyKey: "idem-win-0001" }), "VERIFICATION_REQUIRED");
    const o = await env.ports.otp.issue({ parentRef: inv, scope: "DECISION" });
    assert.equal((await env.ports.otp.verify({ verificationRef: o.verificationRef, code: o.code, decisionMakerRef: DM })).outcome, "VERIFIED");
    assert.equal((await env.ports.decisions.record({ ...base, verificationRef: o.verificationRef, idempotencyKey: "idem-win-0001" })).state, "GRANTED");
  });
}
