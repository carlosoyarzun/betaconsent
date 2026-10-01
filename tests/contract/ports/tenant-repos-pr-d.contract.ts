// Gobierna: CA-124 (PR-D); src/server/ports/{invitation-repository,otp-verification-repository,
// rights-case-repository,enrollment-repository,tenant-resolver,tenant-handle,unit-of-work}.port.ts,
// invitation.spec.yaml, otp-challenge.spec.yaml, rights-case.spec.yaml, tenant-context.spec.yaml,
// common.spec.yaml INV-CM-02/INV-3 (aislamiento, X5) e INV-CM-01 (atomicidad). Suite de contrato
// compartida memoria/Postgres para los repos de tenant de PR-D dentro de una unidad de trabajo.
// TEST-CNS-830..837. Solo datos sinteticos (dominios reservados .invalid).

import assert from "node:assert/strict";

import type { EnrollmentRecord } from "../../../src/server/ports/enrollment-repository.port.ts";
import type { InvitationRecord } from "../../../src/server/ports/invitation-repository.port.ts";
import type { OtpVerificationRecord } from "../../../src/server/ports/otp-verification-repository.port.ts";
import type { RightsCaseRecord } from "../../../src/server/ports/rights-case-repository.port.ts";
import type { TenantHandlePort } from "../../../src/server/ports/tenant-handle.port.ts";
import { hashTenantHandle } from "../../../src/server/ports/tenant-handle.port.ts";
import type { TenantResolverPort } from "../../../src/server/ports/tenant-resolver.port.ts";
import type { UnitOfWorkPort } from "../../../src/server/ports/unit-of-work.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

export interface TenantReposPrDHarness {
  readonly uow: UnitOfWorkPort;
  readonly resolver: TenantResolverPort;
  /** Puerto de handles del adaptador bajo prueba (resolve por handle en claro y por hash). */
  readonly handlePort: TenantHandlePort;
  /** Emite un handle para el tenant (aprovisionamiento; el puerto de dominio es de solo lectura). */
  issueHandle(tenantId: string, seed: { handle: string; chainRef: string; revokedDecisionRef: string }): Promise<void>;
  /** Rota (invalida) el handle del tenant dado. */
  rotateHandle(tenantId: string, handle: string): Promise<void>;
}

export type RegisterReposPrDTest = (name: string, body: (h: TenantReposPrDHarness) => Promise<void>) => void;

const sha = (label: string): string => fixtureUuid(label).replaceAll("-", "").padEnd(64, "0").slice(0, 64);

function invitation(tenantId: string, label: string, extra: Partial<InvitationRecord> = {}): InvitationRecord {
  return {
    invitationRef: fixtureUuid(`inv:${label}`),
    tenantId,
    contextRef: "BETA_2026_01",
    productRef: "LECTORPRO_BETA",
    subjectRef: fixtureUuid(`subj:${label}`),
    state: "DRAFT",
    ...extra,
  };
}

function otp(tenantId: string, label: string, extra: Partial<OtpVerificationRecord> = {}): OtpVerificationRecord {
  return {
    verificationRef: fixtureUuid(`ver:${label}`),
    tenantId,
    scope: "DECISION",
    parentRef: fixtureUuid(`inv:${label}`),
    channelRef: `contract+${label}@example.invalid`,
    codeHash: sha(`code:${label}`),
    attempts: 0,
    expiresAt: new Date("2030-01-01T00:00:00.000Z"),
    state: "CODE_SENT",
    resendCount: 0,
    ...extra,
  };
}

function rightsCase(tenantId: string, label: string, extra: Partial<RightsCaseRecord> = {}): RightsCaseRecord {
  return {
    caseRef: fixtureUuid(`case:${label}`),
    tenantId,
    chainRef: `chain-${label}`,
    revokedDecisionRef: fixtureUuid(`dec:${label}`),
    status: "OPEN",
    ...extra,
  };
}

function enrollment(tenantId: string, label: string, extra: Partial<EnrollmentRecord> = {}): EnrollmentRecord {
  return {
    enrollmentRef: fixtureUuid(`enr:${label}`),
    tenantId,
    subjectRef: fixtureUuid(`subj:${label}`),
    participationRef: fixtureUuid(`part:${label}`),
    state: "ACTIVE",
    ...extra,
  };
}

export function runTenantReposPrDContract(adapterName: string, register: RegisterReposPrDTest): void {
  const name = (id: string, text: string): string => `${id} TenantRepos PR-D contract (${adapterName}): ${text}`;

  register(name("TEST-CNS-830", "InvitationRepository: round-trip con y sin opcionales, upsert de estado, findByRefForUpdate y findActiveBySubject (terminal no cuenta)"), async (h) => {
    const t = fixtureUuid("t830");
    const minimal = invitation(t, "830-a");
    await h.uow.inTenant(t, (tx) => tx.invitationRepo.save(minimal));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findByRef(t, minimal.invitationRef)), minimal);
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findByRefForUpdate(t, minimal.invitationRef)), minimal);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findByRef(t, fixtureUuid("inv-nope"))), null);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findByRefForUpdate(t, fixtureUuid("inv-nope"))), null);
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findActiveBySubject(t, minimal.contextRef, minimal.subjectRef)), minimal);

    const full: InvitationRecord = invitation(t, "830-b", {
      state: "SENT",
      consentVersion: "v1-test",
      expiresAt: new Date("2030-02-03T04:05:06.000Z"),
      recipientChannelRef: "contract+830@example.invalid",
      tokenHash: sha("tok:830-b"),
      boundDecisionMakerRef: fixtureUuid("dm-830"),
      enrollmentRef: fixtureUuid("enr:830"),
      participationRef: fixtureUuid("part:830"),
      reissueOfRef: fixtureUuid("inv:830-prev"),
      recipientBinding: "RECIPIENT_CHANNEL",
    });
    await h.uow.inTenant(t, (tx) => tx.invitationRepo.save(full));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findByRef(t, full.invitationRef)), full);

    // Upsert de estado: la identidad no cambia, el estado y el token si.
    const opened: InvitationRecord = { ...full, state: "OPENED" };
    await h.uow.inTenant(t, (tx) => tx.invitationRepo.save(opened));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findByRef(t, full.invitationRef)), opened);

    // Un estado terminal ya no es "activo" para (contexto, sujeto).
    const done: InvitationRecord = { ...minimal, state: "COMPLETED" };
    await h.uow.inTenant(t, (tx) => tx.invitationRepo.save(done));
    assert.equal(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findActiveBySubject(t, minimal.contextRef, minimal.subjectRef)), null);
    const declined: InvitationRecord = { ...minimal, state: "DECLINED" };
    await h.uow.inTenant(t, (tx) => tx.invitationRepo.save(declined));
    assert.equal(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findActiveBySubject(t, minimal.contextRef, minimal.subjectRef)), null);
  });

  register(name("TEST-CNS-831", "OtpVerificationRepository: round-trip (DECISION y REVOCATION con canal mgmt:), consumedAt, findActiveByParent solo CODE_SENT/NOT_STARTED, findByRefForUpdate"), async (h) => {
    const t = fixtureUuid("t831");
    const a = otp(t, "831-a");
    await h.uow.inTenant(t, (tx) => tx.otpRepo.save(a));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.otpRepo.findByRef(t, a.verificationRef)), a);
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.otpRepo.findByRefForUpdate(t, a.verificationRef)), a);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.otpRepo.findByRef(t, fixtureUuid("ver-nope"))), null);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.otpRepo.findByRefForUpdate(t, fixtureUuid("ver-nope"))), null);
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.otpRepo.findActiveByParent(t, a.parentRef, "DECISION")), a);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.otpRepo.findActiveByParent(t, a.parentRef, "MANAGE")), null, "otro scope no es el mismo padre activo");

    const verified: OtpVerificationRecord = { ...a, attempts: 1, state: "VERIFIED", consumedAt: new Date("2029-12-31T00:00:00.000Z"), resendCount: 2, codeHash: sha("code:831-new") };
    await h.uow.inTenant(t, (tx) => tx.otpRepo.save(verified));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.otpRepo.findByRef(t, a.verificationRef)), verified);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.otpRepo.findActiveByParent(t, a.parentRef, "DECISION")), null, "VERIFIED ya no es activo");
    for (const state of ["EXPIRED", "LOCKED", "FAILED"] as const) {
      await h.uow.inTenant(t, (tx) => tx.otpRepo.save({ ...a, state }));
      assert.equal(await h.uow.inTenant(t, (tx) => tx.otpRepo.findActiveByParent(t, a.parentRef, "DECISION")), null, state);
    }

    const rights = otp(t, "831-r", { scope: "REVOCATION", parentRef: fixtureUuid("chain-831"), channelRef: "mgmt:chain-831" });
    await h.uow.inTenant(t, (tx) => tx.otpRepo.save(rights));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.otpRepo.findActiveByParent(t, fixtureUuid("chain-831"), "REVOCATION")), rights);
  });

  register(name("TEST-CNS-832", "RightsCaseRepository: round-trip con y sin opcionales, upsert de estado, findOpenByChain (RESOLVED/WITHDRAWN no cuentan) y findByRefForUpdate"), async (h) => {
    const t = fixtureUuid("t832");
    const minimal = rightsCase(t, "832-a");
    await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.save(minimal));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.findByRef(t, minimal.caseRef)), minimal);
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.findByRefForUpdate(t, minimal.caseRef)), minimal);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.findByRef(t, fixtureUuid("case-nope"))), null);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.findByRefForUpdate(t, fixtureUuid("case-nope"))), null);
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.findOpenByChain(t, minimal.chainRef, minimal.revokedDecisionRef)), minimal);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.findOpenByChain(t, minimal.chainRef, fixtureUuid("otra-decision"))), null);

    const contacting: RightsCaseRecord = { ...minimal, status: "CONTACTING", origin: "CHANNEL_UNREACHABLE", revocationRef: fixtureUuid("rev832") };
    await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.save(contacting));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.findByRef(t, minimal.caseRef)), contacting);
    for (const status of ["RESOLVED", "WITHDRAWN"] as const) {
      await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.save({ ...contacting, status }));
      assert.equal(await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.findOpenByChain(t, minimal.chainRef, minimal.revokedDecisionRef)), null, status);
    }
  });

  register(name("TEST-CNS-833", "EnrollmentRepository: round-trip, upsert de estado y findActive (CLOSED no cuenta)"), async (h) => {
    const t = fixtureUuid("t833");
    const rec = enrollment(t, "833");
    await h.uow.inTenant(t, (tx) => tx.enrollmentRepo.save(rec));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.enrollmentRepo.findByRef(t, rec.enrollmentRef)), rec);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.enrollmentRepo.findByRef(t, fixtureUuid("enr-nope"))), null);
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.enrollmentRepo.findActive(t, rec.subjectRef, rec.participationRef)), rec);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.enrollmentRepo.findActive(t, rec.subjectRef, fixtureUuid("part-otra"))), null);
    const closed: EnrollmentRecord = { ...rec, state: "CLOSED" };
    await h.uow.inTenant(t, (tx) => tx.enrollmentRepo.save(closed));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.enrollmentRepo.findByRef(t, rec.enrollmentRef)), closed);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.enrollmentRepo.findActive(t, rec.subjectRef, rec.participationRef)), null);
  });

  register(name("TEST-CNS-834", "TenantResolver.byInvitationTokenHash: resuelve (tenant, ref) sin tenant previo desde que la invitacion lleva tokenHash; desconocido o sin token = null; no evalua estado ni expiracion"), async (h) => {
    const ta = fixtureUuid("t834-a");
    const tb = fixtureUuid("t834-b");
    const draft = invitation(ta, "834-draft");
    const sentA = invitation(ta, "834-a", { state: "SENT", tokenHash: sha("tok:834-a"), expiresAt: new Date("2001-01-01T00:00:00.000Z") }); // ya vencida
    const sentB = invitation(tb, "834-b", { state: "SENT", tokenHash: sha("tok:834-b") });
    await h.uow.inTenant(ta, async (tx) => {
      await tx.invitationRepo.save(draft);
      await tx.invitationRepo.save(sentA);
    });
    await h.uow.inTenant(tb, (tx) => tx.invitationRepo.save(sentB));
    assert.deepEqual(await h.resolver.byInvitationTokenHash(sentA.tokenHash as string), { tenantId: ta, invitationRef: sentA.invitationRef });
    assert.deepEqual(await h.resolver.byInvitationTokenHash(sentB.tokenHash as string), { tenantId: tb, invitationRef: sentB.invitationRef });
    assert.equal(await h.resolver.byInvitationTokenHash(sha("tok:834-desconocido")), null);
    assert.equal(await h.resolver.byInvitationTokenHash("no-es-un-hash"), null);
    // Re-guardar con el mismo hash (transiciones posteriores) sigue resolviendo a la misma invitacion.
    await h.uow.inTenant(ta, (tx) => tx.invitationRepo.save({ ...sentA, state: "OPENED" }));
    assert.deepEqual(await h.resolver.byInvitationTokenHash(sentA.tokenHash as string), { tenantId: ta, invitationRef: sentA.invitationRef });
    // La relectura bajo el tenant resuelto es la unica fuente del estado.
    const resolved = await h.resolver.byInvitationTokenHash(sentA.tokenHash as string);
    assert.ok(resolved);
    const reread = await h.uow.inTenant(resolved.tenantId, (tx) => tx.invitationRepo.findByRef(resolved.tenantId, resolved.invitationRef));
    assert.equal(reread?.state, "OPENED");
  });

  register(name("TEST-CNS-835", "TenantResolver.byHandleHash y TenantHandlePort: resuelven (tenant, cadena, decision) por hash o por handle en claro; desconocido o rotado = null"), async (h) => {
    const ta = fixtureUuid("t835-a");
    const tb = fixtureUuid("t835-b");
    const seedA = { handle: "handle-835-a", chainRef: fixtureUuid("chain-835-a"), revokedDecisionRef: fixtureUuid("dec835-a") };
    const seedB = { handle: "handle-835-b", chainRef: fixtureUuid("chain-835-b"), revokedDecisionRef: fixtureUuid("dec835-b") };
    await h.issueHandle(ta, seedA);
    await h.issueHandle(tb, seedB);
    const expectedA = { tenantId: ta, chainRef: seedA.chainRef, revokedDecisionRef: seedA.revokedDecisionRef };
    assert.deepEqual(await h.resolver.byHandleHash(hashTenantHandle(seedA.handle)), expectedA);
    assert.deepEqual(await h.handlePort.resolveByHash(hashTenantHandle(seedA.handle)), expectedA);
    assert.deepEqual(await h.handlePort.resolve(seedA.handle), expectedA);
    assert.equal((await h.resolver.byHandleHash(hashTenantHandle(seedB.handle)))?.tenantId, tb);
    assert.equal(await h.resolver.byHandleHash(sha("handle-desconocido")), null);
    assert.equal(await h.handlePort.resolve("handle-desconocido"), null);
    assert.equal(await h.resolver.byHandleHash("no-es-un-hash"), null);
    // B no puede rotar el handle de A; A si.
    await h.rotateHandle(tb, seedA.handle);
    assert.deepEqual(await h.resolver.byHandleHash(hashTenantHandle(seedA.handle)), expectedA, "rotar desde otro tenant no tiene efecto");
    await h.rotateHandle(ta, seedA.handle);
    assert.equal(await h.resolver.byHandleHash(hashTenantHandle(seedA.handle)), null, "rotado ya no resuelve");
    assert.equal(await h.handlePort.resolve(seedA.handle), null);
    assert.equal((await h.resolver.byHandleHash(hashTenantHandle(seedB.handle)))?.tenantId, tb, "el handle de B sigue vigente");
  });

  register(name("TEST-CNS-836", "aislamiento (INV-3, X5): B no ve invitacion/OTP/caso/enrollment de A (tampoco tras A->B) y escribir con tenantId ajeno se rechaza sin rastro"), async (h) => {
    const ta = fixtureUuid("t836-a");
    const tb = fixtureUuid("t836-b");
    const inv = invitation(ta, "836", { state: "SENT", tokenHash: sha("tok:836") });
    const verification = otp(ta, "836");
    const rcase = rightsCase(ta, "836");
    const enr = enrollment(ta, "836");
    await h.uow.inTenant(ta, async (tx) => {
      await tx.invitationRepo.save(inv);
      await tx.otpRepo.save(verification);
      await tx.rightsCaseRepo.save(rcase);
      await tx.enrollmentRepo.save(enr);
    });
    await h.uow.inTenant(tb, async (tx) => {
      for (const t of [ta, tb]) {
        assert.equal(await tx.invitationRepo.findByRef(t, inv.invitationRef), null);
        assert.equal(await tx.invitationRepo.findByRefForUpdate(t, inv.invitationRef), null);
        assert.equal(await tx.invitationRepo.findActiveBySubject(t, inv.contextRef, inv.subjectRef), null);
        assert.equal(await tx.otpRepo.findByRef(t, verification.verificationRef), null);
        assert.equal(await tx.otpRepo.findByRefForUpdate(t, verification.verificationRef), null);
        assert.equal(await tx.otpRepo.findActiveByParent(t, verification.parentRef, "DECISION"), null);
        assert.equal(await tx.rightsCaseRepo.findByRef(t, rcase.caseRef), null);
        assert.equal(await tx.rightsCaseRepo.findByRefForUpdate(t, rcase.caseRef), null);
        assert.equal(await tx.rightsCaseRepo.findOpenByChain(t, rcase.chainRef, rcase.revokedDecisionRef), null);
        assert.equal(await tx.enrollmentRepo.findByRef(t, enr.enrollmentRef), null);
        assert.equal(await tx.enrollmentRepo.findActive(t, enr.subjectRef, enr.participationRef), null);
      }
    });
    // El hash de A resuelve a A (no a B).
    assert.equal((await h.resolver.byInvitationTokenHash(inv.tokenHash as string))?.tenantId, ta);
    // Escrituras con tenantId falso: cada rechazo en su propia unidad (en Postgres el error aborta la tx).
    await assert.rejects(() => h.uow.inTenant(tb, (tx) => tx.invitationRepo.save(invitation(ta, "836-x", { state: "SENT", tokenHash: sha("tok:836-x") }))));
    await assert.rejects(() => h.uow.inTenant(tb, (tx) => tx.otpRepo.save(otp(ta, "836-x"))));
    await assert.rejects(() => h.uow.inTenant(tb, (tx) => tx.rightsCaseRepo.save(rightsCase(ta, "836-x"))));
    await assert.rejects(() => h.uow.inTenant(tb, (tx) => tx.enrollmentRepo.save(enrollment(ta, "836-x"))));
    // Lo de A intacto y sin rastro de lo rechazado.
    assert.equal(await h.uow.inTenant(ta, (tx) => tx.invitationRepo.findByRef(ta, fixtureUuid("inv:836-x"))), null);
    assert.equal(await h.uow.inTenant(ta, (tx) => tx.otpRepo.findByRef(ta, fixtureUuid("ver:836-x"))), null);
    assert.equal(await h.uow.inTenant(ta, (tx) => tx.rightsCaseRepo.findByRef(ta, fixtureUuid("case:836-x"))), null);
    assert.equal(await h.uow.inTenant(ta, (tx) => tx.enrollmentRepo.findByRef(ta, fixtureUuid("enr:836-x"))), null);
    assert.equal(await h.resolver.byInvitationTokenHash(sha("tok:836-x")), null, "el hash rechazado no quedo registrado");
    assert.ok(await h.uow.inTenant(ta, (tx) => tx.invitationRepo.findByRef(ta, inv.invitationRef)));
  });

  register(name("TEST-CNS-837", "atomicidad: si work lanza no queda nada en invitation, otp, rights_case, enrollment ni en el resolver; el reintento confirma"), async (h) => {
    const t = fixtureUuid("t837");
    const inv = invitation(t, "837", { state: "SENT", tokenHash: sha("tok:837") });
    const verification = otp(t, "837");
    const rcase = rightsCase(t, "837");
    const enr = enrollment(t, "837");
    const boom = new Error("fallo inyectado");
    await assert.rejects(
      () =>
        h.uow.inTenant(t, async (tx) => {
          await tx.invitationRepo.save(inv);
          await tx.otpRepo.save(verification);
          await tx.rightsCaseRepo.save(rcase);
          await tx.enrollmentRepo.save(enr);
          throw boom;
        }),
      (e: unknown) => e === boom,
    );
    assert.equal(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findByRef(t, inv.invitationRef)), null);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.otpRepo.findByRef(t, verification.verificationRef)), null);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.rightsCaseRepo.findByRef(t, rcase.caseRef)), null);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.enrollmentRepo.findByRef(t, enr.enrollmentRef)), null);
    assert.equal(await h.resolver.byInvitationTokenHash(inv.tokenHash as string), null, "el registro del resolver tambien se revirtio");

    await h.uow.inTenant(t, async (tx) => {
      await tx.invitationRepo.save(inv);
      await tx.otpRepo.save(verification);
      await tx.rightsCaseRepo.save(rcase);
      await tx.enrollmentRepo.save(enr);
    });
    assert.ok(await h.uow.inTenant(t, (tx) => tx.invitationRepo.findByRef(t, inv.invitationRef)));
    assert.deepEqual(await h.resolver.byInvitationTokenHash(inv.tokenHash as string), { tenantId: t, invitationRef: inv.invitationRef });
  });
}
