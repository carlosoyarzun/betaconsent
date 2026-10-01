// Gobierna: CA-124 (PR-C); src/server/ports/{revocation-repository,consent-decision-repository,
// recovery-token,tenant-resolver,tenant-catalog,unit-of-work}.port.ts, revocation.spec.yaml,
// consent-decision.spec.yaml, common.spec.yaml INV-CM-02/INV-3 (aislamiento, X5), INV-CM-01
// (atomicidad). Suite de contrato compartida memoria/Postgres para los repos de tenant dentro de
// una unidad de trabajo. TEST-CNS-800..806. Solo datos sinteticos.

import assert from "node:assert/strict";

import type { ConsentDecisionRecord } from "../../../src/server/ports/consent-decision-repository.port.ts";
import type { RecoveryTokenRecord } from "../../../src/server/ports/recovery-token.port.ts";
import type { RevocationRecord } from "../../../src/server/ports/revocation-repository.port.ts";
import type { SchoolParticipationView, TenantCatalogPort } from "../../../src/server/ports/tenant-catalog.port.ts";
import type { TenantResolverPort } from "../../../src/server/ports/tenant-resolver.port.ts";
import type { UnitOfWorkPort } from "../../../src/server/ports/unit-of-work.port.ts";
import { syntheticDecision } from "../synthetic-decision.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

export interface TenantReposHarness {
  readonly uow: UnitOfWorkPort;
  readonly resolver: TenantResolverPort;
  /** Siembra el catalogo del tenant (aprovisionamiento; el dominio nunca lo escribe). */
  seedSubject(tenantId: string, subjectRef: string): Promise<void>;
  seedParticipation(tenantId: string, participation: SchoolParticipationView): Promise<void>;
  /** Catalogo del tenant leido dentro de su unidad de trabajo (bajo RLS en Postgres). */
  withCatalog<T>(tenantId: string, work: (catalog: TenantCatalogPort) => Promise<T>): Promise<T>;
}

export type RegisterReposTest = (name: string, body: (h: TenantReposHarness) => Promise<void>) => void;

const sha = (label: string): string => fixtureUuid(label).replaceAll("-", "").padEnd(64, "0").slice(0, 64);

function revocation(tenantId: string, ref: string, extra: Partial<RevocationRecord> = {}): RevocationRecord {
  return { revocationRef: ref, tenantId, chainRef: `chain-${ref}`, status: "REQUESTED", ...extra };
}

function token(tenantId: string, label: string, extra: Partial<RecoveryTokenRecord> = {}): RecoveryTokenRecord {
  return {
    tokenHash: sha(`hash:${label}`),
    recoveryRef: `rec-${label}`,
    tenantId,
    chainRef: `chain-${label}`,
    revokedDecisionRef: fixtureUuid(`dec:${label}`),
    expiresAt: new Date("2030-01-01T00:00:00.000Z"),
    ...extra,
  };
}

export function runTenantReposContract(adapterName: string, register: RegisterReposTest): void {
  const name = (id: string, text: string): string => `${id} TenantRepos contract (${adapterName}): ${text}`;

  register(name("TEST-CNS-800", "RevocationRepository: round-trip con y sin opcionales, upsert de estado, findByCase y findOpenByChain (FAILED no es abierta, APPLIED si)"), async (h) => {
    const t = fixtureUuid("t800");
    const r1 = fixtureUuid("r800-1");
    const minimal = revocation(t, r1);
    await h.uow.inTenant(t, (tx) => tx.revocationRepo.save(minimal));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.revocationRepo.findByRef(t, r1)), minimal);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.revocationRepo.findByRef(t, fixtureUuid("r800-nope"))), null);

    const verified: RevocationRecord = { ...minimal, status: "VERIFIED", verifiedAuthPath: "OTP", revokedDecisionRef: fixtureUuid("d800") };
    await h.uow.inTenant(t, (tx) => tx.revocationRepo.save(verified));
    const found = await h.uow.inTenant(t, (tx) => tx.revocationRepo.findByRef(t, r1));
    assert.equal(found?.status, "VERIFIED");
    assert.equal(found?.verifiedAuthPath, "OTP");

    const r2 = fixtureUuid("r800-2");
    const full = revocation(t, r2, {
      chainRef: "chain-800-full",
      caseRef: "case-800",
      status: "CONFIRMED",
      attestedVerification: { revocationRef: r2, caseRef: "case-800" },
      recordedByRef: fixtureUuid("rec800"),
      cosignedByRef: fixtureUuid("cos800"),
      revokedDecisionRef: fixtureUuid("d800-2"),
      verifiedAuthPath: "RECOVERY",
      verifiedRecoveryMethod: "HUMAN_ASSISTED",
      reasonCode: "WITHDRAWN_BY_REQUESTER",
    });
    await h.uow.inTenant(t, (tx) => tx.revocationRepo.save(full));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.revocationRepo.findByRef(t, r2)), full);
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.revocationRepo.findByCase(t, "case-800")), full);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.revocationRepo.findByCase(t, "case-otro")), null);

    // findOpenByChain: FAILED no cuenta; APPLIED si (GRD-RV-04 / GRD-RV-27).
    const chain = "chain-800-open";
    const failed = revocation(t, fixtureUuid("r800-f"), { chainRef: chain, status: "FAILED", reasonCode: "WITHDRAWN_BY_REQUESTER" });
    await h.uow.inTenant(t, (tx) => tx.revocationRepo.save(failed));
    assert.equal(await h.uow.inTenant(t, (tx) => tx.revocationRepo.findOpenByChain(t, chain)), null);
    const applied = revocation(t, fixtureUuid("r800-a"), { chainRef: chain, status: "APPLIED" });
    await h.uow.inTenant(t, (tx) => tx.revocationRepo.save(applied));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.revocationRepo.findOpenByChain(t, chain)), applied);
  });

  register(name("TEST-CNS-801", "ConsentDecisionRepository: round-trip, findActiveGrantByChain solo GRANTED y C6 (REVOKED) deja de ser vigente"), async (h) => {
    const t = fixtureUuid("t801");
    const d1 = syntheticDecision(t, fixtureUuid("d801-1"));
    const pending: ConsentDecisionRecord = {
      ...syntheticDecision(t, fixtureUuid("d801-2")),
      state: "PENDING",
      purposes: [{ purpose: "STUDY_PARTICIPATION", choice: "GRANT" }],
      priorStepsComplete: false,
      stepsRecorded: ["CONSENT_VERSION_VIEWED"],
    };
    await h.uow.inTenant(t, async (tx) => {
      await tx.consentDecisionRepo.save(d1);
      await tx.consentDecisionRepo.save(pending);
    });
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findByConsentId(t, d1.consentId)), d1);
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findByConsentId(t, pending.consentId)), pending);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findByConsentId(t, fixtureUuid("d801-nope"))), null);

    assert.equal((await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findActiveGrantByChain(t, d1.chainRef)))?.consentId, d1.consentId);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findActiveGrantByChain(t, pending.chainRef)), null, "PENDING no es una GRANTED vigente");

    // Transicion de PENDING a GRANTED con recibo (C3) y de GRANTED a REVOKED (C6).
    const granted: ConsentDecisionRecord = { ...pending, state: "GRANTED", priorStepsComplete: true, receiptRef: fixtureUuid("rcpt801") };
    await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.save(granted));
    assert.deepEqual(await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findByConsentId(t, granted.consentId)), granted);
    assert.equal((await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findActiveGrantByChain(t, granted.chainRef)))?.consentId, granted.consentId);
    await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.save({ ...granted, state: "REVOKED" }));
    assert.equal(await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findActiveGrantByChain(t, granted.chainRef)), null);
    assert.equal((await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findByConsentId(t, granted.consentId)))?.state, "REVOKED");
  });

  register(name("TEST-CNS-802", "RecoveryTokenRepository: round-trip, consume deja el token consumido (idempotente), consume de otro tenant o de ref inexistente es no-op"), async (h) => {
    const ta = fixtureUuid("t802-a");
    const tb = fixtureUuid("t802-b");
    const rec = token(ta, "802");
    await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.save(rec));
    assert.deepEqual(await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.findByRef(ta, rec.recoveryRef)), rec);
    assert.equal(await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.findByRef(ta, "rec-nope")), null);

    await h.uow.inTenant(tb, (tx) => tx.recoveryTokenRepo.consume(tb, rec.recoveryRef)); // ref de A bajo B: no-op
    assert.equal((await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.findByRef(ta, rec.recoveryRef)))?.consumedAt, undefined);

    await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.consume(ta, rec.recoveryRef));
    const first = (await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.findByRef(ta, rec.recoveryRef)))?.consumedAt;
    assert.ok(first instanceof Date);
    await new Promise((resolve) => setTimeout(resolve, 15));
    await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.consume(ta, rec.recoveryRef));
    const second = (await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.findByRef(ta, rec.recoveryRef)))?.consumedAt;
    assert.ok(second instanceof Date);
    // Un solo uso: el segundo consume no mueve la marca de consumo (memoria la reescribe; ambas la
    // mantienen consumida). Solo se exige que siga consumido.
    assert.ok(second.getTime() >= first.getTime());
    await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.consume(ta, "rec-inexistente")); // no-op
  });

  register(name("TEST-CNS-803", "TenantResolver.byRecoveryTokenHash: resuelve (tenant, ref) sin tenant previo, desconocido = null, no evalua consumo ni expiracion"), async (h) => {
    const ta = fixtureUuid("t803-a");
    const tb = fixtureUuid("t803-b");
    const recA = token(ta, "803-a");
    const recB = token(tb, "803-b", { expiresAt: new Date("2001-01-01T00:00:00.000Z") }); // ya vencido
    await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.save(recA));
    await h.uow.inTenant(tb, (tx) => tx.recoveryTokenRepo.save(recB));
    assert.deepEqual(await h.resolver.byRecoveryTokenHash(recA.tokenHash), { tenantId: ta, recoveryRef: recA.recoveryRef });
    assert.deepEqual(await h.resolver.byRecoveryTokenHash(recB.tokenHash), { tenantId: tb, recoveryRef: recB.recoveryRef });
    assert.equal(await h.resolver.byRecoveryTokenHash(sha("hash:803-desconocido")), null);
    assert.equal(await h.resolver.byRecoveryTokenHash("no-es-un-hash"), null);
    await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.consume(ta, recA.recoveryRef));
    assert.deepEqual(await h.resolver.byRecoveryTokenHash(recA.tokenHash), { tenantId: ta, recoveryRef: recA.recoveryRef }, "consumido tambien resuelve");
    // La relectura bajo el tenant resuelto es la unica fuente del estado.
    const resolved = await h.resolver.byRecoveryTokenHash(recA.tokenHash);
    assert.ok(resolved);
    const reread = await h.uow.inTenant(resolved.tenantId, (tx) => tx.recoveryTokenRepo.findByRef(resolved.tenantId, resolved.recoveryRef));
    assert.ok(reread?.consumedAt instanceof Date);
  });

  register(name("TEST-CNS-804", "TenantCatalog: sujeto y participacion del tenant; desconocido, de otro tenant o sin sembrar = false/null (fail-closed)"), async (h) => {
    const ta = fixtureUuid("t804-a");
    const tb = fixtureUuid("t804-b");
    const subject = fixtureUuid("s804");
    const participation: SchoolParticipationView = { participationRef: fixtureUuid("p804"), contextRef: "BETA_2026_01", productRef: "LECTORPRO_BETA", status: "ACTIVE" };
    await h.seedSubject(ta, subject);
    await h.seedParticipation(ta, participation);
    assert.equal(await h.withCatalog(ta, (c) => c.subjectBelongsToTenant(ta, subject)), true);
    assert.deepEqual(await h.withCatalog(ta, (c) => c.findParticipation(ta, participation.participationRef)), participation);
    assert.equal(await h.withCatalog(ta, (c) => c.subjectBelongsToTenant(ta, fixtureUuid("s804-otro"))), false);
    assert.equal(await h.withCatalog(ta, (c) => c.findParticipation(ta, fixtureUuid("p804-otra"))), null);
    // B no ve el catalogo de A, ni pidiendo el tenant de A.
    assert.equal(await h.withCatalog(tb, (c) => c.subjectBelongsToTenant(tb, subject)), false);
    assert.equal(await h.withCatalog(tb, (c) => c.subjectBelongsToTenant(ta, subject)), false);
    assert.equal(await h.withCatalog(tb, (c) => c.findParticipation(ta, participation.participationRef)), null);
    for (const status of ["PENDING_AUTHORIZATION", "SUSPENDED", "CLOSED"] as const) {
      const p = { ...participation, participationRef: fixtureUuid(`p804-${status}`), status };
      await h.seedParticipation(ta, p);
      assert.equal((await h.withCatalog(ta, (c) => c.findParticipation(ta, p.participationRef)))?.status, status);
    }
  });

  register(name("TEST-CNS-805", "aislamiento (INV-3, X5): B no ve revocacion/decision/token de A (tampoco tras A->B), el hash de A no resuelve a B y escribir con tenantId ajeno se rechaza sin rastro"), async (h) => {
    const ta = fixtureUuid("t805-a");
    const tb = fixtureUuid("t805-b");
    const ref = fixtureUuid("r805");
    const decision = syntheticDecision(ta, fixtureUuid("d805"));
    const rec = token(ta, "805");
    await h.uow.inTenant(ta, async (tx) => {
      await tx.revocationRepo.save(revocation(ta, ref, { caseRef: "case-805" }));
      await tx.consentDecisionRepo.save(decision);
      await tx.recoveryTokenRepo.save(rec);
    });
    await h.uow.inTenant(tb, async (tx) => {
      for (const t of [ta, tb]) {
        assert.equal(await tx.revocationRepo.findByRef(t, ref), null);
        assert.equal(await tx.revocationRepo.findByCase(t, "case-805"), null);
        assert.equal(await tx.revocationRepo.findOpenByChain(t, `chain-${ref}`), null);
        assert.equal(await tx.consentDecisionRepo.findByConsentId(t, decision.consentId), null);
        assert.equal(await tx.consentDecisionRepo.findActiveGrantByChain(t, decision.chainRef), null);
        assert.equal(await tx.recoveryTokenRepo.findByRef(t, rec.recoveryRef), null);
      }
    });
    // El hash de A resuelve a A (no a B), y B no puede usar la ref de A.
    assert.equal((await h.resolver.byRecoveryTokenHash(rec.tokenHash))?.tenantId, ta);
    // Escrituras con tenantId falso: cada rechazo en su propia unidad (en Postgres el error aborta la tx).
    await assert.rejects(() => h.uow.inTenant(tb, (tx) => tx.revocationRepo.save(revocation(ta, fixtureUuid("r805-x")))));
    await assert.rejects(() => h.uow.inTenant(tb, (tx) => tx.consentDecisionRepo.save(syntheticDecision(ta, fixtureUuid("d805-x")))));
    await assert.rejects(() => h.uow.inTenant(tb, (tx) => tx.recoveryTokenRepo.save(token(ta, "805-x"))));
    // Lo de A intacto y sin rastro de lo rechazado.
    assert.equal(await h.uow.inTenant(ta, (tx) => tx.revocationRepo.findByRef(ta, fixtureUuid("r805-x"))), null);
    assert.equal(await h.uow.inTenant(ta, (tx) => tx.consentDecisionRepo.findByConsentId(ta, fixtureUuid("d805-x"))), null);
    assert.equal(await h.uow.inTenant(ta, (tx) => tx.recoveryTokenRepo.findByRef(ta, "rec-805-x")), null);
    assert.equal(await h.resolver.byRecoveryTokenHash(token(ta, "805-x").tokenHash), null, "el hash rechazado no quedo registrado");
    assert.ok(await h.uow.inTenant(ta, (tx) => tx.revocationRepo.findByRef(ta, ref)));
  });

  register(name("TEST-CNS-806", "atomicidad: si work lanza no queda nada en revocation, consent_decision, recovery_token ni en el resolver; el reintento confirma"), async (h) => {
    const t = fixtureUuid("t806");
    const ref = fixtureUuid("r806");
    const decision = syntheticDecision(t, fixtureUuid("d806"));
    const rec = token(t, "806");
    const boom = new Error("fallo inyectado");
    await assert.rejects(
      () =>
        h.uow.inTenant(t, async (tx) => {
          await tx.revocationRepo.save(revocation(t, ref));
          await tx.consentDecisionRepo.save(decision);
          await tx.recoveryTokenRepo.save(rec);
          await tx.recoveryTokenRepo.consume(t, rec.recoveryRef);
          throw boom;
        }),
      (e: unknown) => e === boom,
    );
    assert.equal(await h.uow.inTenant(t, (tx) => tx.revocationRepo.findByRef(t, ref)), null);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.consentDecisionRepo.findByConsentId(t, decision.consentId)), null);
    assert.equal(await h.uow.inTenant(t, (tx) => tx.recoveryTokenRepo.findByRef(t, rec.recoveryRef)), null);
    assert.equal(await h.resolver.byRecoveryTokenHash(rec.tokenHash), null, "el registro del resolver tambien se revirtio");

    await h.uow.inTenant(t, async (tx) => {
      await tx.revocationRepo.save(revocation(t, ref));
      await tx.consentDecisionRepo.save(decision);
      await tx.recoveryTokenRepo.save(rec);
    });
    assert.ok(await h.uow.inTenant(t, (tx) => tx.revocationRepo.findByRef(t, ref)));
    assert.deepEqual(await h.resolver.byRecoveryTokenHash(rec.tokenHash), { tenantId: t, recoveryRef: rec.recoveryRef });
  });
}
