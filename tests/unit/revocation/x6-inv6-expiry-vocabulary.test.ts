// Gobierna: DEC-BR-014 rev. 8 §3 X6 (CA-128) y revocation.spec.yaml:
//  - INV-6 (TEST-CNS-965): "D5: con tenant SUSPENDED, SchoolParticipation SUSPENDED o CLOSED, Enrollment
//    TRANSFERRED/LEFT_SCHOOL, contexto PAUSED y OTP agotado/LOCKED, una revocación verificada llega a
//    APPLIED y emite consent.revoked." (+ eligibility_to_revoke != eligibility_to_participate, INV-CM-06).
//  - INV-10 / DEC-BR-017 §0.3, §5 (TEST-CNS-966): "No hay transición a FAILED salvo R8 (y R8h, deshabilitada);
//    ningún timer cierra una Revocation ni un RightsCase"; la expiración nunca produce FAILED.
//  - Vocabulario DEC-BR-017 §6 (TEST-CNS-967): eventos emitidos en la lista blanca y en `events:` de la spec.
// SYNTHETIC ONLY.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { LEDGER_EVENT_TYPES } from "../../../src/server/modules/common/ledger-event-types.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import {
  confirmRevocation,
  hashRecoveryToken,
  issueRecoveryLinkBearer,
  requestRevocation,
  revokeWithRecoveryLinkByHash,
  verifyRevocationOtp,
  withdrawRevocation,
} from "../../../src/server/modules/revocation/revocation.ts";
import { createInMemoryTenantCatalogAdapter } from "../../../src/infra/adapters/in-memory-tenant-catalog.adapter.ts";
import { createInMemoryEnrollmentRepository } from "../../../src/infra/adapters/in-memory-enrollment-repository.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../src/infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import { createInMemoryEligibilityAdapter } from "../../../src/infra/adapters/in-memory-eligibility.adapter.ts";
import type { OutboxRecord } from "../../../src/server/ports/outbox.port.ts";
import { parseYaml } from "../../../tools/spec-checks/yaml-lite.ts";
import { assertConsentRevokedOutbox } from "../../contract/outbox-evidence.ts";
import { validateLedgerEventPayload } from "../../contract/schema-lite.ts";
import { syntheticDecision, SYNTHETIC_CONTEXT_REF } from "../../contract/synthetic-decision.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { completeDownstream, makeX6Env, REVOCATION_PATHS, revokeVia } from "../../contract/x6-revocation-scenarios.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const T = fixtureUuid("tenant-x6-965");

for (const path of REVOCATION_PATHS) {
  test(`TEST-CNS-965 (INV-6, ${path}): con participación SUSPENDED/CLOSED, enrollment cerrado, inelegible para emitir y OTP LOCKED agotado, la revocación llega a APPLIED y encola consent.revoked`, async () => {
    const tenantCatalog = createInMemoryTenantCatalogAdapter();
    const enrollmentRepo = createInMemoryEnrollmentRepository();
    const otpRepo = createInMemoryOtpVerificationRepository();
    const eligibility = createInMemoryEligibilityAdapter(true);
    const label = `965-${path}`;
    const chain = `chain-${label}`;

    // Condiciones de INV-6 que el modelo IT0 representa: SchoolParticipation SUSPENDED y CLOSED,
    // Enrollment cerrado (TRANSFERRED/LEFT_SCHOOL colapsan en CLOSED en IT0), OTP LOCKED y agotado,
    // y la fórmula de elegibilidad para PARTICIPAR en false (tenant SUSPENDED / contexto PAUSED).
    for (const [ref, status] of [["part-susp", "SUSPENDED"], ["part-closed", "CLOSED"]] as const) {
      tenantCatalog.seedParticipation(T, { participationRef: fixtureUuid(`${label}-${ref}`), contextRef: SYNTHETIC_CONTEXT_REF, productRef: "LECTORPRO_BETA", status });
      await enrollmentRepo.save({ enrollmentRef: fixtureUuid(`${label}-enr-${ref}`), tenantId: T, subjectRef: fixtureUuid(`${label}-sub`), participationRef: fixtureUuid(`${label}-${ref}`), state: "CLOSED" });
    }
    await otpRepo.save({
      verificationRef: fixtureUuid(`${label}-otp`), tenantId: T, scope: "REVOCATION", parentRef: chain, channelRef: "chan-synthetic",
      codeHash: "0".repeat(64), attempts: 99, expiresAt: new Date("2000-01-01T00:00:00Z"), state: "LOCKED", resendCount: 5,
    });
    eligibility.setEligible(T, SYNTHETIC_CONTEXT_REF, "LECTORPRO_BETA", false);
    assert.equal(await eligibility.isEligibleForIssuance(T, SYNTHETIC_CONTEXT_REF, "LECTORPRO_BETA"), false, "eligibility_to_participate = false");

    const env = makeX6Env({ extra: { tenantCatalog, enrollmentRepo, otpRepo } });
    const { revocationRef, decisionRef } = await revokeVia(env, T, label, path);
    assert.equal((await env.ports.revocationRepo.findByRef(T, revocationRef))?.status, "APPLIED", "eligibility_to_revoke != eligibility_to_participate");
    assert.equal((await env.ports.consentDecisionRepo.findByConsentId(T, decisionRef))?.state, "REVOKED");
    const outbox = (env.ports.outbox as unknown as { enqueued: readonly OutboxRecord[] }).enqueued;
    assert.equal(outbox.length, 1);
    assertConsentRevokedOutbox(outbox, await env.ports.ledger.listByAggregate(T, "Revocation", revocationRef), {
      tenantId: T,
      revocationRef,
      decision: (await env.ports.consentDecisionRepo.findByConsentId(T, decisionRef))!,
    });
    // El OTP LOCKED sigue LOCKED (INV-8: la revocación no toca el presupuesto/intentos).
    assert.equal((await otpRepo.findByRef(T, fixtureUuid(`${label}-otp`)))?.state, "LOCKED");
    assert.equal((await otpRepo.findByRef(T, fixtureUuid(`${label}-otp`)))?.attempts, 99);
    // INV-6 cubre también el tramo downstream: sigue hasta COMPLETED con el tenant inelegible.
    await completeDownstream(env, T, revocationRef, label);
  });
}

test("TEST-CNS-965b (INV-6, estructural): el dominio de revocación no depende de elegibilidad, catálogo, enrollment ni presupuesto OTP (tenant SUSPENDED, contexto PAUSED, TRANSFERRED/LEFT_SCHOOL no existen como estado en IT0)", () => {
  for (const file of ["src/server/modules/revocation/revocation.ts", "src/server/modules/revocation/downstream.ts"]) {
    const source = readFileSync(resolve(REPO, file), "utf8");
    for (const forbidden of ["eligibility.port", "tenant-catalog.port", "enrollment-repository.port", "otp-verification-repository.port", "tenantCatalog", "enrollmentRepo", "otpRepo", "isEligibleForIssuance"]) {
      assert.equal(source.includes(forbidden), false, `${file} no debe usar ${forbidden}`);
    }
  }
});

test("TEST-CNS-966 (INV-10): la expiración nunca produce FAILED en las vías OTP -> enlace -> caso humano; solo R8 (retiro explícito) escribe FAILED", async () => {
  // Vía OTP: OTP EXPIRED (otp-challenge) y R2 nunca llega; la Revocation queda REQUESTED, no FAILED.
  {
    const otpRepo = createInMemoryOtpVerificationRepository();
    const env = makeX6Env({ extra: { otpRepo } });
    const D = fixtureUuid("d966-otp");
    const R = fixtureUuid("r966-otp");
    await env.ports.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: fixtureUuid("chain-966-otp") });
    await requestRevocation(env.ports, T, { revocationRef: R, chainRef: fixtureUuid("chain-966-otp"), revokedDecisionRef: D });
    await otpRepo.save({ verificationRef: fixtureUuid("otp966"), tenantId: T, scope: "REVOCATION", parentRef: fixtureUuid("chain-966-otp"), channelRef: "chan-synthetic", codeHash: "0".repeat(64), attempts: 0, expiresAt: new Date(0), state: "EXPIRED", resendCount: 0 });
    assert.equal((await env.ports.revocationRepo.findByRef(T, R))?.status, "REQUESTED");
  }
  {
    const env = makeX6Env({ recoveryTtlMs: 1 });
    const D = fixtureUuid("d966-link");
    await env.ports.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: fixtureUuid("chain-966-link") });
    await issueRecoveryLinkBearer(env.ports, T, fixtureUuid("chain-966-link"), D, "REQUESTER_ASKED");
    const token = env.sink.sent[0]!.recoveryPath.replace("/r/", "");
    await new Promise((r) => setTimeout(r, 10));
    const outcome = await revokeWithRecoveryLinkByHash(env.ports, hashRecoveryToken(token));
    assert.equal(outcome.kind, "UNIFORM", "ERR-RV-05 uniforme");
    assert.equal(await env.ports.revocationRepo.findOpenByChain(T, fixtureUuid("chain-966-link")), null, "un /r/ expirado no crea Revocation ni emite nada");
    const linkEvents = (await env.ports.ledger.listByAggregate(T, "Revocation", fixtureUuid("chain-966-link"))).map((e) => e.eventType);
    assert.deepEqual(linkEvents, ["RECOVERY_TOKEN_ISSUED"], "solo la emisión del token; ni REVOCATION_* ni FAILED");
  }
  // Vía caso humano: una Revocation con caseRef abierta no la cierra ningún temporizador (INV-10): no hay
  // función de dominio que escriba FAILED salvo withdrawRevocation (R8); tripwire estático.
  const failedWriters: string[] = [];
  for (const file of ["revocation/revocation.ts", "revocation/downstream.ts", "rights-case/rights-case.ts", "otp-challenge/otp-challenge.ts"]) {
    const src = readFileSync(resolve(REPO, "src/server/modules", file), "utf8");
    const count = (src.match(/status: "FAILED"/g) ?? []).length + (src.match(/eventType: "REVOCATION_FAILED"/g) ?? []).length;
    if (count > 0) failedWriters.push(`${file}:${count}`);
  }
  assert.deepEqual(failedWriters, ["revocation/revocation.ts:2"], "solo withdrawRevocation (R8): status + evento");
  assert.equal(typeof withdrawRevocation, "function");
});

test("TEST-CNS-967 (DEC-BR-017 §6): todos los eventos de revocación/recuperación/caso humano/downstream están en la lista blanca y en `events:` de la spec, con payload dentro del contrato", async () => {
  const spec = parseYaml(readFileSync(resolve(REPO, "specs/state-machines/revocation.spec.yaml"), "utf8")) as { events: Array<{ id: string; stream: string; payload?: string[] }> };
  const specEvents = new Map(spec.events.filter((e) => e.stream === "LEDGER").map((e) => [e.id, e.payload ?? []] as const));
  const emitted = new Map<string, Set<string>>();
  for (const path of REVOCATION_PATHS) {
    const env = makeX6Env();
    const { revocationRef } = await revokeVia(env, T, `967-${path}`, path);
    await completeDownstream(env, T, revocationRef, `967-${path}`);
    for (const e of await env.ports.ledger.listByAggregate(T, "Revocation", revocationRef)) {
      const keys = emitted.get(e.eventType) ?? new Set<string>();
      for (const k of Object.keys(e.payload)) keys.add(k);
      emitted.set(e.eventType, keys);
      const result = validateLedgerEventPayload(e.eventType, e.payload);
      assert.ok(result.ok, `${e.eventType} fuera de su $def: ${result.errors.join(";")}`);
      if (e.eventType === "REVOCATION_VERIFIED" && (e.payload as { recoveryMethod?: string }).recoveryMethod === "HUMAN_ASSISTED") {
        // RH2 con doble control (GRD-RV-09): el $def exige verifiedByRef y secondApproverRef; schema-lite no evalúa ese if/then,
        // así que se comprueba explícitamente (y TEST-CNS-980 prueba que el emisor falla sin ellos).
        const pl = e.payload as { verifiedByRef?: string; secondApproverRef?: string };
        assert.ok(pl.verifiedByRef && pl.secondApproverRef && pl.verifiedByRef !== pl.secondApproverRef, "RH2: dos principals distintos");
      }
    }
  }
  // R8 (retiro) también emite vocabulario de §6.
  {
    const env = makeX6Env();
    const D = fixtureUuid("d967-r8");
    await env.ports.consentDecisionRepo.save({ ...syntheticDecision(T, D), chainRef: fixtureUuid("chain-967-r8") });
    const R = fixtureUuid("r967-r8");
    await requestRevocation(env.ports, T, { revocationRef: R, chainRef: fixtureUuid("chain-967-r8"), revokedDecisionRef: D });
    await withdrawRevocation(env.ports, T, R);
    for (const e of await env.ports.ledger.listByAggregate(T, "Revocation", R)) {
      const keys = emitted.get(e.eventType) ?? new Set<string>();
      for (const k of Object.keys(e.payload)) keys.add(k);
      emitted.set(e.eventType, keys);
    }
  }
  const allowed = new Set<string>(LEDGER_EVENT_TYPES);
  for (const [eventType, keys] of emitted) {
    assert.ok(allowed.has(eventType), `${eventType} fuera de la lista blanca`);
    const declared = specEvents.get(eventType);
    // RECEIPT_CREATED y CONSENT_REVOKED los declara consent-decision.spec; el resto, revocation.spec §6.
    if (eventType !== "RECEIPT_CREATED" && eventType !== "CONSENT_REVOKED") {
      assert.ok(declared, `${eventType} no está en events: de revocation.spec (DEC-BR-017 §6)`);
      for (const k of keys) assert.ok(declared!.includes(k), `${eventType}.${k} no está en el payload declarado ${JSON.stringify(declared)}`);
    }
  }
  for (const required of ["REVOCATION_REQUESTED", "REVOCATION_VERIFIED", "REVOCATION_CONFIRMED", "CONSENT_REVOKED", "RECEIPT_CREATED", "REVOCATION_DOWNSTREAM_EMITTED", "REVOCATION_DELIVERED", "DOWNSTREAM_ERASURE_ATTESTED", "REVOCATION_FAILED"]) {
    assert.ok(emitted.has(required), `no se ejercitó ${required}`);
  }
  void DomainError; void confirmRevocation; void verifyRevocationOtp;
});
