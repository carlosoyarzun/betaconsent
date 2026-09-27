// Gobierna: OPEN-RV-12, SEC-CNS-013; specs/state-machines/rights-case.spec.yaml.
// TEST-CNS-474 (traceability/test-matrix.csv): checker de runtime que, en un flujo RIGHTS
// end-to-end en memoria, verifica que cada error observado pertenece a errors[] de la
// transición que lo produjo, leído en vivo de la spec con tools/spec-checks/yaml-lite.ts
// (vía loadTransitionErrorsIndex). h01-sm-checker.ts ya verifica de forma estática que
// `errors ⊇ onFail(guards)` en la spec; este test cierra el otro lado: que el CÓDIGO no emite,
// en ningún punto real de ejecución, un DomainError que la spec no haya declarado para esa
// transición (OPEN-RV-12).

import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";

import { DomainError, type DomainErrorCode } from "../../../src/server/modules/common/errors.ts";
import {
  confirmCaseReturnViaHandle,
  expressRevocationIntentInCase,
  type RightsCasePorts,
} from "../../../src/server/modules/rights-case/rights-case.ts";
import { createInMemoryTenantHandleAdapter } from "../../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../src/infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../src/infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../src/infra/adapters/in-memory-ledger.adapter.ts";
import { loadTransitionErrorsIndex } from "../../../tools/spec-checks/transition-errors-index.ts";

const SPEC_DIR = resolve(import.meta.dirname, "../../../specs/state-machines");

interface Observation {
  readonly transitionId: string;
  readonly code: DomainErrorCode;
}

/** Ejecuta `fn`, y si lanza DomainError la registra como observación (transitionId, code);
 * si no lanza, no registra nada. Cualquier otro tipo de excepción se re-lanza (no es del
 * dominio de este checker). */
function observe(transitionId: string, fn: () => void, sink: Observation[]): void {
  try {
    fn();
  } catch (err) {
    if (err instanceof DomainError) {
      sink.push({ transitionId, code: err.code });
      return;
    }
    throw err;
  }
}

test("TEST-CNS-474: todo error observado en un flujo RIGHTS end-to-end pertenece a errors[] de su transición (OPEN-RV-12)", () => {
  const index = loadTransitionErrorsIndex(SPEC_DIR);

  const tenantHandle = createInMemoryTenantHandleAdapter([
    { handle: "handle-A", tenantId: "tenant-1", chainRef: "chain-A", revokedDecisionRef: "decision-A" },
    { handle: "handle-B", tenantId: "tenant-1", chainRef: "chain-B", revokedDecisionRef: "decision-B" },
    // Resuelve a un (tenant,chain) sin caso guardado: dispara ERR-RC-09 (GRD-RC-14 onFail).
    { handle: "handle-orphan", tenantId: "tenant-1", chainRef: "chain-orphan", revokedDecisionRef: "decision-orphan" },
  ]);
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  const revocationRepo = createInMemoryRevocationRepository();
  const ledger = createInMemoryLedgerAdapter();
  const ports: RightsCasePorts = { tenantHandle, rightsCaseRepo, revocationRepo, ledger };

  // Caso A: origin != CHANNEL_UNREACHABLE (GRD-RC-07 no se cumple).
  rightsCaseRepo.save({
    caseRef: "case-A",
    tenantId: "tenant-1",
    chainRef: "chain-A",
    revokedDecisionRef: "decision-A",
    status: "OPEN",
    origin: "LIMIT_REACHED",
  });
  // Caso B: origin = CHANNEL_UNREACHABLE (RC2u sí aplica).
  rightsCaseRepo.save({
    caseRef: "case-B",
    tenantId: "tenant-1",
    chainRef: "chain-B",
    revokedDecisionRef: "decision-B",
    status: "OPEN",
    origin: "CHANNEL_UNREACHABLE",
  });

  const observed: Observation[] = [];

  // RC2u: handle desconocido -> ERR-CM-01 (GRD-CM-01 onFail).
  observe("RC2u", () => confirmCaseReturnViaHandle(ports, "handle-desconocido"), observed);
  // RC2u: handle resuelto pero sin caso ligado -> ERR-RC-09 (GRD-RC-14 onFail).
  observe("RC2u", () => confirmCaseReturnViaHandle(ports, "handle-orphan"), observed);
  // RC2u: caso ligado pero origin != CHANNEL_UNREACHABLE -> ERR-RC-01 (GRD-RC-07 onFail).
  observe("RC2u", () => confirmCaseReturnViaHandle(ports, "handle-A"), observed);
  // RC2u: camino feliz, sin error -> transiciona case-B a CONTACTING.
  observe("RC2u", () => confirmCaseReturnViaHandle(ports, "handle-B"), observed);
  assert.equal(rightsCaseRepo.findByRef("tenant-1", "case-B")?.status, "CONTACTING");
  // RC2u: reintento idempotente (caso ya CONTACTING) -> sin error, sin nuevo evento.
  observe("RC2u", () => confirmCaseReturnViaHandle(ports, "handle-B"), observed);
  assert.equal(ledger.listByAggregate("tenant-1", "RightsCase", "case-B").length, 1);

  // RC3: handle desconocido -> ERR-CM-01.
  observe("RC3", () => expressRevocationIntentInCase(ports, "handle-desconocido"), observed);
  // RC3: handle resuelto pero sin caso ligado -> ERR-RC-09.
  observe("RC3", () => expressRevocationIntentInCase(ports, "handle-orphan"), observed);
  // RC3: camino feliz (case-B ya en CONTACTING) -> sin error; crea Revocation REQUESTED.
  observe("RC3", () => expressRevocationIntentInCase(ports, "handle-B"), observed);
  assert.equal(rightsCaseRepo.findByRef("tenant-1", "case-B")?.status, "IN_VERIFICATION");

  assert.equal(observed.length, 5, `se esperaban 5 observaciones de error, hubo ${observed.length}`);

  for (const { transitionId, code } of observed) {
    assert.ok(
      index.knownTransitionIds().has(transitionId),
      `transición "${transitionId}" no existe en las specs cargadas de ${SPEC_DIR} (typo en el test, no en el código)`,
    );
    assert.ok(
      index.allows(transitionId, code),
      `${code} no está en errors[] de ${transitionId} (declarados: ${index.errorsOf(transitionId).join(", ")}); ` +
        `el código de dominio emite un error que la spec no declaró para esta transición (OPEN-RV-12).`,
    );
  }
});
