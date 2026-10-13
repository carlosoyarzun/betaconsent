// Gobierna: alineacion dominio<->spec confirmada por Carlos 2026-10-13 (F-A10-29; no decide LD-03): R8 solo desde {REQUESTED, VERIFIED, CONFIRMED},
// R3/R3r nunca confirma una verificacion HUMAN_ASSISTED (la via es RH3, cuatro ojos) y GRD-RV-02 exige decision GRANTED de la MISMA cadena en R1.
// Escenarios compartidos por el adaptador in-memory (TEST-CNS-1379) y Postgres (TEST-CNS-1380): ambos deben comportarse igual. SYNTHETIC ONLY.

import assert from "node:assert/strict";

import { DomainError } from "../../src/server/modules/common/errors.ts";
import { confirmRevocation, requestRevocation, withdrawRevocation, type RevocationPorts } from "../../src/server/modules/revocation/revocation.ts";
import type { RevocationRecord } from "../../src/server/ports/revocation-repository.port.ts";
import { syntheticDecision } from "./synthetic-decision.ts";
import { fixtureUuid } from "./uuid-fixture.ts";

const code = (c: string) => (e: unknown) => e instanceof DomainError && e.code === c;

/** `seedDecision` / `seedRevocation`: siembra del adaptador bajo prueba (in-memory: repos; Postgres: save LOCAL). */
export interface FA1029Env {
  readonly ports: RevocationPorts;
  readonly seedDecision: (decision: ReturnType<typeof syntheticDecision>) => Promise<void>;
}

export async function runFA1029Scenarios(env: FA1029Env, T: string, label: string): Promise<void> {
  const { ports } = env;
  const rev = (name: string, extra: Partial<RevocationRecord>): RevocationRecord => ({
    revocationRef: fixtureUuid(`r-${label}-${name}`),
    tenantId: T,
    chainRef: fixtureUuid(`chain-${label}`),
    revokedDecisionRef: fixtureUuid(`d-${label}-${name}`),
    status: "REQUESTED",
    ...extra,
  });

  // R8: desde estados posteriores a CONFIRMED (incluidos DOWNSTREAM_PENDING/DELIVERED/COMPLETED) no procede; desde los tres del grafo si.
  for (const status of ["APPLIED", "DOWNSTREAM_PENDING", "DELIVERED", "COMPLETED"] as const) {
    const r = rev(`r8-${status}`, { status, verifiedAuthPath: "OTP" });
    await ports.uow.inTenant(T, (tx) => tx.revocationRepo.save(r));
    await assert.rejects(() => withdrawRevocation(ports, T, r.revocationRef), code("ERR-CM-06"), `R8 desde ${status}`);
    assert.equal((await ports.uow.inTenant(T, (tx) => tx.revocationRepo.findByRef(T, r.revocationRef)))?.status, status, `${status} intacta`);
  }
  const ok = rev("r8-ok", { status: "CONFIRMED", verifiedAuthPath: "OTP" });
  await ports.uow.inTenant(T, (tx) => tx.revocationRepo.save(ok));
  assert.equal((await withdrawRevocation(ports, T, ok.revocationRef)).status, "FAILED");

  // R3: una verificacion HUMAN_ASSISTED no se confirma por confirm (R3/R3r): ERR-CM-06 y sin cambios; RH3 es la via.
  const ha = rev("r3-ha", { status: "VERIFIED", caseRef: fixtureUuid(`case-${label}`), verifiedAuthPath: "RECOVERY", verifiedRecoveryMethod: "HUMAN_ASSISTED" });
  await ports.uow.inTenant(T, (tx) => tx.revocationRepo.save(ha));
  await assert.rejects(() => confirmRevocation(ports, T, ha.revocationRef), code("ERR-CM-06"), "R3 sobre HUMAN_ASSISTED");
  assert.equal((await ports.uow.inTenant(T, (tx) => tx.revocationRepo.findByRef(T, ha.revocationRef)))?.status, "VERIFIED");

  // R1 / GRD-RV-02: decision ausente, de otra cadena o no GRANTED => ERR-RV-02 sin fila; GRANTED de la misma cadena => REQUESTED.
  const chain = fixtureUuid(`chain-r1-${label}`);
  const refOf = (n: string): string => fixtureUuid(`d-r1-${label}-${n}`);
  await assert.rejects(() => requestRevocation(ports, T, { revocationRef: fixtureUuid(`r1-absent-${label}`), chainRef: chain, revokedDecisionRef: refOf("absent") }), code("ERR-RV-02"), "decision ausente");
  await env.seedDecision({ ...syntheticDecision(T, refOf("otra")), chainRef: fixtureUuid(`otra-${label}`) });
  await assert.rejects(() => requestRevocation(ports, T, { revocationRef: fixtureUuid(`r1-otra-${label}`), chainRef: chain, revokedDecisionRef: refOf("otra") }), code("ERR-RV-02"), "otra cadena");
  await env.seedDecision({ ...syntheticDecision(T, refOf("declined")), chainRef: chain, state: "DECLINED" });
  await assert.rejects(() => requestRevocation(ports, T, { revocationRef: fixtureUuid(`r1-declined-${label}`), chainRef: chain, revokedDecisionRef: refOf("declined") }), code("ERR-RV-02"), "DECLINED");
  for (const n of ["absent", "otra", "declined"]) {
    assert.equal(await ports.uow.inTenant(T, (tx) => tx.revocationRepo.findByRef(T, fixtureUuid(`r1-${n}-${label}`))), null, `sin fila (${n})`);
  }
  await env.seedDecision({ ...syntheticDecision(T, refOf("ok")), chainRef: chain });
  assert.equal((await requestRevocation(ports, T, { revocationRef: fixtureUuid(`r1-ok-${label}`), chainRef: chain, revokedDecisionRef: refOf("ok") })).status, "REQUESTED");
}
