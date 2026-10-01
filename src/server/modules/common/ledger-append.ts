// Gobierna: CA-124 (PR-C), SEC-CNS-013 P2-3 (expectedSequence obligatorio en el puerto del ledger),
// common.spec.yaml ledgerEnvelope (concurrency: expectedSequence). Sin cambio de semántica de dominio.
//
// Los flujos que hasta ahora dependían de la numeración implícita del adaptador (R1, R2, R3, R8,
// invitación, OTP, derechos, ...) ahora deben declarar la secuencia esperada. `appendNext` la lee
// del propio agregado dentro de la MISMA unidad de trabajo y la pasa como `expectedSequence`: el
// resultado es el mismo que antes, pero la verificación y el `sequence = expectedSequence + 1`
// los hace el adaptador (UNIQUE(tenant_id, aggregate_id, sequence) ante la carrera). Las
// transiciones que deciden sobre una secuencia concreta (R4) la pasan explícitamente.

import type { LedgerEventInput, LedgerPort, LedgerRecord } from "../../ports/ledger.port.ts";

export type LedgerAppendInput = Omit<LedgerEventInput, "expectedSequence">;

export async function lastLedgerSequence(
  ledger: LedgerPort,
  tenantId: string,
  aggregateType: string,
  aggregateId: string,
): Promise<number> {
  const history = await ledger.listByAggregate(tenantId, aggregateType, aggregateId);
  return history.reduce((max, record) => Math.max(max, record.sequence), 0);
}

export async function appendNext(ledger: LedgerPort, event: LedgerAppendInput): Promise<LedgerRecord> {
  const expectedSequence = await lastLedgerSequence(ledger, event.tenantId, event.aggregateType, event.aggregateId);
  return ledger.append({ ...event, expectedSequence });
}
