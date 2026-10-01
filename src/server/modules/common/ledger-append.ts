// Gobierna: CA-124 (PR-C), SEC-CNS-013 P2-3 (expectedSequence obligatorio en el puerto del ledger),
// SEC-CNS-015 P1-1/P2-C, common.spec.yaml ledgerEnvelope (concurrency: expectedSequence),
// revocation.spec.yaml R4 ("una tx con lock y expectedSequence"). Sin cambio de semantica de dominio.
//
// REGLA para toda transicion que DECIDE sobre el estado de un agregado (R2, R3, R4, R8, RH2, RH3,
// R2r/R10, C*): leer la secuencia con `lastLedgerSequence` ANTES de leer/bloquear el estado
// (`findByRefForUpdate`) y pasar `expectedSequence = base + k` explicito a `ledger.append`. Asi, si
// otra unidad avanzo el agregado entre la lectura y el append, el ledger falla con
// LedgerSequenceConflictError en vez de escribir sobre un estado que ya cambio.
//
// `appendNext` (lee la secuencia justo antes del append) SOLO es valido para:
//   1. emisiones que no deciden estado: RECOVERY_TOKEN_ISSUED (RV0);
//   2. modulos que aun NO corren en UnitOfWork y que se migraran en PR-D/PR-E (invitation,
//      otp-challenge, consent-decision, rights-case, tenant-context): hoy sus lecturas de estado
//      no son transaccionales, de modo que no hay "lectura previa" que proteger. AL MIGRARLOS a
//      `inTenant` deben capturar la secuencia como la Revocation (SEC-CNS-015 P1-1, tarea de PR-D).
// R1/R1r (agregado nuevo) pasan `expectedSequence: 0` explicito, sin appendNext.

import type { LedgerEventInput, LedgerPort, LedgerRecord } from "../../ports/ledger.port.ts";

export type LedgerAppendInput = Omit<LedgerEventInput, "expectedSequence">;

/** Ultima sequence del agregado (0 = vacio); mismo criterio que el UNIQUE: (tenant, aggregateId). */
export function lastLedgerSequence(ledger: LedgerPort, tenantId: string, aggregateId: string): Promise<number> {
  return ledger.currentSequence(tenantId, aggregateId);
}

/** Append que lee la secuencia justo antes: ver las restricciones de uso en la cabecera. */
export async function appendNext(ledger: LedgerPort, event: LedgerAppendInput): Promise<LedgerRecord> {
  const expectedSequence = await lastLedgerSequence(ledger, event.tenantId, event.aggregateId);
  return ledger.append({ ...event, expectedSequence });
}
