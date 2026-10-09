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
// `appendNext` (lee la secuencia justo antes del append) SOLO es valido para emisiones que no deciden
// estado de un agregado (lista final, SEC-CNS-015 P2-E, PR-D):
//   las emisiones de siembra de tenant-context/seed.ts (agregados nuevos de fixtures, sin decision de estado).
// (RECOVERY_TOKEN_ISSUED y OTP_* ya no van al ledger: ops.security_event, SEC-CNS-021 PR-2. Para otp-challenge la valla de V3 es el lock de fila de
// app.otp_verification con expectedSequence 0.)
// Todo lo demas (invitation I2-I7, otp-challenge V3, consent-decision C1-C5, rights-case
// RC1/RC2u/RC3/RC4-6 y enrollment EN0) corre en `uow.inTenant` con lock de fila + base previa.
// Transiciones que emiten VARIOS eventos del mismo agregado (consent-decision C3/C5) usan
// `sequencedAppender(ledger, tenantId, aggregateId, base)`: cada append declara base + k.
// R1/R1r/I1/EN0/V1/RC1 (agregado nuevo) pasan `expectedSequence: 0` explicito, sin appendNext.

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

/**
 * Appends secuenciados de UN agregado dentro de una tx que ya capturo `base` ANTES del lock de fila:
 * el k-esimo append declara `expectedSequence = base + k`. Si un append deduplicado por idempotencyKey
 * devuelve un registro previo, la siguiente esperada no retrocede (max con la sequence devuelta).
 */
export function sequencedAppender(
  ledger: LedgerPort,
  base: number,
): { append(event: LedgerAppendInput): Promise<LedgerRecord> } {
  let expected = base;
  return {
    async append(event) {
      const record = await ledger.append({ ...event, expectedSequence: expected });
      expected = Math.max(expected, record.sequence);
      return record;
    },
  };
}
