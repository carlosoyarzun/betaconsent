// Gobierna: src/server/ports/otp-budget.port.ts (SEC-CNS-021 PR-4; CFG-OT-BUDGET, GRD-OT-03). Adaptador in-memory IT0 LOCAL/CI: MISMA semantica que
// ops.otp_budget (ventana fija desde el primer fallo, reserva atomica por clave, el acierto revierte). Participante del UnitOfWork in-memory
// (journal): un rollback de la unidad deshace tambien la reserva. Solo guarda el HMAC de la clave y contadores (cero PII).

import type { OtpBudgetKey, OtpBudgetPort } from "../../server/ports/otp-budget.port.ts";
import { JournaledMap, TX_JOURNAL, type TxParticipant } from "./in-memory-tx.ts";

interface BudgetRow {
  readonly windowStart: number;
  readonly expiresAt: number;
  readonly failures: number;
  readonly keyKind: string;
  readonly windowKind: string;
}

export interface InMemoryOtpBudget extends OtpBudgetPort, TxParticipant {
  /** Solo verificacion en tests: filas de un tenant (sin la clave en claro: solo su HMAC). */
  rows(tenantId: string): ReadonlyArray<{ keyKind: string; windowKind: string; keyHmac: string; failures: number; windowStart: Date; expiresAt: Date }>;
}

const rowKey = (tenantId: string, key: OtpBudgetKey): string =>
  [tenantId, key.scopeClass, key.keyKind, key.keyHmac, key.windowKind].join("\u0000");

export function createInMemoryOtpBudget(): InMemoryOtpBudget {
  const store = new JournaledMap<string, BudgetRow>();
  return {
    [TX_JOURNAL](journal) {
      store.journal = journal;
    },
    rows(tenantId) {
      const out: Array<{ keyKind: string; windowKind: string; keyHmac: string; failures: number; windowStart: Date; expiresAt: Date }> = [];
      for (const [k, row] of store) {
        const parts = k.split("\u0000");
        if (parts[0] === tenantId) {
          out.push({ keyKind: row.keyKind, windowKind: row.windowKind, keyHmac: parts[3] as string, failures: row.failures, windowStart: new Date(row.windowStart), expiresAt: new Date(row.expiresAt) });
        }
      }
      return out;
    },
    async findExhausted(tenantId, keys, at, limit) {
      for (const key of keys) {
        const row = store.get(rowKey(tenantId, key));
        if (row && row.expiresAt > at.getTime() && row.failures >= limit) return key;
      }
      return null;
    },
    async reserveFailure(tenantId, keys, at, windowMs, limit) {
      const now = at.getTime();
      for (const key of keys) {
        const k = rowKey(tenantId, key);
        const row = store.get(k);
        if (!row || row.expiresAt <= now) {
          store.set(k, { windowStart: now, expiresAt: now + windowMs, failures: 1, keyKind: key.keyKind, windowKind: key.windowKind });
        } else if (row.failures < limit) {
          store.set(k, { ...row, failures: row.failures + 1 });
        } else {
          return key;
        }
      }
      return null;
    },
    async releaseFailure(tenantId, keys) {
      for (const key of keys) {
        const k = rowKey(tenantId, key);
        const row = store.get(k);
        if (row && row.failures > 0) store.set(k, { ...row, failures: row.failures - 1 });
      }
    },
  };
}
