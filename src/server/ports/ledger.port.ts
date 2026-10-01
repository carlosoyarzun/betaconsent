// Gobierna: specs/state-machines/common.spec.yaml `ledgerEnvelope` (ADR-002 §2, §8).
// Puerto (ADR-001 §11): el dominio solo conoce esta interfaz; la tabla real
// integrity.audit_event vive detrás de un adaptador en src/infra/adapters/**.

import type { ActorRole, ActorType, Environment, TenantId } from "../modules/common/types.ts";

/** Evento a registrar. El dominio nunca pasa PII (INV-CM-05); solo refs opacas y enums. */
export interface LedgerEventInput {
  readonly eventType: string;
  readonly tenantId: TenantId;
  readonly aggregateType: string;
  readonly aggregateId: string;
  readonly actorType: ActorType;
  readonly actorRole?: ActorRole;
  /** Refs opacas de principales ejecutores (RH2/RH2v/RH3, GRD-CM-07 con recordedActor fijo). */
  readonly recordedByRef?: string;
  readonly cosignedByRef?: string;
  readonly payload: Readonly<Record<string, unknown>>;
  /** Clave de idempotencia declarada por la transición (SM-CNS-001 §7 / GRD-CM-08). */
  readonly idempotencyKey?: string;
  /**
   * Control optimista de concurrencia (diseño CA-124 §3 "P2 del ledger", SEC-CNS-013 P2-3,
   * revocation.spec R4). OBLIGATORIO: el append solo procede si la última `sequence` del
   * agregado es exactamente `expectedSequence` (0 = agregado vacío) y registra el evento con
   * `sequence = expectedSequence + 1`; si no, lanza `LedgerSequenceConflictError` sin escribir.
   * Un append deduplicado por `idempotencyKey` devuelve el registro existente antes de evaluar
   * este control. Los flujos que no necesitan decidir sobre la secuencia usan `appendNext`
   * (src/server/modules/common/ledger-append.ts), que la lee dentro de la misma unidad de trabajo.
   */
  readonly expectedSequence: number;
}

/** El agregado avanzó desde `expectedSequence` (UNIQUE(tenant_id, aggregate_id, sequence)). */
export class LedgerSequenceConflictError extends Error {
  readonly expectedSequence: number;
  readonly actualSequence: number;
  constructor(expectedSequence: number, actualSequence: number) {
    super(`ledger sequence conflict: expected ${expectedSequence}, actual ${actualSequence}`);
    this.name = "LedgerSequenceConflictError";
    this.expectedSequence = expectedSequence;
    this.actualSequence = actualSequence;
  }
}

export interface LedgerRecord extends Omit<LedgerEventInput, "expectedSequence"> {
  readonly sequence: number;
  readonly occurredAt: Date;
  /** ADR-002 §2, §8: en IT0 siempre LOCAL/DEV/STAGING, evidentiary=false, dataClass=SYNTHETIC. */
  readonly environment: Environment;
  readonly evidentiary: false;
  readonly dataClass: "SYNTHETIC";
}

export interface LedgerPort {
  /**
   * Append-only (INV-CM-01). Si `idempotencyKey` coincide con un evento ya registrado del
   * mismo agregado, devuelve el registro existente sin duplicar (GRD-CM-08).
   */
  append(event: LedgerEventInput): Promise<LedgerRecord>;
  listByAggregate(tenantId: TenantId, aggregateType: string, aggregateId: string): Promise<readonly LedgerRecord[]>;
}
