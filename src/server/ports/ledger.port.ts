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
}

export interface LedgerRecord extends LedgerEventInput {
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
  append(event: LedgerEventInput): LedgerRecord;
  listByAggregate(tenantId: TenantId, aggregateType: string, aggregateId: string): readonly LedgerRecord[];
}
