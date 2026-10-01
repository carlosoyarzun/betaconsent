// Gobierna: src/server/ports/unit-of-work.port.ts, CA-124 (diseño postgres-design.md rev. 2 §5).
// Adaptador in-memory IT0 de UnitOfWorkPort. Semántica todo-o-nada: si `work` lanza, se deshace
// cada escritura hecha a través de los puertos del tenant (journal de in-memory-tx.ts) y el
// error se propaga sin envolver. Las unidades de trabajo se serializan (una a la vez, como el
// lock de R4 en Postgres) y no se admite anidar `inTenant`.
//
// Aislamiento por tenant (INV-CM-02, INV-3, X5): los puertos que recibe `work` están ligados al
// `tenantId` de `inTenant`. Espejan el comportamiento bajo RLS: una lectura de OTRO tenant
// devuelve vacío (0 filas) y una escritura con tenantId ajeno lanza TenantScopeViolationError
// (WITH CHECK). Cero PII, sin red.

import { AsyncLocalStorage } from "node:async_hooks";

import type { TenantId } from "../../server/modules/common/types.ts";
import type { ConsentDecisionRepositoryPort } from "../../server/ports/consent-decision-repository.port.ts";
import type { EnrollmentRepositoryPort } from "../../server/ports/enrollment-repository.port.ts";
import type { InvitationRepositoryPort } from "../../server/ports/invitation-repository.port.ts";
import type { LedgerPort } from "../../server/ports/ledger.port.ts";
import type { OtpVerificationRepositoryPort } from "../../server/ports/otp-verification-repository.port.ts";
import type { OutboxPort } from "../../server/ports/outbox.port.ts";
import type { RecoveryTokenRepositoryPort } from "../../server/ports/recovery-token.port.ts";
import type { RevocationRepositoryPort } from "../../server/ports/revocation-repository.port.ts";
import type { RightsCaseRepositoryPort } from "../../server/ports/rights-case-repository.port.ts";
import type { TenantTxPorts, UnitOfWorkPort } from "../../server/ports/unit-of-work.port.ts";
import { isTxParticipant, TX_JOURNAL, type TxParticipant, type Undo } from "./in-memory-tx.ts";

/** Escritura con tenantId distinto del de la unidad de trabajo (equivale a WITH CHECK de RLS). */
export class TenantScopeViolationError extends Error {
  constructor(operation: string) {
    super(`tenant scope violation: ${operation} con tenantId ajeno a la unidad de trabajo`);
    this.name = "TenantScopeViolationError";
  }
}

export class NestedUnitOfWorkError extends Error {
  constructor() {
    super("inTenant no admite anidamiento: reutiliza los puertos de la unidad de trabajo activa");
    this.name = "NestedUnitOfWorkError";
  }
}

function scopeRevocationRepo(inner: RevocationRepositoryPort, tenant: TenantId): RevocationRepositoryPort {
  return {
    findByRef: async (t, ref) => (t === tenant ? inner.findByRef(t, ref) : null),
    findByRefForUpdate: async (t, ref) => (t === tenant ? inner.findByRefForUpdate(t, ref) : null),
    findByCase: async (t, caseRef) => (t === tenant ? inner.findByCase(t, caseRef) : null),
    findOpenByChain: async (t, chainRef) => (t === tenant ? inner.findOpenByChain(t, chainRef) : null),
    save: async (record) => {
      if (record.tenantId !== tenant) throw new TenantScopeViolationError("revocationRepo.save");
      return inner.save(record);
    },
  };
}

function scopeConsentDecisionRepo(inner: ConsentDecisionRepositoryPort, tenant: TenantId): ConsentDecisionRepositoryPort {
  return {
    findByConsentId: async (t, id) => (t === tenant ? inner.findByConsentId(t, id) : null),
    findByConsentIdForUpdate: async (t, id) => (t === tenant ? inner.findByConsentIdForUpdate(t, id) : null),
    findActiveGrantByChain: async (t, chainRef) => (t === tenant ? inner.findActiveGrantByChain(t, chainRef) : null),
    save: async (record) => {
      if (record.tenantId !== tenant) throw new TenantScopeViolationError("consentDecisionRepo.save");
      return inner.save(record);
    },
  };
}

function scopeRecoveryTokenRepo(inner: RecoveryTokenRepositoryPort, tenant: TenantId): RecoveryTokenRepositoryPort {
  return {
    findByRef: async (t, ref) => (t === tenant ? inner.findByRef(t, ref) : null),
    save: async (record) => {
      if (record.tenantId !== tenant) throw new TenantScopeViolationError("recoveryTokenRepo.save");
      return inner.save(record);
    },
    consume: async (t, ref) => {
      // Bajo RLS un UPDATE sobre filas de otro tenant afecta 0 filas: nadie lo consumio (false).
      return t === tenant ? inner.consume(t, ref) : false;
    },
  };
}

function scopeInvitationRepo(inner: InvitationRepositoryPort, tenant: TenantId): InvitationRepositoryPort {
  return {
    findByRef: async (t, ref) => (t === tenant ? inner.findByRef(t, ref) : null),
    findByRefForUpdate: async (t, ref) => (t === tenant ? inner.findByRefForUpdate(t, ref) : null),
    findActiveBySubject: async (t, contextRef, subjectRef) => (t === tenant ? inner.findActiveBySubject(t, contextRef, subjectRef) : null),
    save: async (record) => {
      if (record.tenantId !== tenant) throw new TenantScopeViolationError("invitationRepo.save");
      return inner.save(record);
    },
  };
}

function scopeOtpRepo(inner: OtpVerificationRepositoryPort, tenant: TenantId): OtpVerificationRepositoryPort {
  return {
    findByRef: async (t, ref) => (t === tenant ? inner.findByRef(t, ref) : null),
    findByRefForUpdate: async (t, ref) => (t === tenant ? inner.findByRefForUpdate(t, ref) : null),
    findActiveByParent: async (t, parentRef, scope) => (t === tenant ? inner.findActiveByParent(t, parentRef, scope) : null),
    save: async (record) => {
      if (record.tenantId !== tenant) throw new TenantScopeViolationError("otpRepo.save");
      return inner.save(record);
    },
  };
}

function scopeRightsCaseRepo(inner: RightsCaseRepositoryPort, tenant: TenantId): RightsCaseRepositoryPort {
  return {
    findOpenByChain: async (t, chainRef, decisionRef) => (t === tenant ? inner.findOpenByChain(t, chainRef, decisionRef) : null),
    findByRef: async (t, ref) => (t === tenant ? inner.findByRef(t, ref) : null),
    findByRefForUpdate: async (t, ref) => (t === tenant ? inner.findByRefForUpdate(t, ref) : null),
    save: async (record) => {
      if (record.tenantId !== tenant) throw new TenantScopeViolationError("rightsCaseRepo.save");
      return inner.save(record);
    },
  };
}

function scopeEnrollmentRepo(inner: EnrollmentRepositoryPort, tenant: TenantId): EnrollmentRepositoryPort {
  return {
    findByRef: async (t, ref) => (t === tenant ? inner.findByRef(t, ref) : null),
    findActive: async (t, subjectRef, participationRef) => (t === tenant ? inner.findActive(t, subjectRef, participationRef) : null),
    save: async (record) => {
      if (record.tenantId !== tenant) throw new TenantScopeViolationError("enrollmentRepo.save");
      return inner.save(record);
    },
  };
}

function scopeLedger(inner: LedgerPort, tenant: TenantId): LedgerPort {
  return {
    append: async (event) => {
      if (event.tenantId !== tenant) throw new TenantScopeViolationError("ledger.append");
      return inner.append(event);
    },
    currentSequence: async (t, aggregateId) => (t === tenant ? inner.currentSequence(t, aggregateId) : 0),
    listByAggregate: async (t, aggregateType, aggregateId) =>
      t === tenant ? inner.listByAggregate(t, aggregateType, aggregateId) : [],
  };
}

function scopeOutbox(inner: OutboxPort, tenant: TenantId): OutboxPort {
  return {
    enqueue: async (input) => {
      if (input.tenantId !== tenant) throw new TenantScopeViolationError("outbox.enqueue");
      return inner.enqueue(input);
    },
  };
}

// Serializacion y deteccion de anidamiento a nivel de PROCESO (no por instancia): varias UoW in-memory
// pueden compartir participantes (el mismo ledger o consentDecisionRepo entre los bags de consentimiento
// y revocacion de un servidor); si cada una tuviera su propia cola, dos unidades concurrentes
// pisarian el journal de un participante comun. Una sola unidad a la vez en todo el proceso es lo
// que equivale, en memoria, al lock de fila de Postgres.
const active = new AsyncLocalStorage<true>();
let tail: Promise<void> = Promise.resolve();

/**
 * `ports` son los adaptadores in-memory que comparten estado con el resto del proceso; todos
 * deben ser participantes journaled (los creados por createInMemory* lo son; un wrapper que los
 * expanda con `...inner` conserva la participación).
 */
export function createInMemoryUnitOfWork(ports: TenantTxPorts): UnitOfWorkPort {
  const participants: TxParticipant[] = [];
  const keys = [
    "revocationRepo",
    "consentDecisionRepo",
    "recoveryTokenRepo",
    "invitationRepo",
    "otpRepo",
    "rightsCaseRepo",
    "enrollmentRepo",
    "ledger",
    "outbox",
  ] as const;
  for (const name of keys) {
    const port: unknown = ports[name];
    if (!isTxParticipant(port)) {
      throw new Error(`createInMemoryUnitOfWork: ${name} no es un adaptador in-memory participante (falta TX_JOURNAL)`);
    }
    participants.push(port);
  }

  async function run<T>(tenantId: TenantId, work: (tx: TenantTxPorts) => Promise<T>): Promise<T> {
    const journal: Undo[] = [];
    for (const participant of participants) participant[TX_JOURNAL](journal);
    try {
      return await work({
        revocationRepo: scopeRevocationRepo(ports.revocationRepo, tenantId),
        consentDecisionRepo: scopeConsentDecisionRepo(ports.consentDecisionRepo, tenantId),
        recoveryTokenRepo: scopeRecoveryTokenRepo(ports.recoveryTokenRepo, tenantId),
        invitationRepo: scopeInvitationRepo(ports.invitationRepo, tenantId),
        otpRepo: scopeOtpRepo(ports.otpRepo, tenantId),
        rightsCaseRepo: scopeRightsCaseRepo(ports.rightsCaseRepo, tenantId),
        enrollmentRepo: scopeEnrollmentRepo(ports.enrollmentRepo, tenantId),
        ledger: scopeLedger(ports.ledger, tenantId),
        outbox: scopeOutbox(ports.outbox, tenantId),
      });
    } catch (error) {
      for (let i = journal.length - 1; i >= 0; i--) journal[i]?.();
      throw error;
    } finally {
      for (const participant of participants) participant[TX_JOURNAL](null);
    }
  }

  return {
    async inTenant<T>(tenantId: TenantId, work: (tx: TenantTxPorts) => Promise<T>): Promise<T> {
      if (typeof tenantId !== "string" || tenantId.length === 0) {
        throw new Error("inTenant requiere un tenantId resuelto en servidor (no vacío)");
      }
      if (active.getStore()) throw new NestedUnitOfWorkError();
      const previous = tail;
      let release!: () => void;
      tail = new Promise<void>((resolve) => {
        release = resolve;
      });
      await previous;
      try {
        return await active.run(true, () => run(tenantId, work));
      } finally {
        release();
      }
    },
  };
}
