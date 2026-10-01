// Gobierna: CA-124 (PR-C), diseno postgres-design.md rev. 2 §5. Helper de TESTS (no de produccion):
// puertos "fuera de la unidad de trabajo" sobre PgUnitOfWork. Cada llamada abre su propia
// transaccion `inTenant(tenantId)` (autocommit por operacion), para sembrar y leer estado desde un
// test o para los campos del bag de RevocationPorts que el dominio usa fuera de `inTx`
// (lecturas del flujo de recuperacion). Todo lo que escribe en varios repos va por `uow.inTenant`.

import type { TenantTxPorts, UnitOfWorkPort } from "../../../src/server/ports/unit-of-work.port.ts";

export function pgOutsideTxPorts(uow: UnitOfWorkPort): TenantTxPorts {
  return {
    revocationRepo: {
      findByRef: (t, ref) => uow.inTenant(t, (tx) => tx.revocationRepo.findByRef(t, ref)),
      findByCase: (t, caseRef) => uow.inTenant(t, (tx) => tx.revocationRepo.findByCase(t, caseRef)),
      findOpenByChain: (t, chainRef) => uow.inTenant(t, (tx) => tx.revocationRepo.findOpenByChain(t, chainRef)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.revocationRepo.save(record)),
    },
    consentDecisionRepo: {
      findByConsentId: (t, id) => uow.inTenant(t, (tx) => tx.consentDecisionRepo.findByConsentId(t, id)),
      findActiveGrantByChain: (t, chainRef) => uow.inTenant(t, (tx) => tx.consentDecisionRepo.findActiveGrantByChain(t, chainRef)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.consentDecisionRepo.save(record)),
    },
    recoveryTokenRepo: {
      findByRef: (t, ref) => uow.inTenant(t, (tx) => tx.recoveryTokenRepo.findByRef(t, ref)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.recoveryTokenRepo.save(record)),
      consume: (t, ref) => uow.inTenant(t, (tx) => tx.recoveryTokenRepo.consume(t, ref)),
    },
    ledger: {
      append: (event) => uow.inTenant(event.tenantId, (tx) => tx.ledger.append(event)),
      listByAggregate: (t, type, id) => uow.inTenant(t, (tx) => tx.ledger.listByAggregate(t, type, id)),
    },
    outbox: {
      enqueue: (input) => uow.inTenant(input.tenantId, (tx) => tx.outbox.enqueue(input)),
    },
  };
}
