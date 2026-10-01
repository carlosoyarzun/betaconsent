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
      findByRefForUpdate: (t, ref) => uow.inTenant(t, (tx) => tx.revocationRepo.findByRefForUpdate(t, ref)),
      findByCase: (t, caseRef) => uow.inTenant(t, (tx) => tx.revocationRepo.findByCase(t, caseRef)),
      findOpenByChain: (t, chainRef) => uow.inTenant(t, (tx) => tx.revocationRepo.findOpenByChain(t, chainRef)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.revocationRepo.save(record)),
    },
    consentDecisionRepo: {
      findByConsentId: (t, id) => uow.inTenant(t, (tx) => tx.consentDecisionRepo.findByConsentId(t, id)),
      findByConsentIdForUpdate: (t, id) => uow.inTenant(t, (tx) => tx.consentDecisionRepo.findByConsentIdForUpdate(t, id)),
      findActiveGrantByChain: (t, chainRef) => uow.inTenant(t, (tx) => tx.consentDecisionRepo.findActiveGrantByChain(t, chainRef)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.consentDecisionRepo.save(record)),
    },
    recoveryTokenRepo: {
      findByRef: (t, ref) => uow.inTenant(t, (tx) => tx.recoveryTokenRepo.findByRef(t, ref)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.recoveryTokenRepo.save(record)),
      consume: (t, ref) => uow.inTenant(t, (tx) => tx.recoveryTokenRepo.consume(t, ref)),
    },
    invitationRepo: {
      findByRef: (t, ref) => uow.inTenant(t, (tx) => tx.invitationRepo.findByRef(t, ref)),
      findByRefForUpdate: (t, ref) => uow.inTenant(t, (tx) => tx.invitationRepo.findByRefForUpdate(t, ref)),
      findActiveBySubject: (t, ctx, subject) => uow.inTenant(t, (tx) => tx.invitationRepo.findActiveBySubject(t, ctx, subject)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.invitationRepo.save(record)),
    },
    otpRepo: {
      findByRef: (t, ref) => uow.inTenant(t, (tx) => tx.otpRepo.findByRef(t, ref)),
      findByRefForUpdate: (t, ref) => uow.inTenant(t, (tx) => tx.otpRepo.findByRefForUpdate(t, ref)),
      findActiveByParent: (t, parent, scope) => uow.inTenant(t, (tx) => tx.otpRepo.findActiveByParent(t, parent, scope)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.otpRepo.save(record)),
    },
    rightsCaseRepo: {
      findOpenByChain: (t, chain, decision) => uow.inTenant(t, (tx) => tx.rightsCaseRepo.findOpenByChain(t, chain, decision)),
      findByRef: (t, ref) => uow.inTenant(t, (tx) => tx.rightsCaseRepo.findByRef(t, ref)),
      findByRefForUpdate: (t, ref) => uow.inTenant(t, (tx) => tx.rightsCaseRepo.findByRefForUpdate(t, ref)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.rightsCaseRepo.save(record)),
    },
    enrollmentRepo: {
      findByRef: (t, ref) => uow.inTenant(t, (tx) => tx.enrollmentRepo.findByRef(t, ref)),
      findActive: (t, subject, participation) => uow.inTenant(t, (tx) => tx.enrollmentRepo.findActive(t, subject, participation)),
      save: (record) => uow.inTenant(record.tenantId, (tx) => tx.enrollmentRepo.save(record)),
    },
    ledger: {
      append: (event) => uow.inTenant(event.tenantId, (tx) => tx.ledger.append(event)),
      currentSequence: (t, id) => uow.inTenant(t, (tx) => tx.ledger.currentSequence(t, id)),
      listByAggregate: (t, type, id) => uow.inTenant(t, (tx) => tx.ledger.listByAggregate(t, type, id)),
    },
    outbox: {
      enqueue: (input) => uow.inTenant(input.tenantId, (tx) => tx.outbox.enqueue(input)),
    },
    tenantCatalog: {
      subjectBelongsToTenant: (t, subject) => uow.inTenant(t, (tx) => tx.tenantCatalog.subjectBelongsToTenant(t, subject)),
      findParticipation: (t, participation) => uow.inTenant(t, (tx) => tx.tenantCatalog.findParticipation(t, participation)),
    },
    idempotency: {
      find: (t, hash) => uow.inTenant(t, (tx) => tx.idempotency.find(t, hash)),
      store: (t, hash, response) => uow.inTenant(t, (tx) => tx.idempotency.store(t, hash, response)),
    },
  };
}
