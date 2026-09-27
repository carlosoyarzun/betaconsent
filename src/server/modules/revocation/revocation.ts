// Gobierna: specs/state-machines/revocation.spec.yaml (RH2, RH3, R4). Alcance IT0 de este
// archivo (subconjunto mínimo, ver traceability/test-matrix.csv TEST-CNS-462..465): la
// verificación humana atestada (RH2, simplificada a un solo paso para este slice; el
// doble control proposer/approver de la spec completa es una historia posterior), el
// registro de confirmación con cuatro ojos (RH3, simplificado a los guards bajo prueba) y
// la aplicación (R4). No implementa SLA, OTP, CHANNEL_LINK ni el resto de authPath/recoveryMethod.

import { DomainError } from "../common/errors.ts";
import type { RevocationRecord, RevocationRepositoryPort } from "../../ports/revocation-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";

export interface RevocationPorts {
  readonly revocationRepo: RevocationRepositoryPort;
  readonly ledger: LedgerPort;
}

function requireRevocation(ports: RevocationPorts, tenantId: string, revocationRef: string): RevocationRecord {
  const found = ports.revocationRepo.findByRef(tenantId, revocationRef);
  if (!found) {
    // GRD-CM-01/06: revocationRef de otro tenant (o inexistente) -> 404 uniforme (TEST-CNS-464).
    throw new DomainError("ERR-CM-01");
  }
  return found;
}

/**
 * RH2/RH2v (verificación humana atestada), simplificada a un solo registro de atestación
 * para este slice. Deja constancia de (revocationRef, caseRef) ATTESTED para que RH3
 * (GRD-RV-10) pueda exigirla.
 */
export function attestHumanAssistedVerification(
  ports: RevocationPorts,
  tenantId: string,
  revocationRef: string,
  caseRef: string,
): RevocationRecord {
  const found = requireRevocation(ports, tenantId, revocationRef);
  if (found.caseRef !== caseRef) {
    throw new DomainError("ERR-CM-01");
  }
  const verified: RevocationRecord = {
    ...found,
    status: "VERIFIED",
    attestedVerification: { revocationRef, caseRef },
  };
  ports.revocationRepo.save(verified);
  ports.ledger.append({
    eventType: "REVOCATION_VERIFIED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { caseRef, recoveryMethod: "HUMAN_ASSISTED" },
    idempotencyKey: `${revocationRef}:rh2`,
  });
  return verified;
}

export interface CaseConfirmationExecutionContext {
  /** Ref opaca del RIGHTS_OPERATOR que registra, derivada de su sesión (nunca del body). */
  readonly recordedByPrincipalRef: string;
  /** Ref opaca del segundo RIGHTS_OPERATOR que co-firma (cuatro ojos, R14-B). */
  readonly cosignedByPrincipalRef: string;
}

/**
 * Campos que un llamador podría intentar enviar en el cuerpo de la request; se aceptan solo
 * para probar que esta función los IGNORA (TEST-CNS-465): recordedByRef/cosignedByRef salen
 * siempre de `ctx`, nunca de este objeto.
 */
export interface CaseConfirmationUntrustedRequestFields {
  readonly recordedByRef?: string;
  readonly cosignedByRef?: string;
}

/**
 * RH3 (record_case_confirmation + cosign_case_confirmation), simplificada a los guards bajo
 * prueba en este slice: GRD-CM-01/06 (tenant/ruta), GRD-RV-10 (RH2/RH2v ATTESTED previa de la
 * misma (revocationRef, caseRef)) y el origen de recordedByRef/cosignedByRef (F-R14-04,
 * INV-RV-11) desde la sesión autenticada del ejecutor, nunca de un campo de la request.
 */
export function recordCaseConfirmation(
  ports: RevocationPorts,
  tenantId: string,
  revocationRef: string,
  caseRef: string,
  ctx: CaseConfirmationExecutionContext,
  _untrustedRequestFields?: CaseConfirmationUntrustedRequestFields,
): RevocationRecord {
  const found = requireRevocation(ports, tenantId, revocationRef);
  if (found.caseRef !== caseRef) {
    throw new DomainError("ERR-CM-01");
  }

  const attested = found.attestedVerification;
  if (
    found.status !== "VERIFIED" ||
    !attested ||
    attested.revocationRef !== revocationRef ||
    attested.caseRef !== caseRef
  ) {
    // GRD-RV-10 onFail: RH3 sin RH2/RH2v ATTESTED previa de esta misma (revocationRef, caseRef).
    throw new DomainError("ERR-RV-20");
  }

  const confirmed: RevocationRecord = {
    ...found,
    status: "CONFIRMED",
    // F-R14-04 / INV-RV-11: SIEMPRE derivados de ctx (sesión autenticada), nunca del body.
    recordedByRef: ctx.recordedByPrincipalRef,
    cosignedByRef: ctx.cosignedByPrincipalRef,
  };
  ports.revocationRepo.save(confirmed);
  ports.ledger.append({
    eventType: "REVOCATION_CONFIRMED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    recordedByRef: ctx.recordedByPrincipalRef,
    cosignedByRef: ctx.cosignedByPrincipalRef,
    payload: { caseRef },
    idempotencyKey: `${revocationRef}:rh3`,
  });
  return confirmed;
}

/**
 * R4 (job APPLY_REVOCATION), simplificado: CONFIRMED -> APPLIED. Por construcción no recibe
 * ningún puerto de tenant/Study/SchoolParticipation/Enrollment: una ruta RIGHTS nunca puede
 * consultar su estado (INV-CM-06; TEST-CNS-462).
 */
export function applyRevocation(ports: RevocationPorts, tenantId: string, revocationRef: string): RevocationRecord {
  const found = requireRevocation(ports, tenantId, revocationRef);
  if (found.status !== "CONFIRMED") {
    throw new DomainError("ERR-CM-06");
  }
  const applied: RevocationRecord = { ...found, status: "APPLIED" };
  ports.revocationRepo.save(applied);
  ports.ledger.append({
    eventType: "CONSENT_REVOKED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: {},
    idempotencyKey: revocationRef,
  });
  return applied;
}
