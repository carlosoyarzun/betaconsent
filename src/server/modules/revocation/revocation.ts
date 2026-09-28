// Gobierna: specs/state-machines/revocation.spec.yaml (RH2, RH3, R4, R1, R2, R3, R8, RV0
// fuente BEARER). Alcance IT0 de este archivo (subconjunto mínimo, ver
// traceability/test-matrix.csv TEST-CNS-462..465, TEST-CNS-571+): la verificación humana
// atestada (RH2, simplificada a un solo paso para este slice; el doble control
// proposer/approver de la spec completa es una historia posterior), el registro de
// confirmación con cuatro ojos (RH3, simplificado a los guards bajo prueba), la aplicación
// (R4), y (CA-116 UX-CNS-004) el subconjunto self-service authPath OTP: solicitud (R1),
// verificación (R2), confirmación (R3) y retiro explícito (R8) de la revocación, más RV0 con
// fuente BEARER (emisión del enlace de recuperación pedido por el portador; la creación real
// del token de /r/{token} es la PR 2, ver nota en issueRecoveryLinkBearer). No implementa SLA,
// CHANNEL_LINK ni el resto de authPath/recoveryMethod ajenos a este slice.

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

// ---------------------------------------------------------------------------
// CA-116 (revocación IT0, UX-CNS-004, PR1 gestión/retiro self-service): subconjunto mínimo de
// R1 (RequestRevocation), R2 (VerifyRevocationOtp), R3 (ConfirmRevocation) y R8
// (WithdrawRevocationRequest), authPath OTP. Guards implementados: tenant/chain ya resueltos
// del lado servidor por el llamador HTTP (GRD-CM-01/02/06, vía TenantHandlePort + la sesión
// MANAGE verificada, nunca del body); secuencia de estados (REQUESTED -> VERIFIED -> CONFIRMED,
// R8 desde cualquiera de los tres a FAILED). NO implementa: GRD-RV-19/21/23 (expectedSequence
// optimista y su condición de carrera con R4/R8h), presupuesto RIGHTS (V6r/V6c), RightsCase
// (FLAG-escalated/R9), ni la distinción revokedDecisionRef de un ciclo anterior (R14-C, un solo
// ciclo por chainRef en este slice). Documentado como alcance mínimo IT0, igual que RH2/RH3/R4
// arriba; el resto queda para las historias que cierren R14-A/B/C de forma completa.
// ---------------------------------------------------------------------------

export interface RequestRevocationInput {
  readonly revocationRef: string;
  readonly chainRef: string;
  readonly revokedDecisionRef: string;
}

/** R1: null -> REQUESTED. Idempotente por revocationRef: si ya existe una Revocation abierta
 * para esta (tenantId, revocationRef), la devuelve sin duplicar el evento (mismo criterio que
 * requestOtp/GRD-OT-08 más arriba en el módulo hermano). */
export function requestRevocation(ports: RevocationPorts, tenantId: string, input: RequestRevocationInput): RevocationRecord {
  const existing = ports.revocationRepo.findByRef(tenantId, input.revocationRef);
  if (existing) return existing;

  const record: RevocationRecord = {
    revocationRef: input.revocationRef,
    tenantId,
    chainRef: input.chainRef,
    revokedDecisionRef: input.revokedDecisionRef,
    status: "REQUESTED",
  };
  ports.revocationRepo.save(record);
  ports.ledger.append({
    eventType: "REVOCATION_REQUESTED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: input.revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { scope: "ALL", authPath: "OTP", originPurposeRef: "ALL" },
    idempotencyKey: input.revocationRef,
  });
  return record;
}

/** R2: REQUESTED -> VERIFIED, tras un V3 scope REVOCATION correcto posterior a R1 (GRD-RV-05,
 * verificado por el llamador HTTP: el OTP scope REVOCATION solo se puede pedir sobre una sesión
 * que ya tiene revocationRef, es decir después de R1). */
export function verifyRevocationOtp(
  ports: RevocationPorts,
  tenantId: string,
  revocationRef: string,
  verificationRef: string,
): RevocationRecord {
  const found = requireRevocation(ports, tenantId, revocationRef);
  if (found.status === "VERIFIED" || found.status === "CONFIRMED") {
    // Idempotente: un R2 repetido con el mismo resultado no reemite el evento.
    return found;
  }
  if (found.status !== "REQUESTED") {
    throw new DomainError("ERR-CM-06");
  }
  const verified: RevocationRecord = { ...found, status: "VERIFIED" };
  ports.revocationRepo.save(verified);
  ports.ledger.append({
    eventType: "REVOCATION_VERIFIED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { authPath: "OTP", verificationRef },
    idempotencyKey: `${revocationRef}:r2`,
  });
  return verified;
}

/** R3: VERIFIED -> CONFIRMED. En la misma llamada (IT0: sin worker/cola real) se encola y
 * ejecuta R4 (applyRevocation) de inmediato: el comprobante nunca es visible al usuario como un
 * estado intermedio (revocation.spec.yaml R4 "nunca visible al usuario"), así que aplicarlo en
 * el mismo request síncrono es equivalente en efecto observable para IT0 in-memory. */
export function confirmRevocation(ports: RevocationPorts, tenantId: string, revocationRef: string): RevocationRecord {
  const found = requireRevocation(ports, tenantId, revocationRef);
  if (found.status === "CONFIRMED" || found.status === "APPLIED") {
    return found;
  }
  if (found.status !== "VERIFIED") {
    throw new DomainError("ERR-CM-06");
  }
  const confirmed: RevocationRecord = { ...found, status: "CONFIRMED" };
  ports.revocationRepo.save(confirmed);
  ports.ledger.append({
    eventType: "REVOCATION_CONFIRMED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: {},
    idempotencyKey: revocationRef,
  });
  return applyRevocationSync(ports, tenantId, revocationRef);
}

/** R8: REQUESTED|VERIFIED|CONFIRMED -> FAILED (WITHDRAWN_BY_REQUESTER). No admite retiro sobre
 * APPLIED (ya no hay solicitud abierta que retirar). */
export function withdrawRevocation(ports: RevocationPorts, tenantId: string, revocationRef: string): RevocationRecord {
  const found = requireRevocation(ports, tenantId, revocationRef);
  if (found.status === "FAILED") {
    return found;
  }
  if (found.status === "APPLIED") {
    // GRD-RV-15 (serialización con R4): R4 ya ganó la carrera; R8 no tiene efecto.
    throw new DomainError("ERR-CM-06");
  }
  const failed: RevocationRecord = { ...found, status: "FAILED", reasonCode: "WITHDRAWN_BY_REQUESTER" };
  ports.revocationRepo.save(failed);
  ports.ledger.append({
    eventType: "REVOCATION_FAILED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { reasonCode: "WITHDRAWN_BY_REQUESTER" },
    idempotencyKey: revocationRef,
  });
  return failed;
}

/**
 * R4 síncrono (ver nota en confirmRevocation): variante interna de applyRevocation que no
 * duplica el guard `status !== CONFIRMED` porque siempre se llama justo tras fijar CONFIRMED en
 * la misma función. Expuesta también como `applyRevocation` más abajo para el caso RH3 (worker
 * separado del confirm de doble control).
 */
function applyRevocationSync(ports: RevocationPorts, tenantId: string, revocationRef: string): RevocationRecord {
  return applyRevocation(ports, tenantId, revocationRef);
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

export type Rv0BearerTrigger = "REQUESTER_ASKED" | "LIMIT_REACHED";

export interface Rv0BearerResult {
  readonly sent: boolean;
}

/**
 * RV0 con fuente BEARER (revocation.spec.yaml RV0 guardsBySource.BEARER): POST explícito desde
 * el handle MANAGE_ENTRY de /m/, sin canal en el body (GRD-RV-17). Alcance IT0 de este slice
 * (PR1, UX-CNS-004 §3 "bloqueado→enviar enlace"): registra RECOVERY_TOKEN_ISSUED en el ledger
 * como emisión SECURITY (kind: EMISSION, sin cambio de estado de la Revocation) y responde
 * "enviado"; NO crea el `tenant_resolve.recovery_token` real ni el handle /r/{token} que lo
 * consume (eso es RC-116 PR 2, GET /r/{token} + POST /recovery/revoke): sin ese token, el botón
 * "Enviar enlace de recuperación" queda conectado al endpoint correcto del contrato
 * (POST /manage/recovery-link, API-CNS-134) y emite el evento correcto, pero el enlace en sí no
 * es canjeable todavía. Reportado como pendiente explícito para la PR 2 (ver reporte de tarea).
 */
export function issueRecoveryLinkBearer(
  ports: RevocationPorts,
  tenantId: string,
  chainRef: string,
  revokedDecisionRef: string,
  trigger: Rv0BearerTrigger,
): Rv0BearerResult {
  ports.ledger.append({
    eventType: "RECOVERY_TOKEN_ISSUED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: chainRef,
    actorType: "HUMAN",
    actorRole: "UNVERIFIED_BEARER",
    payload: { chainRef, revokedDecisionRef, trigger },
    // Sin idempotencyKey: cada emisión es un token nuevo (K vigentes por cadena, revocation.spec
    // RV0 effects); una emisión nueva no invalida ni dedupea las vigentes.
  });
  return { sent: true };
}
