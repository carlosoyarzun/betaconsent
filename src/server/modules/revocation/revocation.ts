// Gobierna: specs/state-machines/revocation.spec.yaml (RH2, RH3, R4, R1, R2, R3, R8, RV0
// fuente BEARER, R1r, R2r, R3r, R10, R11). Alcance IT0 de este archivo (subconjunto mínimo, ver
// traceability/test-matrix.csv TEST-CNS-462..465, TEST-CNS-571+): la verificación humana
// atestada (RH2, simplificada a un solo paso para este slice; el doble control
// proposer/approver de la spec completa es una historia posterior), el registro de
// confirmación con cuatro ojos (RH3, simplificado a los guards bajo prueba), la aplicación
// (R4), (CA-116 UX-CNS-004 PR 1) el subconjunto self-service authPath OTP: solicitud (R1),
// verificación (R2), confirmación (R3) y retiro explícito (R8) de la revocación, más RV0 con
// fuente BEARER (emisión del enlace de recuperación pedido por el portador), y (CA-116
// UX-CNS-004 PR 2, TEST-CNS-589+) el authPath RECOVERY/CHANNEL_LINK del único POST de
// /recovery/revoke: R1r (null|REQUESTED -> REQUESTED), R2r (REQUESTED -> VERIFIED, consume el
// token), R10 (VERIFIED -> VERIFIED, re-verificación), R11 (CONFIRMED -> CONFIRMED, NOOP sin
// consumir el token) y R3r (VERIFIED -> CONFIRMED, reutiliza confirmRevocation/R4 síncrono). No
// implementa SLA, HUMAN_ASSISTED (RC3/R12/RH2v/RH3 fuente RECOVERY) ni el resto de
// authPath/recoveryMethod ajenos a este slice.

import { createHash, randomBytes, randomUUID } from "node:crypto";

import { DomainError } from "../common/errors.ts";
import type { RevocationRecord, RevocationRepositoryPort } from "../../ports/revocation-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { RecoveryTokenRepositoryPort } from "../../ports/recovery-token.port.ts";
import type { RecoveryLinkChannelPort } from "../../ports/recovery-link-channel.port.ts";
import type { RecoveryTokenPolicy } from "./recovery-token-policy.config.ts";

export interface RevocationPorts {
  readonly revocationRepo: RevocationRepositoryPort;
  readonly ledger: LedgerPort;
  /** CA-116 PR 2 (RV0 BEARER, GET /r/{token}, POST /recovery/revoke). */
  readonly recoveryTokenRepo: RecoveryTokenRepositoryPort;
  readonly recoveryLinkChannel: RecoveryLinkChannelPort;
  readonly recoveryTokenPolicy: RecoveryTokenPolicy;
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
    // ":r1" (mismo motivo que ":r3" en confirmRevocation más abajo): evita colisionar con otro
    // idempotencyKey plano `revocationRef` del mismo agregado.
    idempotencyKey: `${input.revocationRef}:r1`,
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
    // ":r3" evita colisionar con el idempotencyKey plano `revocationRef` de R4/applyRevocation
    // más abajo (mismo aggregateId "Revocation"/revocationRef): dos idempotencyKey iguales en el
    // mismo agregado deduplicarían CONSENT_REVOKED contra REVOCATION_CONFIRMED (ledger dedupe es
    // por (tenantId, aggregateType, aggregateId, idempotencyKey), no por eventType).
    idempotencyKey: `${revocationRef}:r3`,
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
    idempotencyKey: `${revocationRef}:r8`,
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

function hashRecoveryToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * RV0 con fuente BEARER (revocation.spec.yaml RV0 guardsBySource.BEARER): POST explícito desde
 * el handle MANAGE_ENTRY de /m/, sin canal en el body (GRD-RV-17). Alcance IT0 (PR1, UX-CNS-004
 * §3 "bloqueado→enviar enlace" + PR 2, TEST-CNS-589+): crea el `tenant_resolve.recovery_token`
 * real (token opaco CSPRNG, mismo patrón GRD-IV-05 que invitation.ts sendInvitation: solo el
 * hash persiste, TTL P-15 vía recoveryTokenPolicy), lo emite por `recoveryLinkChannel` (sink
 * in-memory de LOCAL, nunca en la respuesta HTTP ni en logs, Cero PII) y registra
 * RECOVERY_TOKEN_ISSUED en el ledger como emisión SECURITY (kind: EMISSION, sin cambio de
 * estado de la Revocation). No implementa K vigentes por cadena (P-16) ni la ventana P-17
 * (revocation.spec RV0 effects): cada emisión crea un token nuevo sin invalidar los vigentes,
 * sin límite todavía (documentado como alcance mínimo IT0, igual que el resto de este archivo).
 */
export function issueRecoveryLinkBearer(
  ports: RevocationPorts,
  tenantId: string,
  chainRef: string,
  revokedDecisionRef: string,
  trigger: Rv0BearerTrigger,
): Rv0BearerResult {
  const token = randomBytes(32).toString("hex"); // GRD-RV-06/GRD-IV-05: CSPRNG, opaco, no JWT.
  const tokenHash = hashRecoveryToken(token);
  const recoveryRef = `rec-${randomUUID()}`;
  const expiresAt = new Date(Date.now() + ports.recoveryTokenPolicy.ttlMs);
  ports.recoveryTokenRepo.save({ tokenHash, recoveryRef, tenantId, chainRef, revokedDecisionRef, expiresAt });
  // El token en claro solo vive en este mensaje del sink LOCAL; se descarta al retornar.
  ports.recoveryLinkChannel.send({ recoveryPath: `/r/${token}` });
  ports.ledger.append({
    eventType: "RECOVERY_TOKEN_ISSUED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: chainRef,
    actorType: "HUMAN",
    actorRole: "UNVERIFIED_BEARER",
    payload: { chainRef, revokedDecisionRef, trigger, recoveryRef },
    // Sin idempotencyKey: cada emisión es un token nuevo (K vigentes por cadena, revocation.spec
    // RV0 effects); una emisión nueva no invalida ni dedupea las vigentes.
  });
  return { sent: true };
}

// ---------------------------------------------------------------------------
// CA-116 PR 2 (UX-CNS-004, recovery): único POST de /recovery/revoke — R1r+R2r+R3r (token
// fresco sobre una cadena sin Revocation abierta o con una REQUESTED existente), R10+R3r
// (token fresco sobre una Revocation VERIFIED, re-verificación) o R11 (NOOP, ya CONFIRMED).
// TEST-CNS-589+.
// ---------------------------------------------------------------------------

/** GET /r/{token} (API-CNS-103, INV-CM-08): resuelve el token por su hash SIN consumirlo ni
 * transicionar nada (el consumo ocurre solo en POST /recovery/revoke, revokeWithRecoveryLink).
 * Devuelve `null` si el hash no resuelve, si ya fue consumido o si expiró (GRD-RV-06); el
 * llamador SIEMPRE trata `null` como la respuesta uniforme de ERR-RV-05, sin distinguir motivo. */
export function resolveRecoveryTokenForRedeem(
  ports: Pick<RevocationPorts, "recoveryTokenRepo">,
  token: string,
): { tenantId: string; chainRef: string; revokedDecisionRef: string; tokenHash: string } | null {
  const tokenHash = hashRecoveryToken(token);
  const found = ports.recoveryTokenRepo.findByTokenHash(tokenHash);
  if (!found) return null;
  if (found.consumedAt) return null;
  if (found.expiresAt.getTime() <= Date.now()) return null;
  return { tenantId: found.tenantId, chainRef: found.chainRef, revokedDecisionRef: found.revokedDecisionRef, tokenHash: found.tokenHash };
}

/** R1r: null -> REQUESTED, authPath RECOVERY/CHANNEL_LINK (mismo POST único de
 * /recovery/revoke, revocation.spec.yaml:197-218). A diferencia de requestRevocation (R1, OTP),
 * siempre crea: el llamador (revokeWithRecoveryLink) solo entra aquí cuando ya confirmó que no
 * hay Revocation abierta para esta cadena (findOpenByChain). */
function requestRevocationRecovery(
  ports: RevocationPorts,
  tenantId: string,
  chainRef: string,
  revokedDecisionRef: string,
  recoveryRef: string,
): RevocationRecord {
  const revocationRef = `rv-${randomUUID()}`;
  const record: RevocationRecord = { revocationRef, tenantId, chainRef, revokedDecisionRef, status: "REQUESTED" };
  ports.revocationRepo.save(record);
  ports.ledger.append({
    eventType: "REVOCATION_REQUESTED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { scope: "ALL", authPath: "RECOVERY", recoveryMethod: "CHANNEL_LINK", originPurposeRef: "ALL", recoveryRef },
    idempotencyKey: `${revocationRef}:r1r`,
  });
  return record;
}

/** R2r (REQUESTED -> VERIFIED) / R10 (VERIFIED -> VERIFIED, self-loop de re-verificación):
 * ambos consumen el token en la misma tx (GRD-RV-06, ya hecho por el llamador antes de entrar
 * aquí) y emiten REVOCATION_VERIFIED authPath RECOVERY (revocation.spec.yaml:255-271,489-497).
 * El idempotencyKey incluye recoveryRef porque R10 puede repetirse con un token distinto sobre
 * la misma revocationRef (cada re-verificación es un hecho nuevo, no un replay). */
function verifyRevocationRecovery(ports: RevocationPorts, tenantId: string, found: RevocationRecord, recoveryRef: string): RevocationRecord {
  const verified: RevocationRecord = { ...found, status: "VERIFIED" };
  ports.revocationRepo.save(verified);
  ports.ledger.append({
    eventType: "REVOCATION_VERIFIED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: found.revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { authPath: "RECOVERY", recoveryMethod: "CHANNEL_LINK", recoveryRef },
    idempotencyKey: `${found.revocationRef}:r2r:${recoveryRef}`,
  });
  return verified;
}

export type RecoveryRevokeOutcome =
  | { readonly kind: "CONFIRMED"; readonly revocationRef: string }
  | { readonly kind: "IN_PROGRESS" }
  | { readonly kind: "UNIFORM" };

/**
 * POST /recovery/revoke (API-CNS-135, GRD-RV-06): único punto de entrada del authPath
 * RECOVERY/CHANNEL_LINK. `tenantId`/`chainRef`/`revokedDecisionRef` vienen SIEMPRE de la sesión
 * RECOVERY creada por GET /r/{token} (nunca del body); `tokenHash` es el del token que esa
 * misma sesión ligó al canjear el enlace.
 *
 * - Token inválido/consumido/expirado o ligado a otra cadena/decisión (GRD-RV-06 onFail):
 *   "UNIFORM" (ERR-RV-05), sin consumir nada ni emitir evento.
 * - Sin Revocation abierta para la cadena: R1r (REQUESTED) + R2r (VERIFIED) + R3r (CONFIRMED,
 *   con R4 síncrono) en la misma llamada.
 * - Revocation REQUESTED (p. ej. abierta por R1 self-service): R2r + R3r.
 * - Revocation VERIFIED: R10 (re-verificación) + R3r.
 * - Revocation CONFIRMED: R11, NOOP — "en curso", el token NO se consume, sin evento.
 * - Revocation APPLIED (GRD-RV-27, más allá de APPLIED): "UNIFORM", sin consumir el token.
 */
export function revokeWithRecoveryLink(
  ports: RevocationPorts,
  tenantId: string,
  chainRef: string,
  revokedDecisionRef: string,
  tokenHash: string,
): RecoveryRevokeOutcome {
  const tokenRecord = ports.recoveryTokenRepo.findByTokenHash(tokenHash);
  if (
    !tokenRecord ||
    tokenRecord.tenantId !== tenantId ||
    tokenRecord.chainRef !== chainRef ||
    tokenRecord.revokedDecisionRef !== revokedDecisionRef ||
    tokenRecord.consumedAt ||
    tokenRecord.expiresAt.getTime() <= Date.now()
  ) {
    // GRD-RV-06 onFail: ERR-RV-05, respuesta uniforme, sin revelar revocationRef, sin evento.
    return { kind: "UNIFORM" };
  }

  const existing = ports.revocationRepo.findOpenByChain(tenantId, chainRef);

  if (existing?.status === "CONFIRMED") {
    // R11 (kind NOOP, SEC N-05): ni consume el token ni emite evento.
    return { kind: "IN_PROGRESS" };
  }
  if (existing?.status === "APPLIED") {
    // GRD-RV-27: más allá de APPLIED, respuesta uniforme; el caso (si existe) cierra por
    // RC4/RC5, fuera de alcance de este slice self-service.
    return { kind: "UNIFORM" };
  }

  // A partir de aquí el token siempre se consume: GRD-RV-23 nunca lo deja sin efecto.
  ports.recoveryTokenRepo.consume(tokenHash);

  let record: RevocationRecord;
  if (!existing) {
    // R1r: null -> REQUESTED, seguido de R2r en el mismo POST.
    record = requestRevocationRecovery(ports, tenantId, chainRef, revokedDecisionRef, tokenRecord.recoveryRef);
    record = verifyRevocationRecovery(ports, tenantId, record, tokenRecord.recoveryRef);
  } else if (existing.status === "VERIFIED") {
    // R10: VERIFIED -> VERIFIED (re-verificación).
    record = verifyRevocationRecovery(ports, tenantId, existing, tokenRecord.recoveryRef);
  } else {
    // existing.status === "REQUESTED": R2r directo sobre una solicitud abierta por otra vía.
    record = verifyRevocationRecovery(ports, tenantId, existing, tokenRecord.recoveryRef);
  }

  // R3r: VERIFIED -> CONFIRMED, mismo POST (confirmRevocation ya encola R4 síncrono).
  const confirmed = confirmRevocation(ports, tenantId, record.revocationRef);
  return { kind: "CONFIRMED", revocationRef: confirmed.revocationRef };
}
