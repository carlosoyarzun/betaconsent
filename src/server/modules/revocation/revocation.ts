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
import type { OutboxPort } from "../../ports/outbox.port.ts";
import type { RecoveryTokenRecord, RecoveryTokenRepositoryPort } from "../../ports/recovery-token.port.ts";
import type { RecoveryLinkChannelPort } from "../../ports/recovery-link-channel.port.ts";
import type { ConsentDecisionRepositoryPort } from "../../ports/consent-decision-repository.port.ts";
import type { StaffIdentityPort } from "../../ports/staff-identity.port.ts";
import type { TenantResolverPort } from "../../ports/tenant-resolver.port.ts";
import type { UnitOfWorkPort } from "../../ports/unit-of-work.port.ts";
import type { RecoveryTokenPolicy } from "./recovery-token-policy.config.ts";
import { appendNext, lastLedgerSequence } from "../common/ledger-append.ts";

export interface RevocationPorts {
  readonly revocationRepo: RevocationRepositoryPort;
  readonly ledger: LedgerPort;
  /** CA-127: outbox transaccional; R4 encola consent.revoked (revocation.spec R4 emits, GRD-RV-11). */
  readonly outbox: OutboxPort;
  /** CA-116 PR 2 (RV0 BEARER, GET /r/{token}, POST /recovery/revoke). */
  readonly recoveryTokenRepo: RecoveryTokenRepositoryPort;
  readonly recoveryLinkChannel: RecoveryLinkChannelPort;
  readonly recoveryTokenPolicy: RecoveryTokenPolicy;
  /** SEC-CNS-014 (FINDING P1-01): fuente de verdad de la GRANTED vigente de la cadena, para
   * que GRD-RV-06 pueda comparar contra el ciclo real en vez de solo contra el propio token
   * (evaluateRecoveryTokenEligibility). */
  readonly consentDecisionRepo: ConsentDecisionRepositoryPort;
  /** CA-124 (diseño postgres-design.md §5): toda operación que escribe en varios repos corre en
   * UNA unidad de trabajo del tenant (R3+R4, recuperación, RH3 cosign+R4: si algo falla no
   * queda ninguna escritura y el reintento converge). */
  readonly uow: UnitOfWorkPort;
  /** CA-124 §3/§5: lookup SIN tenant por hash del token de recuperación (GRD-CM-01). */
  readonly tenantResolver: TenantResolverPort;
}

/** Ejecuta `fn` en una unidad de trabajo del tenant; dentro, los repos/ledger/outbox del bag se
 * sustituyen por los puertos de la tx. Las funciones `...Tx` de este módulo solo llaman a otras
 * `...Tx` (inTenant no se anida). */
function inTx<T>(ports: RevocationPorts, tenantId: string, fn: (txPorts: RevocationPorts) => Promise<T>): Promise<T> {
  return ports.uow.inTenant(tenantId, (tx) => fn({ ...ports, ...tx }));
}

/** Secuencia vigente de la Revocation: se lee ANTES de bloquear/leer el estado (SEC-CNS-015 P1-1). */
const revocationSequence = (ports: RevocationPorts, tenantId: string, revocationRef: string): Promise<number> =>
  lastLedgerSequence(ports.ledger, tenantId, revocationRef);

/** Relee la Revocation CON lock de fila (revocation.spec R4 "una tx con lock", SEC-CNS-015 P1-1): solo
 * se usa dentro de la unidad de trabajo; la decision de transicion se toma sobre el estado bloqueado. */
async function requireRevocation(ports: RevocationPorts, tenantId: string, revocationRef: string): Promise<RevocationRecord> {
  const found = await ports.revocationRepo.findByRefForUpdate(tenantId, revocationRef);
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
): Promise<RevocationRecord> {
  return inTx(ports, tenantId, (p) => attestHumanAssistedVerificationTx(p, tenantId, revocationRef, caseRef));
}

async function attestHumanAssistedVerificationTx(
  ports: RevocationPorts,
  tenantId: string,
  revocationRef: string,
  caseRef: string,
): Promise<RevocationRecord> {
  const base = await revocationSequence(ports, tenantId, revocationRef);
  const found = await requireRevocation(ports, tenantId, revocationRef);
  if (found.caseRef !== caseRef) {
    throw new DomainError("ERR-CM-01");
  }
  const verified: RevocationRecord = {
    ...found,
    status: "VERIFIED",
    attestedVerification: { revocationRef, caseRef },
    verifiedAuthPath: "RECOVERY",
    verifiedRecoveryMethod: "HUMAN_ASSISTED",
  };
  await ports.revocationRepo.save(verified);
  await ports.ledger.append({
    expectedSequence: base,
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

// ---------------------------------------------------------------------------
// CA-128 (API-CNS-138, RH3 paso 1 — record_case_confirmation, sin co-firma). Esta función implementa el
// paso 1 LITERAL de la spec (x-state-transition: {id: RH3, step: record, effect: none}):
// registra recordedByRef SIN transicionar el estado de la Revocation ni emitir
// REVOCATION_CONFIRMED (ledger-event-payloads.schema.json: recordedByRef/cosignedByRef son
// "ambos o ninguno" vía dependentRequired; registrar solo uno haría fallar el append). La
// Revocation permanece VERIFIED hasta que un segundo RIGHTS_OPERATOR distinto co-firme
// (API-CNS-139, cosignCaseConfirmation, abajo).
//
// Reconciliación (CA-128, API-CNS-139): la variante atómica previa (recordCaseConfirmation,
// registro + co-firma en una llamada) se retiró; RH3 tiene una única semántica en dos pasos
// (record -> cosignCaseConfirmation). TEST-CNS-463..465 se reescribieron sobre los dos pasos.
// ---------------------------------------------------------------------------

export interface CaseConfirmationRecordContext {
  /** Ref opaca del RIGHTS_OPERATOR que registra, derivada de su sesión CASE (nunca del body). */
  readonly recordedByPrincipalRef: string;
}

/**
 * GRD-RC-15 (nominal_roster_minimum, rights-case.spec.yaml): la lista nominal atestada exige
 * ≥2 RIGHTS_OPERATOR distintos y ≥2 aprobadores distintos, sin que un mismo principal ocupe dos
 * roles. Fail-closed: dotación insuficiente -> ERR-RC-10 (ROSTER_INSUFFICIENT), el caso sigue
 * abierto, nunca FAILED.
 */
async function assertNominalRosterMinimum(staffIdentity: StaffIdentityPort): Promise<void> {
  const roster = await staffIdentity.listRoster();
  const operatorRefs = new Set(roster.filter((principal) => principal.role === "RIGHTS_OPERATOR").map((principal) => principal.principalRef));
  const approverRefs = new Set(roster.filter((principal) => principal.role === "APPROVER").map((principal) => principal.principalRef));
  if (operatorRefs.size < 2 || approverRefs.size < 2) {
    throw new DomainError("ERR-RC-10");
  }
}

/**
 * RH3 paso 1 (record_case_confirmation), API-CNS-138. Guards de este slice (CA-128; el resto de
 * la lista `x-guards` del contrato -- GRD-RV-07, GRD-RV-23, GRD-RV-24, GRD-RV-26, GRD-RV-28,
 * GRD-RC-10 -- no está implementado todavía, mismo patrón de alcance mínimo documentado arriba
 * en este archivo para RH2/RH3):
 * - GRD-CM-01/06/07/10: aplicados por el llamador HTTP (case-confirmation.handler.ts). GRD-CM-06
 *   se cumple por construcción: esta función no recibe ningún puerto de tenant/Study/
 *   SchoolParticipation/Enrollment (INV-CM-06).
 * - GRD-RV-10 (ERR-RV-20): exige una RH2/RH2v ATTESTED previa de la misma (revocationRef,
 *   caseRef).
 * - GRD-RC-15 (ERR-RC-10): dotación nominal mínima (arriba).
 */
export function recordCaseConfirmationPendingCosign(
  ports: RevocationPorts,
  staffIdentity: StaffIdentityPort,
  tenantId: string,
  revocationRef: string,
  caseRef: string,
  ctx: CaseConfirmationRecordContext,
): Promise<RevocationRecord> {
  return inTx(ports, tenantId, (p) => recordCaseConfirmationPendingCosignTx(p, staffIdentity, tenantId, revocationRef, caseRef, ctx));
}

async function recordCaseConfirmationPendingCosignTx(
  ports: RevocationPorts,
  staffIdentity: StaffIdentityPort,
  tenantId: string,
  revocationRef: string,
  caseRef: string,
  ctx: CaseConfirmationRecordContext,
): Promise<RevocationRecord> {
  const found = await requireRevocation(ports, tenantId, revocationRef);
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

  await assertNominalRosterMinimum(staffIdentity);

  // Paso 1 literal (effect: none): registra recordedByRef, sin tocar `status` ni emitir evento.
  const recorded: RevocationRecord = {
    ...found,
    recordedByRef: ctx.recordedByPrincipalRef,
  };
  await ports.revocationRepo.save(recorded);
  return recorded;
}

export interface CaseConfirmationCosignContext {
  /** Ref opaca del segundo RIGHTS_OPERATOR que co-firma, derivada de su sesión CASE (nunca del
   * body, GRD-CM-07). */
  readonly cosignedByPrincipalRef: string;
}

/**
 * RH3 paso 2 (cosign_case_confirmation), API-CNS-139: VERIFIED -> CONFIRMED. Guards de este
 * slice: GRD-CM-01/06 (tenant/caseRef), GRD-RV-10 (ERR-RV-20), GRD-RC-15 (ERR-RC-10) y
 * GRD-RV-26 (ERR-RV-18): exige una confirmación previa registrada (paso 1) y un co-firmante
 * distinto de recordedByRef (CHECK cosigned_by_ref <> recorded_by_ref, INV-RV-11). El rol
 * RIGHTS_OPERATOR del co-firmante lo verifica el llamador HTTP (LEGAL DECISION LD-03: la regla
 * definitiva de quién escribe/co-firma la confirmación no la decide este código).
 * Idempotente por revocationRef: repetir sobre una Revocation ya CONFIRMED/APPLIED devuelve el
 * registro sin reemitir REVOCATION_CONFIRMED. R4 (applyRevocation) se ejecuta aquí de forma
 * síncrona (IT0, decisión de Carlos 2026-09-28; worker asíncrono diferido): devuelve APPLIED.
 */
export function cosignCaseConfirmation(
  ports: RevocationPorts,
  staffIdentity: StaffIdentityPort,
  tenantId: string,
  revocationRef: string,
  caseRef: string,
  ctx: CaseConfirmationCosignContext,
): Promise<RevocationRecord> {
  return inTx(ports, tenantId, (p) => cosignCaseConfirmationTx(p, staffIdentity, tenantId, revocationRef, caseRef, ctx));
}

async function cosignCaseConfirmationTx(
  ports: RevocationPorts,
  staffIdentity: StaffIdentityPort,
  tenantId: string,
  revocationRef: string,
  caseRef: string,
  ctx: CaseConfirmationCosignContext,
): Promise<RevocationRecord> {
  const base = await revocationSequence(ports, tenantId, revocationRef);
  const found = await requireRevocation(ports, tenantId, revocationRef);
  if (found.caseRef !== caseRef) {
    throw new DomainError("ERR-CM-01");
  }
  if (found.status === "APPLIED" && found.cosignedByRef) {
    return found; // idempotente: ya confirmada y aplicada, sin reaplicar ni duplicar eventos.
  }
  if (found.status === "CONFIRMED" && found.cosignedByRef) {
    // CONFIRMED sin aplicar (R4 falló antes): reintenta R4, sin reemitir REVOCATION_CONFIRMED.
    return applyRevocationTx(ports, tenantId, revocationRef, base);
  }

  const attested = found.attestedVerification;
  if (
    found.status !== "VERIFIED" ||
    !attested ||
    attested.revocationRef !== revocationRef ||
    attested.caseRef !== caseRef
  ) {
    throw new DomainError("ERR-RV-20");
  }

  await assertNominalRosterMinimum(staffIdentity);

  // GRD-RV-26: sin confirmación registrada (paso 1) o con el mismo principal -> sin efecto.
  const recordedByRef = found.recordedByRef;
  if (!recordedByRef || recordedByRef === ctx.cosignedByPrincipalRef) {
    throw new DomainError("ERR-RV-18");
  }

  const confirmed: RevocationRecord = { ...found, status: "CONFIRMED", cosignedByRef: ctx.cosignedByPrincipalRef };
  await ports.revocationRepo.save(confirmed);
  const confirmedEvent = await ports.ledger.append({
    expectedSequence: base,
    eventType: "REVOCATION_CONFIRMED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    recordedByRef,
    cosignedByRef: ctx.cosignedByPrincipalRef,
    // ledger-event-payloads.schema.json REVOCATION_CONFIRMED (RH3): ambos o ninguno.
    payload: { revocationRef, recordedByRef, cosignedByRef: ctx.cosignedByPrincipalRef },
    idempotencyKey: `${revocationRef}:rh3`,
  });
  // R4 síncrono en IT0 por decisión de Carlos 2026-09-28; worker asíncrono diferido. Mismo patrón
  // que confirmRevocation (R3 -> R4). CA-124: RH3 cosign + R4 corren en UNA unidad de trabajo; si
  // R4 falla el error se propaga y NO queda ninguna escritura (la Revocation sigue VERIFIED con su
  // recordedByRef, sin REVOCATION_CONFIRMED) y el reintento de cosign converge hasta APPLIED.
  return applyRevocationTx(ports, tenantId, revocationRef, Math.max(base, confirmedEvent.sequence));
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

/** GRD-RV-02 (parcial, ver FINDING P2 del reporte CA-127): una decisión ya REVOKED por C6 no es
 * elegible para una revocación nueva (R1) ni para emitir enlace (RV0). La verificación completa
 * "es la GRANTED vigente de la cadena" exige fixtures con chainRef coherente en los tests. */
async function isAlreadyRevoked(
  ports: Pick<RevocationPorts, "consentDecisionRepo">,
  tenantId: string,
  decisionRef: string,
): Promise<boolean> {
  return (await ports.consentDecisionRepo.findByConsentId(tenantId, decisionRef))?.state === "REVOKED";
}

/** R1: null -> REQUESTED. Idempotente por revocationRef: si ya existe una Revocation abierta
 * para esta (tenantId, revocationRef), la devuelve sin duplicar el evento (mismo criterio que
 * requestOtp/GRD-OT-08 más arriba en el módulo hermano). */
export function requestRevocation(ports: RevocationPorts, tenantId: string, input: RequestRevocationInput): Promise<RevocationRecord> {
  return inTx(ports, tenantId, (p) => requestRevocationTx(p, tenantId, input));
}

async function requestRevocationTx(ports: RevocationPorts, tenantId: string, input: RequestRevocationInput): Promise<RevocationRecord> {
  const existing = await ports.revocationRepo.findByRef(tenantId, input.revocationRef);
  if (existing) return existing;

  // GRD-RV-02 (chain_granted, ERR-RV-02): la cadena debe tener aún la GRANTED vigente que se
  // revoca; una decisión ya REVOKED por C6 no es elegible. Sin escrituras ni eventos.
  if (await isAlreadyRevoked(ports, tenantId, input.revokedDecisionRef)) {
    throw new DomainError("ERR-RV-02");
  }

  const record: RevocationRecord = {
    revocationRef: input.revocationRef,
    tenantId,
    chainRef: input.chainRef,
    revokedDecisionRef: input.revokedDecisionRef,
    status: "REQUESTED",
  };
  await ports.revocationRepo.save(record);
  await ports.ledger.append({
    expectedSequence: 0,
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
): Promise<RevocationRecord> {
  return inTx(ports, tenantId, (p) => verifyRevocationOtpTx(p, tenantId, revocationRef, verificationRef));
}

async function verifyRevocationOtpTx(
  ports: RevocationPorts,
  tenantId: string,
  revocationRef: string,
  verificationRef: string,
): Promise<RevocationRecord> {
  const base = await revocationSequence(ports, tenantId, revocationRef);
  const found = await requireRevocation(ports, tenantId, revocationRef);
  if (found.status === "VERIFIED" || found.status === "CONFIRMED") {
    // Idempotente: un R2 repetido con el mismo resultado no reemite el evento.
    return found;
  }
  if (found.status !== "REQUESTED") {
    throw new DomainError("ERR-CM-06");
  }
  const verified: RevocationRecord = { ...found, status: "VERIFIED", verifiedAuthPath: "OTP", verifiedRecoveryMethod: undefined };
  await ports.revocationRepo.save(verified);
  await ports.ledger.append({
    expectedSequence: base,
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
export function confirmRevocation(ports: RevocationPorts, tenantId: string, revocationRef: string): Promise<RevocationRecord> {
  return inTx(ports, tenantId, (p) => confirmRevocationTx(p, tenantId, revocationRef));
}

async function confirmRevocationTx(ports: RevocationPorts, tenantId: string, revocationRef: string): Promise<RevocationRecord> {
  const base = await revocationSequence(ports, tenantId, revocationRef);
  const found = await requireRevocation(ports, tenantId, revocationRef);
  if (found.status === "CONFIRMED" || found.status === "APPLIED") {
    return found;
  }
  if (found.status !== "VERIFIED") {
    throw new DomainError("ERR-CM-06");
  }
  const confirmed: RevocationRecord = { ...found, status: "CONFIRMED" };
  await ports.revocationRepo.save(confirmed);
  const confirmedEvent = await ports.ledger.append({
    expectedSequence: base,
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
  // CA-124: R3 + R4 en la misma unidad de trabajo (P2 de lampone-security): si R4 falla, la
  // Revocation vuelve a VERIFIED (no queda CONFIRMED huérfana) y el reintento de R3 llega a APPLIED.
  return applyRevocationTx(ports, tenantId, revocationRef, Math.max(base, confirmedEvent.sequence));
}

/** R8: REQUESTED|VERIFIED|CONFIRMED -> FAILED (WITHDRAWN_BY_REQUESTER). No admite retiro sobre
 * APPLIED (ya no hay solicitud abierta que retirar). */
export function withdrawRevocation(ports: RevocationPorts, tenantId: string, revocationRef: string): Promise<RevocationRecord> {
  return inTx(ports, tenantId, (p) => withdrawRevocationTx(p, tenantId, revocationRef));
}

async function withdrawRevocationTx(ports: RevocationPorts, tenantId: string, revocationRef: string): Promise<RevocationRecord> {
  const base = await revocationSequence(ports, tenantId, revocationRef);
  const found = await requireRevocation(ports, tenantId, revocationRef);
  if (found.status === "FAILED") {
    return found;
  }
  if (found.status === "APPLIED") {
    // GRD-RV-15 (serialización con R4): R4 ya ganó la carrera; R8 no tiene efecto.
    throw new DomainError("ERR-CM-06");
  }
  const failed: RevocationRecord = { ...found, status: "FAILED", reasonCode: "WITHDRAWN_BY_REQUESTER" };
  await ports.revocationRepo.save(failed);
  await ports.ledger.append({
    expectedSequence: base,
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
 * R4 (job APPLY_REVOCATION), simplificado: CONFIRMED -> APPLIED. Por construcción no recibe
 * ningún puerto de tenant/Study/SchoolParticipation/Enrollment: una ruta RIGHTS nunca puede
 * consultar su estado (INV-CM-06; TEST-CNS-462).
 */
export function applyRevocation(ports: RevocationPorts, tenantId: string, revocationRef: string): Promise<RevocationRecord> {
  return inTx(ports, tenantId, (p) => applyRevocationTx(p, tenantId, revocationRef));
}

/** `knownSequence`: secuencia del agregado ya capturada por el llamador en la misma unidad de trabajo
 * (R3/RH3 que acaban de apendizar); si falta, se lee ANTES de bloquear la Revocation. */
async function applyRevocationTx(
  ports: RevocationPorts,
  tenantId: string,
  revocationRef: string,
  knownSequence?: number,
): Promise<RevocationRecord> {
  const lastSequence = knownSequence ?? (await revocationSequence(ports, tenantId, revocationRef));
  const found = await requireRevocation(ports, tenantId, revocationRef);
  if (found.status !== "CONFIRMED") {
    throw new DomainError("ERR-CM-06");
  }
  // GRD-RV-29 / INV-RV-07: authPath y recoveryMethod se DERIVAN del registro (último
  // REVOCATION_VERIFIED), nunca de input del usuario. Sin fuente en el dominio no se inventa un
  // valor: falla cerrado (no debería ocurrir; R2/R2r/R10/RH2 fijan siempre la vía).
  const { verifiedAuthPath, verifiedRecoveryMethod, revokedDecisionRef } = found;
  if (!verifiedAuthPath || !revokedDecisionRef || (verifiedAuthPath === "RECOVERY" && !verifiedRecoveryMethod)) {
    throw new DomainError("ERR-CM-06");
  }
  // CA-127: todo lo que puede fallar va antes de la primera escritura. contextRef y subjectRef
  // del sobre salen de la decisión revocada; si no existe, falla cerrado sin escrituras.
  const decision = await ports.consentDecisionRepo.findByConsentIdForUpdate(tenantId, revokedDecisionRef);
  // C6 (GRD-CD-09): solo una decisión GRANTED se revoca; REVOKED = reintento de R4 (converge).
  if (!decision || (decision.state !== "GRANTED" && decision.state !== "REVOKED")) {
    throw new DomainError("ERR-CM-06");
  }
  // SEC-CNS-013 P2-3 / SEC-CNS-015 P1-1: `lastSequence` se capturo ANTES del lock y de la decision de
  // estado; si el agregado avanzo desde entonces el append falla con LedgerSequenceConflictError.
  const rev = await ports.ledger.append({
    expectedSequence: lastSequence,
    eventType: "CONSENT_REVOKED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: {
      revocationRef,
      revokedDecisionRef,
      scope: "ALL", // BETA_2026_01: toda revocación es retiro total (vocabulary.scope).
      effectiveAt: new Date().toISOString(), // hora del append (RULE-CNS-025), nunca del cliente.
      authPath: verifiedAuthPath,
      ...(verifiedAuthPath === "RECOVERY" ? { recoveryMethod: verifiedRecoveryMethod } : {}),
      originPurposeRef: "ALL", // scope ALL en IT0; mismo valor que REVOCATION_REQUESTED.
    },
    idempotencyKey: revocationRef,
  });
  // Recibo de la revocación: receiptRef = revocationRef, el mismo "Comprobante" que muestra la
  // UI de autoservicio/recuperación. managementLinkIssued=false (IT0: sin management_token).
  await ports.ledger.append({
    // Tras un append nuevo el agregado quedó en rev.sequence; ante dedupe de CONSENT_REVOKED no se
    // escribió nada y sigue en lastSequence.
    expectedSequence: Math.max(lastSequence, rev.sequence),
    eventType: "RECEIPT_CREATED",
    tenantId,
    aggregateType: "Revocation",
    aggregateId: revocationRef,
    actorType: "HUMAN",
    actorRole: "DECISION_MAKER",
    payload: { receiptRef: revocationRef, managementLinkIssued: false },
    idempotencyKey: `${revocationRef}:receipt`,
  });
  // effectiveAt se lee del registro devuelto: ante dedupe es el original (un solo reloj).
  const effectiveAt = (rev.payload as { effectiveAt: string }).effectiveAt;
  await ports.outbox.enqueue({
    tenantId,
    eventType: "consent.revoked",
    contextRef: decision.contextRef,
    subjectRef: decision.subjectRef,
    occurredAt: effectiveAt,
    payload: { revocationRef, scope: "ALL", effectiveAt },
    dedupeKey: `${revocationRef}:consent.revoked`,
  });
  // C6 (consent-decision.spec.yaml): GRANTED -> REVOKED en el mismo lote que R4. Ya REVOKED
  // (reintento): no se reproyecta; ledger y outbox ya deduplicaron arriba (sin segundo evento).
  if (decision.state === "GRANTED") {
    await ports.consentDecisionRepo.save({ ...decision, state: "REVOKED" });
  }
  // CA-124: ledger + recibo + outbox + proyección REVOKED + APPLIED confirman juntos en la unidad
  // de trabajo del llamador; si algo falla no queda nada (ni CONFIRMED huérfana) y el reintento
  // converge. La dedupe de ledger/outbox se conserva por idempotencia en reintentos sobre estado
  // ya persistido (p. ej. R4 aplicada por un flujo anterior a UnitOfWork).
  const applied: RevocationRecord = { ...found, status: "APPLIED" };
  await ports.revocationRepo.save(applied);
  return applied;
}

export type Rv0BearerTrigger = "REQUESTER_ASKED" | "LIMIT_REACHED";

export interface Rv0BearerResult {
  readonly sent: boolean;
}

/** SEC-CNS-014: GET /r/{token} (revocation-flow.handler.ts) también hashea con esta función,
 * SIN leer ningún port (el hash es puro), para que el 303 sea idéntico sea o no válido el
 * token. Exportada para ese único uso fuera de este módulo. */
export function hashRecoveryToken(token: string): string {
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
export async function issueRecoveryLinkBearer(
  ports: RevocationPorts,
  tenantId: string,
  chainRef: string,
  revokedDecisionRef: string,
  trigger: Rv0BearerTrigger,
): Promise<Rv0BearerResult> {
  // GRD-RV-02 (precondición de RV0, ERR-RV-02 uniforme): cadena ya REVOKED (C6) o de otro ciclo
  // -> no se emite token ni evento; la respuesta HTTP sigue siendo la uniforme.
  if (await isAlreadyRevoked(ports, tenantId, revokedDecisionRef)) {
    return { sent: false };
  }
  const token = randomBytes(32).toString("hex"); // GRD-RV-06/GRD-IV-05: CSPRNG, opaco, no JWT.
  const tokenHash = hashRecoveryToken(token);
  const recoveryRef = `rec-${randomUUID()}`;
  const expiresAt = new Date(Date.now() + ports.recoveryTokenPolicy.ttlMs);
  // CA-124: token + evento de ledger en una sola unidad de trabajo. El envío al canal (efecto
  // externo, no transaccional) va DESPUÉS de confirmar: si la escritura falla no sale ningún enlace.
  await inTx(ports, tenantId, async (p) => {
    await p.recoveryTokenRepo.save({ tokenHash, recoveryRef, tenantId, chainRef, revokedDecisionRef, expiresAt });
    await appendNext(p.ledger, {
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
  });
  // El token en claro solo vive en este mensaje del sink LOCAL; se descarta al retornar.
  await ports.recoveryLinkChannel.send({ recoveryPath: `/r/${token}` });
  return { sent: true };
}

// ---------------------------------------------------------------------------
// CA-116 PR 2 (UX-CNS-004, recovery): único POST de /recovery/revoke — R1r+R2r+R3r (token
// fresco sobre una cadena sin Revocation abierta o con una REQUESTED existente), R10+R3r
// (token fresco sobre una Revocation VERIFIED, re-verificación) o R11 (NOOP, ya CONFIRMED).
// TEST-CNS-589+.
// ---------------------------------------------------------------------------

/** CA-124 §5: hash -> (tenant, recoveryRef) por el TenantResolverPort (sin tenant) y relectura del
 * registro bajo ese tenant. `null` si el hash no resuelve. No evalúa consumo ni expiración. */
async function findRecoveryTokenByHash(
  ports: Pick<RevocationPorts, "recoveryTokenRepo" | "tenantResolver">,
  tokenHash: string,
): Promise<RecoveryTokenRecord | null> {
  const resolved = await ports.tenantResolver.byRecoveryTokenHash(tokenHash);
  if (!resolved) return null;
  const record = await ports.recoveryTokenRepo.findByRef(resolved.tenantId, resolved.recoveryRef);
  // SEC-CNS-015 P2-A: la ref resuelta debe corresponder al hash pedido (defensa en profundidad).
  return record && record.tokenHash === tokenHash ? record : null;
}

/** SEC-CNS-014 (P1): ya NO la usa el handler HTTP de GET /r/{token} (revocation-flow.handler.ts
 * handleRedeemRecoveryLink), que dejó de leer la BD en el GET (303 uniforme sin validar). Se
 * conserva como helper de dominio, reutilizado por los tests unitarios de este módulo (p. ej.
 * revocation-self-service.test.ts) para obtener el hash real de un token sembrado por
 * issueRecoveryLinkBearer sin duplicar la lógica de hash+lookup. Resuelve el token por su hash
 * SIN consumirlo ni transicionar nada (el consumo ocurre solo en POST /recovery/revoke,
 * revokeWithRecoveryLink). Devuelve `null` si el hash no resuelve, si ya fue consumido o si
 * expiró (GRD-RV-06). */
export async function resolveRecoveryTokenForRedeem(
  ports: Pick<RevocationPorts, "recoveryTokenRepo" | "tenantResolver">,
  token: string,
): Promise<{ tenantId: string; chainRef: string; revokedDecisionRef: string; tokenHash: string } | null> {
  const tokenHash = hashRecoveryToken(token);
  const found = await findRecoveryTokenByHash(ports, tokenHash);
  if (!found) return null;
  if (found.consumedAt) return null;
  if (found.expiresAt.getTime() <= Date.now()) return null;
  return { tenantId: found.tenantId, chainRef: found.chainRef, revokedDecisionRef: found.revokedDecisionRef, tokenHash: found.tokenHash };
}

/** R1r: null -> REQUESTED, authPath RECOVERY/CHANNEL_LINK (mismo POST único de
 * /recovery/revoke, revocation.spec.yaml:197-218). A diferencia de requestRevocation (R1, OTP),
 * siempre crea: el llamador (revokeWithRecoveryLink) solo entra aquí cuando ya confirmó que no
 * hay Revocation abierta para esta cadena (findOpenByChain). */
async function requestRevocationRecovery(
  ports: RevocationPorts,
  tenantId: string,
  chainRef: string,
  revokedDecisionRef: string,
  recoveryRef: string,
): Promise<RevocationRecord> {
  // Ref UUIDv4 opaco (common.schema.json Ref); el prefijo "rv-" incumplía el contrato (FINDING P1).
  const revocationRef = randomUUID();
  const record: RevocationRecord = { revocationRef, tenantId, chainRef, revokedDecisionRef, status: "REQUESTED" };
  await ports.revocationRepo.save(record);
  await ports.ledger.append({
    expectedSequence: 0,
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
async function verifyRevocationRecovery(ports: RevocationPorts, tenantId: string, stale: RevocationRecord, recoveryRef: string): Promise<RevocationRecord> {
  // SEC-CNS-015 P1-1: secuencia antes del lock; `stale` vino de una lectura sin lock (findOpenByChain),
  // asi que se relee con lock y solo se transiciona si sigue REQUESTED/VERIFIED (nunca se pisa FAILED/APPLIED).
  const base = await revocationSequence(ports, tenantId, stale.revocationRef);
  const found = await requireRevocation(ports, tenantId, stale.revocationRef);
  if (found.status !== "REQUESTED" && found.status !== "VERIFIED") {
    throw new DomainError("ERR-CM-06");
  }
  const verified: RevocationRecord = {
    ...found,
    status: "VERIFIED",
    verifiedAuthPath: "RECOVERY",
    verifiedRecoveryMethod: "CHANNEL_LINK",
  };
  await ports.revocationRepo.save(verified);
  await ports.ledger.append({
    expectedSequence: base,
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

export interface RecoveryTokenEligibility {
  readonly tokenRecord: RecoveryTokenRecord;
  /** Revocation abierta (no terminal) de la cadena, si existe. */
  readonly existing: RevocationRecord | null;
}

/**
 * GRD-RV-06 (SEC-CNS-014, FINDING P1-01): predicado puro (sin efectos: no consume el token ni
 * escribe nada), reutilizable por revokeWithRecoveryLink (POST /recovery/revoke, que sí
 * transiciona) y por GET /recovery/confirm en modo solo lectura (siguiente PR). Devuelve null
 * si el "otro ciclo" no es elegible; en ese caso el llamador SIEMPRE responde "UNIFORM"
 * (ERR-RV-05) sin consumir el token ni emitir eventos. Exige, en orden:
 *
 * 1) el token existe, no está consumido/expirado, y coincide con (tenantId, chainRef,
 *    revokedDecisionRef) tal como llegan en la sesión RECOVERY (defensa en profundidad; esos
 *    tres valores se derivaron del mismo tokenRecord en GET /r/{token}, así que esta
 *    comparación por sí sola NUNCA basta para detectar un ciclo viejo -- ver [2]).
 * 2) la decisión GRANTED vigente de la cadena (`consentDecisionRepo.findActiveGrantByChain`,
 *    NUNCA el valor que trae el propio token) es igual a `tokenRecord.revokedDecisionRef`: un
 *    token emitido para D1, sin consumir y dentro de P-15, deja de ser elegible en cuanto la
 *    cadena tiene una GRANTED nueva (D2) -- antes de este fix [1] siempre pasaba porque
 *    comparaba el token contra sí mismo.
 * 3) si hay una Revocation abierta para la cadena, su `revokedDecisionRef` también coincide con
 *    el del token (mismo ciclo que la Revocation en curso, no una entrelazada de otro ciclo).
 */
export async function evaluateRecoveryTokenEligibility(
  ports: Pick<RevocationPorts, "recoveryTokenRepo" | "revocationRepo" | "consentDecisionRepo" | "tenantResolver">,
  tenantId: string,
  chainRef: string,
  revokedDecisionRef: string,
  tokenHash: string,
): Promise<RecoveryTokenEligibility | null> {
  const resolved = await ports.tenantResolver.byRecoveryTokenHash(tokenHash);
  const tokenRecord =
    resolved && resolved.tenantId === tenantId ? await ports.recoveryTokenRepo.findByRef(tenantId, resolved.recoveryRef) : null;
  if (
    !tokenRecord ||
    tokenRecord.tokenHash !== tokenHash || // SEC-CNS-015 P2-A
    tokenRecord.tenantId !== tenantId ||
    tokenRecord.chainRef !== chainRef ||
    tokenRecord.revokedDecisionRef !== revokedDecisionRef ||
    tokenRecord.consumedAt ||
    tokenRecord.expiresAt.getTime() <= Date.now()
  ) {
    return null;
  }

  // [2] SEC-CNS-014 P1-01: la GRANTED vigente real de la cadena, no la que trae el token.
  const activeGrant = await ports.consentDecisionRepo.findActiveGrantByChain(tenantId, chainRef);
  if (!activeGrant || activeGrant.consentId !== tokenRecord.revokedDecisionRef) {
    return null;
  }

  const existing = await ports.revocationRepo.findOpenByChain(tenantId, chainRef);
  if (existing && existing.revokedDecisionRef !== tokenRecord.revokedDecisionRef) {
    return null;
  }

  return { tokenRecord, existing };
}

/**
 * SEC-CNS-014 (GET /r/{token} ya no lee la BD): dado solo el hash del portador
 * (`__Host-cns-recovery`, recovery-handle.ts), resuelve server-side (tenantId, chainRef,
 * revokedDecisionRef) desde `recoveryTokenRepo` (GRD-CM-01), nunca desde la cookie ni el body.
 * Si el hash no resuelve a ningún token (inexistente), devuelve identidad vacía: el llamador
 * (evaluateRecoveryTokenEligibilityByHash / revokeWithRecoveryLinkByHash) igual falla en el
 * primer chequeo de `evaluateRecoveryTokenEligibility` (`!tokenRecord`), sin usar esta
 * identidad vacía para nada más.
 */
async function identityFromTokenHash(
  ports: Pick<RevocationPorts, "recoveryTokenRepo" | "tenantResolver">,
  tokenHash: string,
): Promise<{ tenantId: string; chainRef: string; revokedDecisionRef: string }> {
  const record = await findRecoveryTokenByHash(ports, tokenHash);
  return record
    ? { tenantId: record.tenantId, chainRef: record.chainRef, revokedDecisionRef: record.revokedDecisionRef }
    : { tenantId: "", chainRef: "", revokedDecisionRef: "" };
}

/**
 * GET /recovery/confirm (SEC-CNS-014, INV-CM-08): variante de evaluateRecoveryTokenEligibility
 * que solo necesita el hash (el llamador ya no tiene tenantId/chainRef/revokedDecisionRef
 * resueltos de antes, porque GET /r/{token} ya no los resuelve). Sigue siendo un predicado puro
 * (sin efectos); reutiliza evaluateRecoveryTokenEligibility con la identidad que el propio
 * tokenRecord declara, así que el chequeo [1] de esa función (comparar contra lo que trae la
 * sesión) se vuelve una comparación del registro contra sí mismo — los chequeos [2] (GRANTED
 * vigente real) y [3] (Revocation abierta del mismo ciclo) siguen aplicando sin cambios.
 */
export async function evaluateRecoveryTokenEligibilityByHash(
  ports: Pick<RevocationPorts, "recoveryTokenRepo" | "revocationRepo" | "consentDecisionRepo" | "tenantResolver">,
  tokenHash: string,
): Promise<RecoveryTokenEligibility | null> {
  const { tenantId, chainRef, revokedDecisionRef } = await identityFromTokenHash(ports, tokenHash);
  return evaluateRecoveryTokenEligibility(ports, tenantId, chainRef, revokedDecisionRef, tokenHash);
}

/**
 * POST /recovery/revoke (SEC-CNS-014): variante de revokeWithRecoveryLink que resuelve
 * tenantId/chainRef/revokedDecisionRef en servidor desde el hash del portador (GRD-CM-01),
 * nunca desde la cookie ni el body (la cookie `__Host-cns-recovery` solo trae el hash).
 */
export async function revokeWithRecoveryLinkByHash(ports: RevocationPorts, tokenHash: string): Promise<RecoveryRevokeOutcome> {
  const { tenantId, chainRef, revokedDecisionRef } = await identityFromTokenHash(ports, tokenHash);
  if (tenantId === "") return { kind: "UNIFORM" }; // hash sin token: respuesta uniforme, sin tx ni evento.
  return revokeWithRecoveryLink(ports, tenantId, chainRef, revokedDecisionRef, tokenHash);
}

/**
 * POST /recovery/revoke (API-CNS-135, GRD-RV-06): único punto de entrada del authPath
 * RECOVERY/CHANNEL_LINK. `tenantId`/`chainRef`/`revokedDecisionRef` vienen SIEMPRE de la sesión
 * RECOVERY creada por GET /r/{token} (nunca del body); `tokenHash` es el del token que esa
 * misma sesión ligó al canjear el enlace.
 *
 * - Token inválido/consumido/expirado, ligado a otra cadena/decisión, o de un ciclo que ya no
 *   es el vigente de la cadena (GRD-RV-06 onFail, evaluateRecoveryTokenEligibility): "UNIFORM"
 *   (ERR-RV-05), sin consumir nada ni emitir evento.
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
): Promise<RecoveryRevokeOutcome> {
  // CA-124 (P2 de lampone-security): la elegibilidad, el consumo del token, R1r/R2r|R10, R3r y R4
  // corren en UNA unidad de trabajo. Si R4 falla, el token NO queda consumido, no queda
  // Revocation CONFIRMED ni evento alguno, y el mismo enlace sirve para reintentar hasta APPLIED
  // (antes el reintento caía en R11 NOOP con la Revocation varada en CONFIRMED).
  return inTx(ports, tenantId, (p) => revokeWithRecoveryLinkTx(p, tenantId, chainRef, revokedDecisionRef, tokenHash));
}

async function revokeWithRecoveryLinkTx(
  ports: RevocationPorts,
  tenantId: string,
  chainRef: string,
  revokedDecisionRef: string,
  tokenHash: string,
): Promise<RecoveryRevokeOutcome> {
  const eligibility = await evaluateRecoveryTokenEligibility(ports, tenantId, chainRef, revokedDecisionRef, tokenHash);
  if (!eligibility) {
    // GRD-RV-06 onFail: ERR-RV-05, respuesta uniforme, sin revelar revocationRef, sin evento.
    return { kind: "UNIFORM" };
  }
  const { tokenRecord, existing } = eligibility;

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
  await ports.recoveryTokenRepo.consume(tenantId, tokenRecord.recoveryRef);

  let record: RevocationRecord;
  if (!existing) {
    // R1r: null -> REQUESTED, seguido de R2r en el mismo POST.
    record = await requestRevocationRecovery(ports, tenantId, chainRef, revokedDecisionRef, tokenRecord.recoveryRef);
    record = await verifyRevocationRecovery(ports, tenantId, record, tokenRecord.recoveryRef);
  } else if (existing.status === "VERIFIED") {
    // R10: VERIFIED -> VERIFIED (re-verificación).
    record = await verifyRevocationRecovery(ports, tenantId, existing, tokenRecord.recoveryRef);
  } else {
    // existing.status === "REQUESTED": R2r directo sobre una solicitud abierta por otra vía.
    record = await verifyRevocationRecovery(ports, tenantId, existing, tokenRecord.recoveryRef);
  }

  // R3r: VERIFIED -> CONFIRMED, mismo POST y misma unidad de trabajo (encola R4 síncrono).
  const confirmed = await confirmRevocationTx(ports, tenantId, record.revocationRef);
  return { kind: "CONFIRMED", revocationRef: confirmed.revocationRef };
}
