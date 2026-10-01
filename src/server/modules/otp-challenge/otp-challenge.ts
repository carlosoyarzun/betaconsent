// Gobierna: specs/state-machines/otp-challenge.spec.yaml (V1 RequestOtp, V3 SubmitOtp
// correct_code, V2 SubmitOtp wrong_code, V4 LOCKED) y common.spec.yaml (GRD-CM-02, GRD-CM-05).
// Alcance IT0 de este archivo (subconjunto mínimo, TEST-CNS-483 en adelante): solo scope
// DECISION (padre = Invitation), sin REVOCATION/MANAGE. No implementa V2r (reenvío), V5
// (expiración por barrido, solo se evalúa perezosamente al comparar), V6/V6a (presupuesto
// por clave, requiere ops.otp_budget) ni GRD-OT-08/13 (ligar el challenge al
// handle/sesión que lo pidió: sin infraestructura de handles HTTP en este slice). Los
// parámetros P-01 (longitud), P-02 (TTL) y P-03 (intentos máx.) de SEC-CNS-006 no se fijan
// aquí (esta spec no fija valores); el llamador los inyecta vía `OtpPolicy`. Ver reporte de
// la tarea para el detalle de lo diferido.
//
// V2r (resendOtp, Carlos 2026-09-27): agrega el subconjunto mínimo de V2r (reemplaza el
// código sin reiniciar `attempts` ni el presupuesto, GRD-OT-06). P-06 (límite de reenvíos) no
// tiene valor aprobado en SEC-CNS-006: se modela como `maxResends` en `OtpPolicy`, exigido por
// `otp-policy.config.ts` y sin default de producción (mismo patrón que P-01/P-02/P-03). No
// implementa GRD-OT-13 (challenge_bound_to_request_handle: sin infraestructura de handles HTTP
// en este slice, igual que V1/V3 ya declaran arriba) ni el presupuesto por clave (V6/V6a/V6r).

import { BINDING_RESULT_PLACEHOLDER_OPEN_CT03, opaqueUuidV4 } from "../common/opaque-ref.ts";
import { createHmac, hkdfSync, randomInt, randomUUID, timingSafeEqual } from "node:crypto";

import { DomainError, type DomainErrorCode } from "../common/errors.ts";
import { assertRouteEligible, assertTenantConsistency } from "../common/guards.ts";
import type { TenantId } from "../common/types.ts";
import type { OtpChannelPort } from "../../ports/otp-channel.port.ts";
import type { OtpScope, OtpVerificationRecord, OtpVerificationRepositoryPort } from "../../ports/otp-verification-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { UnitOfWorkPort } from "../../ports/unit-of-work.port.ts";
import type { InvitationPorts } from "../invitation/invitation.ts";
import { invitationPortsInTx, markInvitationVerifiedTx } from "../invitation/invitation.ts";
import { lastLedgerSequence } from "../common/ledger-append.ts";

export interface OtpPolicy {
  /** P-01 (no fijado aquí): dígitos del código. */
  readonly codeLength: number;
  /** P-03 (no fijado aquí): intentos máximos antes de LOCKED. */
  readonly maxAttempts: number;
  /** P-02 (no fijado aquí): vigencia del código en milisegundos. */
  readonly ttlMs: number;
  /** P-06 (no fijado aquí, sin valor aprobado en SEC-CNS-006): reenvíos máximos (V2r,
   * GRD-OT-06) antes de ERR-OT-09. */
  readonly maxResends: number;
}

export interface OtpChallengePorts {
  readonly otpRepo: OtpVerificationRepositoryPort;
  readonly channel: OtpChannelPort;
  readonly ledger: LedgerPort;
  readonly invitation: InvitationPorts;
  /** CA-124 (diseño §5, SEC-CNS-015 P2-E): cada transición corre en UNA unidad de trabajo del tenant
   * (estado + ledger + Invitation I5 en la misma tx); dentro, los repos/ledger del bag son los de la tx.
   * Su tenancy debe compartir `otpRepo` e `invitation.invitationRepo` con este bag. */
  readonly uow: UnitOfWorkPort;
  readonly policy: OtpPolicy;
  /** Análogo de K_otp_env (P-08); IT0 in-memory, inyectado por el llamador. */
  readonly secret: Buffer;
  /** Reloj inyectable (ms epoch) para tests deterministas de expiración; por defecto Date.now (hora de servidor, GRD-CM-12). */
  readonly now?: () => number;
}

/** OTP_ISSUED.channelRef (security-event-payloads: Ref opaco): el canal real (email) nunca va al ledger; HMAC con el
 * secreto del módulo, determinista por (tenant, canal). */
// X6 P2-5: subclave HKDF con info propio, distinta de la clave con que se hashea el código OTP (hashCode usa
// el secreto directo): una colisión de uso entre ambos HMAC no puede revelar el canal ni el código.
const OTP_CHANNEL_REF_HKDF_INFO = "lampone-cns/otp-channel-ref/v1";

export function deriveOtpChannelRefKey(secret: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), OTP_CHANNEL_REF_HKDF_INFO, 32));
}

export function opaqueChannelRef(secret: Buffer, tenantId: TenantId, channelRef: string): string {
  return opaqueUuidV4("otp-channel", `${tenantId}\u0000${channelRef}`, deriveOtpChannelRefKey(secret));
}

const clockMs = (ports: { readonly now?: () => number }): number => (ports.now ?? Date.now)();

function hashCode(secret: Buffer, verificationRef: string, code: string): Buffer {
  return createHmac("sha256", secret).update(`${verificationRef}\u0000${code}`).digest();
}

function generateCode(length: number): string {
  let code = "";
  for (let i = 0; i < length; i += 1) {
    code += String(randomInt(0, 10));
  }
  return code;
}

type RightsOtpPorts = Omit<OtpChallengePorts, "invitation">;

/** Ejecuta `fn` en una unidad de trabajo del tenant; dentro, `otpRepo`, `ledger` (y la Invitation, si el
 * bag la trae) son los de la tx. Las funciones de este modulo no anidan `inTenant`. Si la unidad se
 * reintenta (carrera de secuencia/UNIQUE), `fn` se reejecuta entera: no debe tener efectos fuera de la tx
 * (el envio del codigo va DESPUES del commit). */
function inTx<P extends RightsOtpPorts & { readonly invitation?: InvitationPorts }, T>(
  ports: P,
  tenantId: TenantId,
  fn: (txPorts: P) => Promise<T>,
): Promise<T> {
  return ports.uow.inTenant(tenantId, (tx) =>
    fn({
      ...ports,
      otpRepo: tx.otpRepo,
      ledger: tx.ledger,
      ...(ports.invitation ? { invitation: invitationPortsInTx(ports.invitation, tx) } : {}),
    }),
  );
}

/** Secuencia vigente del challenge: se lee ANTES de bloquear/leer el estado (SEC-CNS-015 P2-E). */
const verificationSequence = (ports: RightsOtpPorts, tenantId: TenantId, verificationRef: string): Promise<number> =>
  lastLedgerSequence(ports.ledger, tenantId, verificationRef);

/** Relee el challenge CON lock de fila (SEC-CNS-015 P2-E): solo dentro de la unidad de trabajo. */
async function requireVerification(ports: RightsOtpPorts, tenantId: TenantId, verificationRef: string): Promise<OtpVerificationRecord> {
  const found = await ports.otpRepo.findByRefForUpdate(tenantId, verificationRef);
  if (!found) {
    throw new DomainError("ERR-CM-01");
  }
  assertTenantConsistency(found.tenantId, tenantId); // GRD-CM-02
  return found;
}

/** Resultado de una unidad de V2/V3/V4: los fallos que DEBEN dejar efecto (intento reservado, LOCKED,
 * EXPIRED + su evento) se confirman y el error se lanza DESPUES del commit; un throw dentro revertiria
 * la reserva del intento (GRD-OT-04, SEC F02). */
type SubmitOutcome = { readonly ok: OtpVerificationRecord } | { readonly fail: DomainErrorCode };

function settle(outcome: SubmitOutcome): OtpVerificationRecord {
  if ("fail" in outcome) {
    throw new DomainError(outcome.fail);
  }
  return outcome.ok;
}

interface SubmitSpec {
  /** Si no es null, el challenge debe ser de ese scope (ERR-OT-01 si no). */
  readonly expectScope: OtpScope | null;
  /** Scope que declaran los eventos OTP_LOCKED/OTP_FAILED. */
  readonly eventScope: OtpScope;
  readonly verifiedPayload: (found: OtpVerificationRecord) => Record<string, unknown>;
  /** Efecto de la verificacion en la misma tx (I5 para scope DECISION). */
  readonly onVerified?: (found: OtpVerificationRecord) => Promise<void>;
}

/** Nucleo de V3/V2/V4 en UNA tx con lock de fila y base previa (SEC-CNS-015 P2-E). */
async function submitCore(
  ports: RightsOtpPorts,
  tenantId: TenantId,
  verificationRef: string,
  code: string,
  spec: SubmitSpec,
): Promise<SubmitOutcome> {
  const base = await verificationSequence(ports, tenantId, verificationRef);
  const found = await requireVerification(ports, tenantId, verificationRef);
  if (spec.expectScope !== null && found.scope !== spec.expectScope) {
    // ERR-OT-05 (OTP_SCOPE_MISUSE): VERIFIED de un scope no sirve para otro.
    throw new DomainError("ERR-OT-01");
  }
  if (found.state === "LOCKED") {
    return { fail: "ERR-OT-04" };
  }
  if (found.state === "VERIFIED" || found.consumedAt) {
    // Replay de un challenge ya consumido (INV-OT-07).
    return { fail: "ERR-OT-03" };
  }
  if (found.expiresAt.getTime() <= clockMs(ports)) {
    // V5 (expiracion perezosa) + GRD-OT-05.
    await ports.otpRepo.save({ ...found, state: "EXPIRED" });
    return { fail: "ERR-OT-03" };
  }

  // GRD-OT-04 (attempts_below_N_atomic): reserva el intento ANTES de comparar (SEC F02).
  const attempts = found.attempts + 1;
  const candidateHash = hashCode(ports.secret, verificationRef, code);
  const storedHash = Buffer.from(found.codeHash, "hex");
  const isCorrect = candidateHash.length === storedHash.length && timingSafeEqual(candidateHash, storedHash); // GRD-OT-07

  if (isCorrect) {
    const verified: OtpVerificationRecord = { ...found, attempts, state: "VERIFIED", consumedAt: new Date() };
    await ports.otpRepo.save(verified);
    await ports.ledger.append({
      expectedSequence: base,
      eventType: "DECISION_MAKER_CHANNEL_VERIFIED",
      tenantId,
      aggregateType: "DecisionMakerVerification",
      aggregateId: verificationRef,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: spec.verifiedPayload(found),
      idempotencyKey: `${verificationRef}:verified`,
    });
    if (spec.onVerified) {
      await spec.onVerified(found); // I5 en la misma tx: si falla, el challenge no queda VERIFIED.
    }
    return { ok: verified };
  }

  if (attempts >= ports.policy.maxAttempts) {
    const locked: OtpVerificationRecord = { ...found, attempts, state: "LOCKED" };
    await ports.otpRepo.save(locked);
    await ports.ledger.append({
      expectedSequence: base,
      eventType: "OTP_LOCKED",
      tenantId,
      aggregateType: "DecisionMakerVerification",
      aggregateId: verificationRef,
      actorType: "SYSTEM_GUARD",
      payload: { verificationRef, scope: spec.eventScope },
      idempotencyKey: `${verificationRef}:locked`,
    });
    return { fail: "ERR-OT-04" };
  }

  const failed: OtpVerificationRecord = { ...found, attempts, state: "CODE_SENT" };
  await ports.otpRepo.save(failed);
  await ports.ledger.append({
    expectedSequence: base,
    eventType: "OTP_FAILED",
    tenantId,
    aggregateType: "DecisionMakerVerification",
    aggregateId: verificationRef,
    actorType: "HUMAN",
    actorRole: "UNVERIFIED_BEARER",
    payload: { verificationRef, scope: spec.eventScope },
    idempotencyKey: `${verificationRef}:failed:${attempts}`,
  });
  return { fail: "ERR-OT-02" };
}

interface Issued {
  readonly record: OtpVerificationRecord;
  /** Codigo en claro a enviar DESPUES del commit; ausente si se devolvio el challenge activo. */
  readonly code?: string;
}

/** Crea el challenge (agregado nuevo: expectedSequence 0) dentro de la tx; el envio va fuera. */
async function issueChallengeTx(
  ports: RightsOtpPorts,
  tenantId: TenantId,
  verificationRef: string,
  scope: OtpScope,
  parentRef: string,
  channelRef: string,
): Promise<Issued> {
  const code = generateCode(ports.policy.codeLength);
  const codeHash = hashCode(ports.secret, verificationRef, code).toString("hex");
  const record: OtpVerificationRecord = {
    verificationRef,
    tenantId,
    scope,
    parentRef,
    channelRef,
    codeHash,
    attempts: 0,
    expiresAt: new Date(clockMs(ports) + ports.policy.ttlMs),
    state: "CODE_SENT",
    resendCount: 0,
  };
  await ports.otpRepo.save(record);
  await ports.ledger.append({
    expectedSequence: 0, // agregado nuevo; la carrera por el padre la resuelve el UNIQUE parcial GRD-OT-08
    eventType: "OTP_ISSUED",
    tenantId,
    aggregateType: "DecisionMakerVerification",
    aggregateId: verificationRef,
    actorType: "HUMAN",
    actorRole: "UNVERIFIED_BEARER",
    payload: { verificationRef, scope, channelRef: opaqueChannelRef(ports.secret, tenantId, channelRef) },
    idempotencyKey: `${verificationRef}:issued`,
  });
  return { record, code };
}

/** Challenge activo vigente del padre, bajo lock. Si el activo ya expiro (hora de servidor >= expiresAt, P-02),
 * pasa a EXPIRED y deja de ser activo: otp-challenge.spec V5 ("se puede crear un challenge nuevo") y estado EXPIRED terminal;
 * devuelve null para que V1 emita uno nuevo. SEC-CNS-016 P2-3 (disponibilidad). No emite OTP_EXPIRED (igual
 * que la expiracion perezosa de V3). */
async function activeUnexpired(ports: RightsOtpPorts, tenantId: TenantId, parentRef: string, scope: OtpScope): Promise<OtpVerificationRecord | null> {
  const active = await ports.otpRepo.findActiveByParent(tenantId, parentRef, scope);
  if (!active) return null;
  if (active.expiresAt.getTime() > clockMs(ports)) return active;
  const locked = await ports.otpRepo.findByRefForUpdate(tenantId, active.verificationRef);
  if (!locked || (locked.state !== "CODE_SENT" && locked.state !== "NOT_STARTED")) return null;
  await ports.otpRepo.save({ ...locked, state: "EXPIRED" });
  return null;
}

/** Ref para un challenge nuevo: si la pedida ya existe (p.ej. la de un challenge expirado guardada en la sesion), se
 * usa una fresca; un challenge terminal nunca se reutiliza (INV-OT-07) y la key `:issued` dedupearia el evento. */
async function freshRef(ports: RightsOtpPorts, tenantId: TenantId, requested: string): Promise<string> {
  return (await ports.otpRepo.findByRef(tenantId, requested)) ? randomUUID() : requested;
}

/** Envia el codigo tras el commit (INV-OT-02: el codigo en claro no sale de aqui). */
async function deliver(ports: RightsOtpPorts, issued: Issued, verificationRef: string, channelRef: string): Promise<OtpVerificationRecord> {
  if (issued.code !== undefined) {
    await ports.channel.send({ channelRef, verificationRef, code: issued.code });
  }
  return issued.record;
}

/** V1: NOT_STARTED -> CODE_SENT (scope DECISION). Guards: GRD-CM-02, GRD-CM-05, GRD-OT-01, GRD-OT-02, GRD-OT-08 (subconjunto). */
export async function requestOtp(
  ports: OtpChallengePorts,
  tenantId: TenantId,
  verificationRef: string,
  invitationRef: string,
  channelRef: string,
): Promise<OtpVerificationRecord> {
  const issued = await inTx(ports, tenantId, async (p): Promise<Issued> => {
    const invitation = await p.invitation.invitationRepo.findByRefForUpdate(tenantId, invitationRef); // lock: V1 decide sobre la Invitation (SEC-CNS-016 P2-4)
    if (!invitation) {
      throw new DomainError("ERR-CM-01");
    }
    assertTenantConsistency(invitation.tenantId, tenantId); // GRD-CM-02

    if (invitation.state !== "OPENED" && invitation.state !== "VERIFIED") {
      // GRD-OT-01 (valid_parent_by_scope), byScope DECISION: Invitation OPENED | VERIFIED (M4).
      throw new DomainError("ERR-OT-01");
    }
    if (!invitation.recipientChannelRef || invitation.recipientChannelRef !== channelRef) {
      // GRD-OT-02 (bound_channel_only): solo al canal ligado, nunca uno aportado por el cliente.
      throw new DomainError("ERR-OT-08");
    }
    assertRouteEligible(
      await p.invitation.eligibility.isEligibleForIssuance(tenantId, invitation.contextRef, invitation.productRef),
    ); // GRD-CM-05 (guardsByScope.DECISION)

    const active = await activeUnexpired(p, tenantId, invitationRef, "DECISION");
    if (active) {
      // GRD-OT-08 (subconjunto): V1 repetido sobre el mismo padre es idempotente (mismo challenge activo).
      return { record: active };
    }
    return issueChallengeTx(p, tenantId, await freshRef(p, tenantId, verificationRef), "DECISION", invitationRef, channelRef);
  });
  return deliver(ports, issued, issued.record.verificationRef, channelRef);
}

/** V3/V2/V4: intenta verificar el código. Correcto -> VERIFIED (dispara I5 en la misma tx). Incorrecto -> V2/V4. */
export async function submitOtp(
  ports: OtpChallengePorts,
  tenantId: TenantId,
  verificationRef: string,
  code: string,
  decisionMakerRef: string,
): Promise<OtpVerificationRecord> {
  const outcome = await inTx(ports, tenantId, (p) =>
    submitCore(p, tenantId, verificationRef, code, {
      expectScope: null,
      eventScope: "DECISION",
      verifiedPayload: (found) => ({ verificationRef, parentRef: found.parentRef, decisionMakerRef, scope: "DECISION", method: "EMAIL_OTP", bindingResult: BINDING_RESULT_PLACEHOLDER_OPEN_CT03 }),
      onVerified: async (found) => {
        await markInvitationVerifiedTx(p.invitation, tenantId, found.parentRef, decisionMakerRef, verificationRef); // I5
      },
    }),
  );
  return settle(outcome);
}

// ---------------------------------------------------------------------------
// CA-116 (revocación IT0, UX-CNS-004): subconjunto mínimo de V1/V3 para scope REVOCATION/MANAGE
// (routeClass RIGHTS, padre = chainRef). A diferencia de requestOtp/submitOtp (scope DECISION),
// estas funciones NO dependen de InvitationPorts: el llamador (consent-flow.handler.ts) ya
// resolvió el chainRef y validó GRD-OT-01 byScope (REVOCATION: chain con GRANTED vigente;
// MANAGE: chain existente con alguna decisión) usando el propio handle MANAGE_ENTRY ya
// resuelto por TenantHandlePort al crear la sesión (GET /m/{token}); repetir esa validación
// aquí exigiría inyectar ConsentDecisionPorts en este módulo, fuera del subconjunto mínimo de
// este slice (ver reporte de la tarea). channelRef es un valor opaco derivado del chainRef
// (nunca del cliente, GRD-OT-02 trivialmente satisfecho porque es siempre el mismo valor
// para el mismo chainRef). No implementa V2r, V6/V6a/V6r/V6c (presupuesto/rotación) ni
// GRD-OT-13 (bound_to_request_handle): mismo alcance mínimo que requestOtp/submitOtp arriba.
// ---------------------------------------------------------------------------

/** V1 byScope REVOCATION/MANAGE: NOT_STARTED -> CODE_SENT. */
export async function requestRightsOtp(
  ports: RightsOtpPorts,
  tenantId: TenantId,
  verificationRef: string,
  scope: "REVOCATION" | "MANAGE",
  chainRef: string,
  channelRef: string,
): Promise<OtpVerificationRecord> {
  const issued = await inTx(ports, tenantId, async (p): Promise<Issued> => {
    const active = await activeUnexpired(p, tenantId, chainRef, scope);
    if (active) {
      // GRD-OT-08 (subconjunto): idempotente, mismo challenge activo.
      return { record: active };
    }
    return issueChallengeTx(p, tenantId, await freshRef(p, tenantId, verificationRef), scope, chainRef, channelRef);
  });
  return deliver(ports, issued, issued.record.verificationRef, channelRef);
}

/**
 * V3/V2/V4 byScope REVOCATION/MANAGE: intenta verificar el código. A diferencia de submitOtp
 * (scope DECISION), NO dispara I5 (no hay Invitation que verificar); el efecto scope-específico
 * (fijar session.manageDecisionMakerRef, habilitar R2) lo hace el llamador HTTP con el
 * `OtpVerificationRecord` devuelto.
 */
export async function submitRightsOtp(
  ports: RightsOtpPorts,
  tenantId: TenantId,
  verificationRef: string,
  scope: "REVOCATION" | "MANAGE",
  code: string,
  decisionMakerRef: string,
): Promise<OtpVerificationRecord> {
  const outcome = await inTx(ports, tenantId, (p) =>
    submitCore(p, tenantId, verificationRef, code, {
      expectScope: scope,
      eventScope: scope,
      verifiedPayload: (found) => ({ verificationRef, parentRef: found.parentRef, decisionMakerRef, scope, method: "EMAIL_OTP", bindingResult: BINDING_RESULT_PLACEHOLDER_OPEN_CT03 }),
    }),
  );
  return settle(outcome);
}

/**
 * V2r: CODE_SENT -> CODE_SENT (ResendOtp). Reemplaza codeHash sin reiniciar `attempts` ni el
 * presupuesto (GRD-OT-06); mismo canal ligado (GRD-OT-02, ya validado al emitir el challenge
 * original). No implementa GRD-OT-13 (bound_to_request_handle): ver nota de alcance arriba.
 * Lock de fila + base previa (SEC-CNS-015 P2-E); el envio va tras el commit.
 */
export async function resendOtp(ports: OtpChallengePorts, tenantId: TenantId, verificationRef: string): Promise<OtpVerificationRecord> {
  type ResendOutcome = { readonly ok: { readonly record: OtpVerificationRecord; readonly code: string } } | { readonly fail: DomainErrorCode };
  const outcome = await inTx(ports, tenantId, async (p): Promise<ResendOutcome> => {
    const base = await verificationSequence(p, tenantId, verificationRef);
    const found = await requireVerification(p, tenantId, verificationRef);

    if (found.state === "LOCKED") {
      return { fail: "ERR-OT-04" };
    }
    if (found.state !== "CODE_SENT" || found.consumedAt) {
      // VERIFIED (ya consumido) o EXPIRED: replay de un challenge terminal (INV-OT-07 análogo).
      return { fail: "ERR-OT-03" };
    }
    if (found.expiresAt.getTime() <= clockMs(p)) {
      await p.otpRepo.save({ ...found, state: "EXPIRED" });
      return { fail: "ERR-OT-03" };
    }
    if (found.resendCount >= p.policy.maxResends) {
      // GRD-OT-06 (resend_limits, P-06): límite alcanzado, el challenge no cambia.
      return { fail: "ERR-OT-09" };
    }

    const code = generateCode(p.policy.codeLength);
    const codeHash = hashCode(p.secret, verificationRef, code).toString("hex");
    const resent: OtpVerificationRecord = { ...found, codeHash, resendCount: found.resendCount + 1 };
    await p.otpRepo.save(resent);
    await p.ledger.append({
      expectedSequence: base,
      eventType: "OTP_ISSUED",
      tenantId,
      aggregateType: "DecisionMakerVerification",
      aggregateId: verificationRef,
      actorType: "HUMAN",
      actorRole: "UNVERIFIED_BEARER",
      payload: { verificationRef, scope: "DECISION", channelRef: opaqueChannelRef(p.secret, tenantId, found.channelRef) },
      idempotencyKey: `${verificationRef}:resend:${resent.resendCount}`,
    });
    return { ok: { record: resent, code } };
  });
  if ("fail" in outcome) {
    throw new DomainError(outcome.fail);
  }
  // INV-OT-02: el código en claro nunca sale de aquí, y solo tras confirmar.
  await ports.channel.send({ channelRef: outcome.ok.record.channelRef, verificationRef, code: outcome.ok.code });
  return outcome.ok.record;
}
