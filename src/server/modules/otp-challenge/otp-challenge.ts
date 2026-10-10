// Gobierna: specs/state-machines/otp-challenge.spec.yaml (V1 RequestOtp, V3 SubmitOtp
// correct_code, V2 SubmitOtp wrong_code, V4 LOCKED) y common.spec.yaml (GRD-CM-02, GRD-CM-05).
// SEC-CNS-021 PR-2 (F-1): OTP_ISSUED/FAILED/LOCKED se escriben en ops.security_event (tx.securityEvents) en la MISMA tx que el estado del
// challenge; en el ledger solo queda DECISION_MAKER_CHANNEL_VERIFIED (V3, expectedSequence 0). La valla de concurrencia es el lock de fila
// de app.otp_verification (findByRefForUpdate), ya no la secuencia del ledger.
//
// SEC-CNS-021 PR-4 (CA-146 / DF-10, F-4, F-5; D6, D8 de Carlos 2026-10-08): presupuesto de fallos por clave (ops.otp_budget, P-04/P-04a/b/c/P-05), V6 (DECISION)
// y V6r (RIGHTS) al agotarse, V6a (3.er challenge LOCKED de una invitacion -> invitation.otp_exhausted, P-07 DECISION, GRD-OT-09/14) y P-06 en V2r
// (>= 60 s entre envios y <= 3 envios por hora por verificacion; el envio INICIAL de V1 cuenta, D8). `maxResends` se retiro: P-06 lo reemplaza.
// DIFERIDO (D6): el tope RIGHTS DAYS_30 (P-07, V6c, rotacion del management token): P07_RIGHTS_DAYS_30_CAP_ENFORCED = false; el unico tope de RIGHTS es P-04 DAY_1.
//
// ORDEN DE LOCKS (F-4, P1; sin riesgo de deadlock). TODOS los caminos que toman mas de un lock lo hacen en este orden global:
//   1. app.invitation (SOLO scope DECISION; FOR UPDATE)            -> V1 (requestOtp), V2/V3/V4/V6/V6a (submitOtp) y V2r (resendOtp, scope DECISION)
//   2. app.otp_verification (FOR UPDATE, por verificationRef)
//   3. ops.otp_budget (filas de las claves, via INSERT ... ON CONFLICT DO UPDATE), SIEMPRE en el orden CHANNEL y luego INVITATION|CHAIN (otp-budget.ts)
//   4. filas nuevas (ops.security_event, integrity.audit_event)
// Un camino puede omitir niveles (RIGHTS no tiene invitacion; V1 solo lee el presupuesto) pero nunca invertir su orden relativo. Antes de PR-4
// submitOtp bloqueaba challenge -> invitacion (via I5/V6a) mientras V1 bloqueaba invitacion -> challenge: ciclo posible. Ahora submitOtp/resendOtp leen
// el challenge SIN lock (scope y parentRef son inmutables), bloquean la invitacion y recien entonces bloquean el challenge (lockParentThenChallenge).
// V4/V6a y V1 comparten el lock de la invitacion: un V1 concurrente con el 3.er LOCKED se evalua DESPUES de V6a y ve otp_exhausted (SEC N-09, GRD-OT-09).
//
// Alcance IT0 de este archivo: GRD-OT-13 (ligar el challenge al handle/sesion que lo pidio) sigue sin implementarse (sin infraestructura de handles en este slice);
// V5 (expiracion) se evalua perezosamente al comparar o reenviar. Los parametros P-01 (6 digitos), P-02 (10 min) y P-03 (5 intentos) de SEC-CNS-006 rev. 5 §1 estan
// APROBADOS por Carlos (approved-parameters.ts) y son el default de otp-policy.config.ts; el llamador los inyecta via `OtpPolicy`. P-04, P-06 y P-07 se
// resuelven con `budgetPolicy` (default aprobado; overrides solo LOCAL via el loader).

import { BINDING_RESULT_PLACEHOLDER_OPEN_CT03, opaqueUuidV4 } from "../common/opaque-ref.ts";
import { createHmac, hkdfSync, randomInt, randomUUID, timingSafeEqual } from "node:crypto";

import {
  APPROVED_P04_OTP_BUDGET_MAX_FAILURES,
  APPROVED_P04_OTP_BUDGET_WINDOW_MS,
  APPROVED_P06_OTP_MAX_SENDS_PER_HOUR,
  APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS,
  APPROVED_P06_OTP_SEND_WINDOW_MS,
  APPROVED_P07_OTP_DECISION_MAX_LOCKED_CHALLENGES,
} from "../common/approved-parameters.ts";

import { DomainError, type DomainErrorCode } from "../common/errors.ts";
import { assertRouteEligible, assertTenantConsistency } from "../common/guards.ts";
import type { TenantId } from "../common/types.ts";
import type { OtpChannelPort } from "../../ports/otp-channel.port.ts";
import type { OtpScope, OtpVerificationRecord, OtpVerificationRepositoryPort } from "../../ports/otp-verification-repository.port.ts";
import type { InvitationRecord } from "../../ports/invitation-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { OtpBudgetPort } from "../../ports/otp-budget.port.ts";
import type { SecurityEventPort } from "../../ports/security-event.port.ts";
import type { UnitOfWorkPort } from "../../ports/unit-of-work.port.ts";
import type { InvitationPorts } from "../invitation/invitation.ts";
import { invitationPortsInTx, markInvitationVerifiedTx } from "../invitation/invitation.ts";
import { otpBudgetKeys, scopeClassOf } from "./otp-budget.ts";

export interface OtpPolicy {
  /** P-01 (aprobado: 6; approved-parameters.ts): dígitos del código. */
  readonly codeLength: number;
  /** P-03 (aprobado: 5): intentos máximos antes de LOCKED. */
  readonly maxAttempts: number;
  /** P-02 (aprobado: 10 min): vigencia del código en milisegundos. */
  readonly ttlMs: number;
  /** P-04 (aprobado: 10 fallos por clave y ventana DAY_1). Opcional: ausente = valor aprobado. Un override distinto solo se admite en LOCAL (otp-policy.config.ts). */
  readonly budgetMaxFailures?: number;
  /** P-04 (aprobado: ventana fija de 24 h desde el primer fallo). Opcional: ausente = valor aprobado. */
  readonly budgetWindowMs?: number;
  /** P-07 DECISION (aprobado: 3 challenges LOCKED por invitacion -> V6a). Opcional: ausente = valor aprobado. */
  readonly maxLockedChallenges?: number;
  /** P-06 (aprobado: >= 60 s entre envíos de una verificación). Opcional: ausente = valor aprobado. */
  readonly minResendIntervalMs?: number;
  /** P-06 (aprobado: <= 3 envíos por hora por verificación, el inicial incluido; D8). Opcional: ausente = valor aprobado. */
  readonly maxSendsPerHour?: number;
}

/** Parametros P-04/P-06/P-07 resueltos: el valor del `OtpPolicy` o, si falta, el APROBADO (approved-parameters.ts). */
function budgetPolicy(policy: OtpPolicy): {
  readonly maxFailures: number;
  readonly windowMs: number;
  readonly maxLocked: number;
  readonly minResendIntervalMs: number;
  readonly maxSendsPerHour: number;
} {
  return {
    maxFailures: policy.budgetMaxFailures ?? APPROVED_P04_OTP_BUDGET_MAX_FAILURES,
    windowMs: policy.budgetWindowMs ?? APPROVED_P04_OTP_BUDGET_WINDOW_MS,
    maxLocked: policy.maxLockedChallenges ?? APPROVED_P07_OTP_DECISION_MAX_LOCKED_CHALLENGES,
    minResendIntervalMs: policy.minResendIntervalMs ?? APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS,
    maxSendsPerHour: policy.maxSendsPerHour ?? APPROVED_P06_OTP_MAX_SENDS_PER_HOUR,
  };
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

/** Puertos de UNA tx: los de `RightsOtpPorts` ligados a la unidad + `securityEvents` (ops.security_event). SEC-CNS-021 PR-2 (F-1,
 * INV-21-02): OTP_ISSUED/FAILED/LOCKED se escriben ahi, en la MISMA tx que el estado del challenge, y no en el ledger. */
type OtpTxPorts = RightsOtpPorts & {
  readonly securityEvents: SecurityEventPort;
  /** SEC-CNS-021 PR-4: presupuesto de fallos (ops.otp_budget) de la tx. */
  readonly otpBudget: OtpBudgetPort;
  /** Solo scope DECISION (V1/V2/V3/V4/V6/V6a/V2r): puertos de la Invitation ligados a la tx. */
  readonly invitation?: InvitationPorts;
};

/** Ejecuta `fn` en una unidad de trabajo del tenant; dentro, `otpRepo`, `ledger` (y la Invitation, si el
 * bag la trae) son los de la tx. Las funciones de este modulo no anidan `inTenant`. Si la unidad se
 * reintenta (carrera de secuencia/UNIQUE), `fn` se reejecuta entera: no debe tener efectos fuera de la tx
 * (el envio del codigo va DESPUES del commit). */
function inTx<P extends RightsOtpPorts & { readonly invitation?: InvitationPorts }, T>(
  ports: P,
  tenantId: TenantId,
  fn: (txPorts: P & { readonly securityEvents: SecurityEventPort; readonly otpBudget: OtpBudgetPort }) => Promise<T>,
): Promise<T> {
  return ports.uow.inTenant(tenantId, (tx) =>
    fn({
      ...ports,
      otpRepo: tx.otpRepo,
      ledger: tx.ledger,
      securityEvents: tx.securityEvents,
      otpBudget: tx.otpBudget,
      ...(ports.invitation ? { invitation: invitationPortsInTx(ports.invitation, tx) } : {}),
    }),
  );
}

/** Relee el challenge CON lock de fila (SEC-CNS-015 P2-E): solo dentro de la unidad de trabajo. */
async function requireVerification(ports: RightsOtpPorts, tenantId: TenantId, verificationRef: string): Promise<OtpVerificationRecord> {
  const found = await ports.otpRepo.findByRefForUpdate(tenantId, verificationRef);
  if (!found) {
    throw new DomainError("ERR-CM-01");
  }
  assertTenantConsistency(found.tenantId, tenantId); // GRD-CM-02
  return found;
}

/**
 * F-4 (orden de locks, ver cabecera): lee el challenge SIN lock solo para conocer scope y parentRef (inmutables), bloquea la invitacion padre (scope
 * DECISION) y recien despues bloquea el challenge (releyendo el estado confirmado). Evita el ciclo invitacion<->challenge con V1.
 */
async function lockParentThenChallenge(
  ports: OtpTxPorts,
  tenantId: TenantId,
  verificationRef: string,
): Promise<{ readonly found: OtpVerificationRecord; readonly invitation: InvitationRecord | null }> {
  const peek = await ports.otpRepo.findByRef(tenantId, verificationRef);
  if (!peek) {
    throw new DomainError("ERR-CM-01");
  }
  let invitation: InvitationRecord | null = null;
  if (peek.scope === "DECISION" && ports.invitation) {
    invitation = await ports.invitation.invitationRepo.findByRefForUpdate(tenantId, peek.parentRef);
  }
  const found = await requireVerification(ports, tenantId, verificationRef);
  return { found, invitation };
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

/** ERR-OT-06 (DECISION: la via es reemitir la invitacion) o ERR-OT-07 (RIGHTS: respuesta uniforme, RECOVERY visible). */
function budgetExhaustedError(scope: OtpScope): DomainErrorCode {
  return scopeClassOf(scope) === "DECISION" ? "ERR-OT-06" : "ERR-OT-07";
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
  ports: OtpTxPorts,
  tenantId: TenantId,
  verificationRef: string,
  code: string,
  spec: SubmitSpec,
): Promise<SubmitOutcome> {
  // SEC-CNS-021 PR-2 (valla de concurrencia): la unica fila del ledger de este agregado es DECISION_MAKER_CHANNEL_VERIFIED
  // (sequence 1, expectedSequence 0). La valla ya no es la secuencia (los OTP_* salieron del ledger) sino el lock de fila de
  // app.otp_verification (findByRefForUpdate): un V3 concurrente espera, relee VERIFIED y sale por ERR-OT-03 sin llegar al append.
  const { found, invitation } = await lockParentThenChallenge(ports, tenantId, verificationRef); // F-4: invitacion -> challenge
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

  // GRD-OT-03 (budget_by_scope_class, P-04/P-05): reserva atomica de un fallo en cada clave aplicable, ANTES de comparar y en la misma tx que GRD-OT-04.
  // Sin cupo en alguna clave -> rechazo SIN comparar: V6 (DECISION, ERR-OT-06) o V6r (RIGHTS, ERR-OT-07); el challenge pasa a FAILED y queda
  // OTP_BUDGET_EXHAUSTED. La Revocation de la cadena no se toca (V6r nunca la deniega). El rechazo no consume el intento (no se comparo).
  const budget = budgetPolicy(ports.policy);
  const budgetKeys = otpBudgetKeys(ports.secret, tenantId, found.scope, found.parentRef, found.channelRef);
  const exhausted = await ports.otpBudget.reserveFailure(tenantId, budgetKeys, new Date(clockMs(ports)), budget.windowMs, budget.maxFailures);
  if (exhausted) {
    await ports.otpRepo.save({ ...found, state: "FAILED" });
    await ports.securityEvents.record({
      tenantId,
      eventType: "OTP_BUDGET_EXHAUSTED",
      verificationRef,
      scopeClass: exhausted.scopeClass,
      keyKind: exhausted.keyKind,
      windowKind: exhausted.windowKind,
    });
    return { fail: budgetExhaustedError(found.scope) };
  }

  // GRD-OT-04 (attempts_below_N_atomic): reserva el intento ANTES de comparar (SEC F02).
  const attempts = found.attempts + 1;
  const candidateHash = hashCode(ports.secret, verificationRef, code);
  const storedHash = Buffer.from(found.codeHash, "hex");
  const isCorrect = candidateHash.length === storedHash.length && timingSafeEqual(candidateHash, storedHash); // GRD-OT-07

  if (isCorrect) {
    await ports.otpBudget.releaseFailure(tenantId, budgetKeys); // los aciertos no consumen presupuesto (P-04)
    const verified: OtpVerificationRecord = { ...found, attempts, state: "VERIFIED", consumedAt: new Date() };
    await ports.otpRepo.save(verified);
    await ports.ledger.append({
      expectedSequence: 0,
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
    await ports.securityEvents.record({ tenantId, eventType: "OTP_LOCKED", verificationRef, otpScope: spec.eventScope });
    if (found.scope === "DECISION" && invitation && ports.invitation) {
      // V6a (GRD-OT-09, P-07): contabilidad del padre bajo el lock de la invitacion ya tomado. El challenge LOCKED no transiciona (R13-7).
      const lockedCount = await ports.otpRepo.countLockedByParent(tenantId, found.parentRef, "DECISION");
      if (lockedCount >= budget.maxLocked && invitation.otpExhausted !== true) {
        await ports.invitation.invitationRepo.markOtpExhausted(tenantId, found.parentRef);
        await ports.securityEvents.record({ tenantId, eventType: "OTP_BUDGET_EXHAUSTED", verificationRef, scopeClass: "DECISION", keyKind: "INVITATION", windowKind: "DAY_1" });
      }
    }
    return { fail: "ERR-OT-04" };
  }

  const failed: OtpVerificationRecord = { ...found, attempts, state: "CODE_SENT" };
  await ports.otpRepo.save(failed);
  await ports.securityEvents.record({ tenantId, eventType: "OTP_FAILED", verificationRef, otpScope: spec.eventScope });
  return { fail: "ERR-OT-02" };
}

interface Issued {
  readonly record: OtpVerificationRecord;
  /** Codigo en claro a enviar DESPUES del commit; ausente si se devolvio el challenge activo. */
  readonly code?: string;
}

/** Crea el challenge (agregado nuevo: expectedSequence 0) dentro de la tx; el envio va fuera. */
async function issueChallengeTx(
  ports: OtpTxPorts,
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
    // P-06 (D8): el envio inicial cuenta como el primero de la ventana de 1 h.
    lastSentAt: new Date(clockMs(ports)),
    sendsWindowStart: new Date(clockMs(ports)),
    sendsInWindow: 1,
  };
  await ports.otpRepo.save(record);
  // La carrera por el padre la resuelve el UNIQUE parcial GRD-OT-08 (la tx entera revierte, evento incluido).
  await ports.securityEvents.record({
    tenantId,
    eventType: "OTP_ISSUED",
    verificationRef,
    otpScope: scope,
    channelRef: opaqueChannelRef(ports.secret, tenantId, channelRef),
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

/** GRD-OT-03 en V1: lanza ERR-OT-06/07 si alguna clave aplicable ya no tiene cupo en su ventana vigente. Solo lectura. */
async function assertBudgetCapacity(
  ports: OtpTxPorts,
  tenantId: TenantId,
  scope: OtpScope,
  parentRef: string,
  channelRef: string,
): Promise<void> {
  const budget = budgetPolicy(ports.policy);
  const keys = otpBudgetKeys(ports.secret, tenantId, scope, parentRef, channelRef);
  if (await ports.otpBudget.findExhausted(tenantId, keys, new Date(clockMs(ports)), budget.maxFailures)) {
    throw new DomainError(budgetExhaustedError(scope));
  }
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
    if (invitation.otpExhausted === true) {
      // GRD-OT-14 (parent_not_otp_exhausted): V6a ya marco la invitacion (bajo este mismo lock); la via es reemitirla.
      throw new DomainError("ERR-OT-06");
    }
    // GRD-OT-03 en V1: solo SELECT, sin cupo en alguna clave -> respuesta generica (el borde HTTP la hace uniforme). No reserva.
    await assertBudgetCapacity(p, tenantId, "DECISION", invitationRef, channelRef);

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
  decisionMakerRefKeyVersion: number,
): Promise<OtpVerificationRecord> {
  const outcome = await inTx(ports, tenantId, (p) =>
    submitCore(p, tenantId, verificationRef, code, {
      expectScope: null,
      eventScope: "DECISION",
      verifiedPayload: (found) => ({ verificationRef, parentRef: found.parentRef, decisionMakerRef, decisionMakerRefKeyVersion, scope: "DECISION", method: "EMAIL_OTP", bindingResult: BINDING_RESULT_PLACEHOLDER_OPEN_CT03 }),
      onVerified: async (found) => {
        await markInvitationVerifiedTx(p.invitation, tenantId, found.parentRef, decisionMakerRef, decisionMakerRefKeyVersion, verificationRef); // I5
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
    await assertBudgetCapacity(p, tenantId, scope, chainRef, channelRef); // GRD-OT-03 / V6r (ERR-OT-07)
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
  decisionMakerRefKeyVersion: number,
): Promise<OtpVerificationRecord> {
  const outcome = await inTx(ports, tenantId, (p) =>
    submitCore(p, tenantId, verificationRef, code, {
      expectScope: scope,
      eventScope: scope,
      verifiedPayload: (found) => ({ verificationRef, parentRef: found.parentRef, decisionMakerRef, decisionMakerRefKeyVersion, scope, method: "EMAIL_OTP", bindingResult: BINDING_RESULT_PLACEHOLDER_OPEN_CT03 }),
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
    const { found } = await lockParentThenChallenge(p, tenantId, verificationRef); // F-4: invitacion (DECISION) -> challenge; el lock de fila es la valla (PR-2)

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
    // GRD-OT-06 (resend_limits, P-06; D8: el envio inicial de V1 cuenta), con hora de servidor y bajo el lock del challenge. Si el limite se alcanza,
    // el challenge no cambia (ERR-OT-09). Sin marcas (fila anterior a 0032) = sin envios registrados.
    const budget = budgetPolicy(p.policy);
    const nowMs = clockMs(p);
    if (found.lastSentAt !== undefined && nowMs - found.lastSentAt.getTime() < budget.minResendIntervalMs) {
      return { fail: "ERR-OT-09" }; // < 60 s desde el ultimo envio
    }
    let windowStartMs = found.sendsWindowStart?.getTime();
    let sendsInWindow = found.sendsInWindow ?? 0;
    if (windowStartMs === undefined || windowStartMs + APPROVED_P06_OTP_SEND_WINDOW_MS <= nowMs) {
      windowStartMs = nowMs; // ventana de 1 h vencida: arranca otra desde este envio
      sendsInWindow = 0;
    }
    if (sendsInWindow >= budget.maxSendsPerHour) {
      return { fail: "ERR-OT-09" }; // el envio excede el maximo por hora (el inicial cuenta)
    }

    const code = generateCode(p.policy.codeLength);
    const codeHash = hashCode(p.secret, verificationRef, code).toString("hex");
    const resent: OtpVerificationRecord = {
      ...found,
      codeHash,
      resendCount: found.resendCount + 1,
      lastSentAt: new Date(nowMs),
      sendsWindowStart: new Date(windowStartMs),
      sendsInWindow: sendsInWindow + 1,
    };
    await p.otpRepo.save(resent);
    await p.securityEvents.record({
      tenantId,
      eventType: "OTP_ISSUED",
      verificationRef,
      otpScope: found.scope,
      channelRef: opaqueChannelRef(p.secret, tenantId, found.channelRef),
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
