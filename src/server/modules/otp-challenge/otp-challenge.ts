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

import { createHmac, randomInt, timingSafeEqual } from "node:crypto";

import { DomainError } from "../common/errors.ts";
import { assertRouteEligible, assertTenantConsistency } from "../common/guards.ts";
import type { TenantId } from "../common/types.ts";
import type { OtpChannelPort } from "../../ports/otp-channel.port.ts";
import type { OtpVerificationRecord, OtpVerificationRepositoryPort } from "../../ports/otp-verification-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { InvitationPorts } from "../invitation/invitation.ts";
import { markInvitationVerified } from "../invitation/invitation.ts";

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
  readonly policy: OtpPolicy;
  /** Análogo de K_otp_env (P-08); IT0 in-memory, inyectado por el llamador. */
  readonly secret: Buffer;
}

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

function requireVerification(ports: OtpChallengePorts, tenantId: TenantId, verificationRef: string): OtpVerificationRecord {
  const found = ports.otpRepo.findByRef(tenantId, verificationRef);
  if (!found) {
    throw new DomainError("ERR-CM-01");
  }
  assertTenantConsistency(found.tenantId, tenantId); // GRD-CM-02
  return found;
}

/** V1: NOT_STARTED -> CODE_SENT (scope DECISION). Guards: GRD-CM-02, GRD-CM-05, GRD-OT-01, GRD-OT-02, GRD-OT-08 (subconjunto). */
export function requestOtp(
  ports: OtpChallengePorts,
  tenantId: TenantId,
  verificationRef: string,
  invitationRef: string,
  channelRef: string,
): OtpVerificationRecord {
  const invitation = ports.invitation.invitationRepo.findByRef(tenantId, invitationRef);
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
    ports.invitation.eligibility.isEligibleForIssuance(tenantId, invitation.contextRef, invitation.productRef),
  ); // GRD-CM-05 (guardsByScope.DECISION)

  const active = ports.otpRepo.findActiveByParent(tenantId, invitationRef, "DECISION");
  if (active) {
    // GRD-OT-08 (subconjunto): V1 repetido sobre el mismo padre es idempotente (mismo challenge activo).
    return active;
  }

  const code = generateCode(ports.policy.codeLength);
  const codeHash = hashCode(ports.secret, verificationRef, code).toString("hex");
  const record: OtpVerificationRecord = {
    verificationRef,
    tenantId,
    scope: "DECISION",
    parentRef: invitationRef,
    channelRef,
    codeHash,
    attempts: 0,
    expiresAt: new Date(Date.now() + ports.policy.ttlMs),
    state: "CODE_SENT",
    resendCount: 0,
  };
  ports.otpRepo.save(record);
  ports.channel.send({ channelRef, verificationRef, code }); // INV-OT-02: el código en claro no sale de aquí.
  ports.ledger.append({
    eventType: "OTP_ISSUED",
    tenantId,
    aggregateType: "DecisionMakerVerification",
    aggregateId: verificationRef,
    actorType: "HUMAN",
    actorRole: "UNVERIFIED_BEARER",
    payload: { verificationRef, scope: "DECISION" },
    idempotencyKey: `${verificationRef}:issued`,
  });
  return record;
}

/** V3/V2/V4: intenta verificar el código. Correcto -> VERIFIED (dispara I5). Incorrecto -> V2/V4. */
export function submitOtp(
  ports: OtpChallengePorts,
  tenantId: TenantId,
  verificationRef: string,
  code: string,
  decisionMakerRef: string,
): OtpVerificationRecord {
  const found = requireVerification(ports, tenantId, verificationRef);

  if (found.state === "LOCKED") {
    throw new DomainError("ERR-OT-04");
  }
  if (found.state === "VERIFIED" || found.consumedAt) {
    // Replay de un challenge ya consumido (INV-OT-07).
    throw new DomainError("ERR-OT-03");
  }
  if (found.expiresAt.getTime() <= Date.now()) {
    // V5 (expiración perezosa) + GRD-OT-05.
    ports.otpRepo.save({ ...found, state: "EXPIRED" });
    throw new DomainError("ERR-OT-03");
  }

  // GRD-OT-04 (attempts_below_N_atomic): reserva el intento ANTES de comparar (SEC F02).
  const attempts = found.attempts + 1;
  const candidateHash = hashCode(ports.secret, verificationRef, code);
  const storedHash = Buffer.from(found.codeHash, "hex");
  const isCorrect = candidateHash.length === storedHash.length && timingSafeEqual(candidateHash, storedHash); // GRD-OT-07

  if (isCorrect) {
    const verified: OtpVerificationRecord = { ...found, attempts, state: "VERIFIED", consumedAt: new Date() };
    ports.otpRepo.save(verified);
    ports.ledger.append({
      eventType: "DECISION_MAKER_CHANNEL_VERIFIED",
      tenantId,
      aggregateType: "DecisionMakerVerification",
      aggregateId: verificationRef,
      actorType: "HUMAN",
      actorRole: "DECISION_MAKER",
      payload: { verificationRef, parentRef: found.parentRef, decisionMakerRef, scope: "DECISION", method: "EMAIL_OTP" },
      idempotencyKey: `${verificationRef}:verified`,
    });
    markInvitationVerified(ports.invitation, tenantId, found.parentRef, decisionMakerRef, verificationRef); // I5
    return verified;
  }

  if (attempts >= ports.policy.maxAttempts) {
    const locked: OtpVerificationRecord = { ...found, attempts, state: "LOCKED" };
    ports.otpRepo.save(locked);
    ports.ledger.append({
      eventType: "OTP_LOCKED",
      tenantId,
      aggregateType: "DecisionMakerVerification",
      aggregateId: verificationRef,
      actorType: "SYSTEM_GUARD",
      payload: { verificationRef, scope: "DECISION" },
      idempotencyKey: `${verificationRef}:locked`,
    });
    throw new DomainError("ERR-OT-04");
  }

  const failed: OtpVerificationRecord = { ...found, attempts, state: "CODE_SENT" };
  ports.otpRepo.save(failed);
  ports.ledger.append({
    eventType: "OTP_FAILED",
    tenantId,
    aggregateType: "DecisionMakerVerification",
    aggregateId: verificationRef,
    actorType: "HUMAN",
    actorRole: "UNVERIFIED_BEARER",
    payload: { verificationRef, scope: "DECISION" },
    idempotencyKey: `${verificationRef}:failed:${attempts}`,
  });
  throw new DomainError("ERR-OT-02");
}

/**
 * V2r: CODE_SENT -> CODE_SENT (ResendOtp). Reemplaza codeHash sin reiniciar `attempts` ni el
 * presupuesto (GRD-OT-06); mismo canal ligado (GRD-OT-02, ya validado al emitir el challenge
 * original). No implementa GRD-OT-13 (bound_to_request_handle): ver nota de alcance arriba.
 */
export function resendOtp(ports: OtpChallengePorts, tenantId: TenantId, verificationRef: string): OtpVerificationRecord {
  const found = requireVerification(ports, tenantId, verificationRef);

  if (found.state === "LOCKED") {
    throw new DomainError("ERR-OT-04");
  }
  if (found.state !== "CODE_SENT" || found.consumedAt) {
    // VERIFIED (ya consumido) o EXPIRED: replay de un challenge terminal (INV-OT-07 análogo).
    throw new DomainError("ERR-OT-03");
  }
  if (found.expiresAt.getTime() <= Date.now()) {
    ports.otpRepo.save({ ...found, state: "EXPIRED" });
    throw new DomainError("ERR-OT-03");
  }

  if (found.resendCount >= ports.policy.maxResends) {
    // GRD-OT-06 (resend_limits, P-06): límite alcanzado, el challenge no cambia.
    throw new DomainError("ERR-OT-09");
  }

  const code = generateCode(ports.policy.codeLength);
  const codeHash = hashCode(ports.secret, verificationRef, code).toString("hex");
  const resent: OtpVerificationRecord = { ...found, codeHash, resendCount: found.resendCount + 1 };
  ports.otpRepo.save(resent);
  ports.channel.send({ channelRef: found.channelRef, verificationRef, code }); // INV-OT-02: nunca en claro fuera de aquí.
  ports.ledger.append({
    eventType: "OTP_ISSUED",
    tenantId,
    aggregateType: "DecisionMakerVerification",
    aggregateId: verificationRef,
    actorType: "HUMAN",
    actorRole: "UNVERIFIED_BEARER",
    payload: { verificationRef, scope: "DECISION" },
    idempotencyKey: `${verificationRef}:resend:${resent.resendCount}`,
  });
  return resent;
}
