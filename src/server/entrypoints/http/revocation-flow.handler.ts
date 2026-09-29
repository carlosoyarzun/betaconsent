// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-102 (GET /m/{token}),
// API-CNS-103 (GET /r/{token}), API-CNS-130 (POST /manage/revocation, R1), API-CNS-131 (POST
// /manage/revocation/verify, R2), API-CNS-132 (POST /manage/revocation/confirm, R3),
// API-CNS-133 (POST /manage/revocation/withdraw, R8), API-CNS-134 (POST
// /manage/recovery-link, RV0 fuente BEARER), API-CNS-135 (POST /recovery/revoke, R1r/R2r/R3r/
// R10/R11), rights-case.spec.yaml RC1 fuente BEARER (POST /rights-case/open). CA-116
// (UX-CNS-004): PR1 gestión/retiro self-service (TEST-CNS-581+) y PR2 recuperación
// (TEST-CNS-589+).
//
// Mismo patrón que consent-flow.handler.ts: actor y tenant/chainRef SIEMPRE de la sesión
// (nunca del body); GRD-CM-10 (CSRF/Origin) en cada POST; 404 uniforme si la sesión no
// resuelve. GET /m/{token} y GET /r/{token} siguen INV-CM-08 (no transicionan: solo resuelven
// el handle y crean la sesión), igual que GET /i/{token} en consent-flow.handler.ts.

import { randomUUID } from "node:crypto";

import { DomainError } from "../../modules/common/errors.ts";
import { assertCsrfAndOrigin } from "../../modules/common/guards.ts";
import type { TenantHandlePort } from "../../ports/tenant-handle.port.ts";
import type { ManageHandlePolicy } from "../../modules/revocation/manage-handle-policy.config.ts";
import {
  confirmRevocation,
  evaluateRecoveryTokenEligibilityByHash,
  hashRecoveryToken,
  issueRecoveryLinkBearer,
  requestRevocation,
  revokeWithRecoveryLinkByHash,
  verifyRevocationOtp,
  withdrawRevocation,
  type RevocationPorts,
} from "../../modules/revocation/revocation.ts";
import { openRightsCase, type RightsCasePorts } from "../../modules/rights-case/rights-case.ts";
import type { RecoveryHandlePolicy } from "../../modules/revocation/recovery-handle-policy.config.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";
import { decodeSession, encodeSession, type ConsentSessionPayload } from "./consent-session.ts";
import {
  decodeRecoveryHandle,
  encodeRecoveryHandle,
  generateRecoveryCsrfToken,
  serializeRecoveryHandleCookie,
  verifyRecoveryCsrfToken,
} from "./recovery-handle.ts";
import { decodeLinkHandle, encodeLinkHandle, hashLinkToken, serializeLinkHandleCookie, type LinkHandleType } from "./link-handle.ts";
import type { HttpResult, RawConsentRequest } from "./consent-flow.handler.ts";

export interface RevocationFlowPorts {
  readonly tenantHandle: TenantHandlePort;
  readonly revocation: RevocationPorts;
  readonly rightsCase: Pick<RightsCasePorts, "rightsCaseRepo" | "ledger">;
}

const MANAGE_LANDING_ROUTE = "/manage";
const RECOVERY_CONFIRM_ROUTE = "/recovery/confirm";
/** Cabeceras del canje /r/{token} (API-CNS-103), mismas de GET /m/{token}/GET /i/{token}. */
const REDEMPTION_HEADERS = { "Referrer-Policy": "no-referrer", "Cache-Control": "no-store" } as const;

/** SEC-CNS-014 FINDING P2-04: tope de largo antes de hashear. GET /r/{token} ya no lee la BD ni
 * valida el token (contracts/openapi RedemptionToken acota a maxLength 128; este tope es más
 * holgado a propósito, para no acoplar este archivo al schema del contrato) — cualquier
 * entrada, del largo que sea, produce el mismo 303 idéntico; truncar antes de hashear solo
 * acota el costo de una entrada adversarial larguísima, nunca cambia el resultado observable. */
const RECOVERY_TOKEN_HASH_MAX_INPUT_LENGTH = 512;

function uniformNotFound(): HttpResult {
  return { status: 404, body: { status: 404 } };
}

function csrfRejected(): HttpResult {
  return { status: 403, body: { code: "CSRF_REJECTED", status: 403, correlationId: randomUUID() } };
}

function problem(status: 409 | 422, code: string): HttpResult {
  return { status, body: { code, status, correlationId: randomUUID() } };
}

function readSession(request: RawConsentRequest, config: RightsCaseHttpConfig, sessionSecret: Buffer): ConsentSessionPayload | null {
  const cookies = parseCookies(request.cookieHeader);
  return decodeSession(sessionSecret, cookies[config.sessionCookieName]);
}

function checkCsrf(request: RawConsentRequest, config: RightsCaseHttpConfig): HttpResult | null {
  const cookies = parseCookies(request.cookieHeader);
  try {
    assertCsrfAndOrigin({
      originHeader: request.originHeader,
      allowedOrigin: config.allowedOrigin,
      csrfHeaderToken: request.csrfHeaderToken,
      csrfCookieToken: cookies[config.csrfCookieName],
    });
    return null;
  } catch (err) {
    if (err instanceof DomainError && err.code === "ERR-CM-09") return csrfRejected();
    throw err;
  }
}

// ---------------------------------------------------------------------------
// GET /m/{token} (API-CNS-102, P-14, SEC-CNS-014). Canje uniforme SIN transición (INV-CM-08
// reforzado, Carlos 2026-09-28 opción a): NUNCA lee la BD (ni tenantHandle ni ningún otro port),
// solo hashea el token y fija el handle MANAGE_ENTRY firmado (`__Host-cns-m-handle`,
// link-handle.ts). El 303 a /manage es bit a bit idéntico sea el token válido, inexistente,
// rotado o de otro tenant: GRD-CM-01 se evalúa en GET /manage (render, solo lectura), nunca aquí.
// ---------------------------------------------------------------------------
export function handleRedeemManagementLink(
  token: string,
  manageHandlePolicy: ManageHandlePolicy,
  manageHandleKey: Buffer,
  manageEntryHandleCookieName: string,
): HttpResult {
  const tokenHash = hashLinkToken(token);
  const expiresAtEpochSeconds = Math.floor((Date.now() + manageHandlePolicy.ttlMs) / 1000);
  const cookieValue = encodeLinkHandle(manageHandleKey, "MANAGE_ENTRY", tokenHash, expiresAtEpochSeconds);
  return {
    status: 303,
    body: {},
    location: MANAGE_LANDING_ROUTE,
    setLinkHandleCookie: serializeLinkHandleCookie(manageEntryHandleCookieName, cookieValue, Math.floor(manageHandlePolicy.ttlMs / 1000)),
    // Mismo criterio que GET /i/{token} (consent-flow.handler.ts): RedemptionToken nunca se
    // reenvía a terceros (Referrer-Policy no-referrer); no-store evita reintentos cacheados.
    extraHeaders: { ...REDEMPTION_HEADERS },
  };
}

// ---------------------------------------------------------------------------
// GET /manage (UX-CNS-004, SEC-CNS-014, INV-CM-08). Solo lectura. FINDING P1 (Carlos, prueba en
// navegador): el handle MANAGE_ENTRY vigente (fijado por el GET /m/{token} MÁS RECIENTE) SIEMPRE
// manda sobre una sesión previa — "el último enlace abierto manda", mismo criterio que
// /recovery/confirm (PR #23). Si el handle resuelve a una identidad DISTINTA de la sesión
// existente (otro chainRef, p. ej. el enlace de gestión de un segundo hijo), se descarta la
// sesión vieja y se crea una nueva; si resuelve a la MISMA identidad, se reutiliza la sesión
// existente (preserva progreso — V3 MANAGE, revocationRef — que el handle no reconstruye). Si el
// handle está presente pero inválido (inexistente/rotado), la sesión previa se borra SIEMPRE.
// Solo cuando NO hay handle en absoluto se cae de vuelta a la sesión existente (navegación
// dentro del mismo flujo, sin volver a pasar por GET /m/{token}).
// ---------------------------------------------------------------------------
export interface ManageLandingView {
  readonly session: ConsentSessionPayload | null;
  /** Presente solo cuando esta llamada resolvió una sesión NUEVA (handle recién resuelto, sea la
   * primera visita o un enlace distinto al de la sesión previa): el caller debe fijar esta
   * cookie en la respuesta. */
  readonly sessionCookieToSet?: string;
  /** true cuando hay que invalidar una cookie de sesión previa (handle presente pero inválido, o
   * handle presente y válido mas de una identidad DISTINTA de la sesión previa): el caller debe
   * fijar `Set-Cookie` con Max-Age=0 para esa cookie. */
  readonly clearSessionCookie?: boolean;
}

const MANAGE_ENTRY_HANDLE_TYPE: LinkHandleType = "MANAGE_ENTRY";

function sameManageIdentity(session: ConsentSessionPayload, tenantId: string, chainRef: string, revokedDecisionRef: string): boolean {
  return session.tenantId === tenantId && session.chainRef === chainRef && session.revokedDecisionRef === revokedDecisionRef;
}

export async function resolveManageLandingSession(
  ports: Pick<RevocationFlowPorts, "tenantHandle">,
  sessionSecret: Buffer,
  existingSession: ConsentSessionPayload | null,
  manageHandleKey: Buffer,
  cookies: Readonly<Record<string, string>>,
  manageEntryHandleCookieName: string,
): Promise<ManageLandingView> {
  const handle = decodeLinkHandle(manageHandleKey, MANAGE_ENTRY_HANDLE_TYPE, cookies[manageEntryHandleCookieName]);
  if (handle) {
    const resolved = await ports.tenantHandle.resolveByHash(handle.h);
    if (!resolved) {
      // Handle inválido: nunca reutiliza una sesión previa, la que sea.
      return { session: null, clearSessionCookie: Boolean(existingSession) };
    }
    if (existingSession && existingSession.chainRef && sameManageIdentity(existingSession, resolved.tenantId, resolved.chainRef, resolved.revokedDecisionRef)) {
      return { session: existingSession };
    }
    const session: ConsentSessionPayload = {
      tenantId: resolved.tenantId,
      chainRef: resolved.chainRef,
      revokedDecisionRef: resolved.revokedDecisionRef,
    };
    return { session, sessionCookieToSet: encodeSession(sessionSecret, session) };
  }
  if (existingSession && existingSession.chainRef) {
    return { session: existingSession };
  }
  return { session: null };
}

// ---------------------------------------------------------------------------
// POST /manage/revocation (R1). API-CNS-130. Requiere sesión MANAGE verificada (V3 MANAGE);
// chainRef/revokedDecisionRef SIEMPRE de la sesión, nunca del body.
// ---------------------------------------------------------------------------
export async function handleRequestRevocation(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.chainRef || !session.revokedDecisionRef || !session.manageDecisionMakerRef) return uniformNotFound();

  const revocationRef = session.revocationRef ?? randomUUID();
  let revocation;
  try {
    revocation = await requestRevocation(ports.revocation, session.tenantId, {
      revocationRef,
      chainRef: session.chainRef,
      revokedDecisionRef: session.revokedDecisionRef,
    });
  } catch (err) {
    // GRD-RV-02 (ERR-RV-02): respuesta uniforme (UniformAccepted), sin revelar el estado de la cadena.
    if (err instanceof DomainError && err.code === "ERR-RV-02") return { status: 202, body: { result: "RECEIVED" } };
    throw err;
  }
  const nextSession: ConsentSessionPayload = { ...session, revocationRef: revocation.revocationRef };
  return {
    status: 200,
    body: { revocationRef: revocation.revocationRef, status: revocation.status },
    setSessionCookie: encodeSession(sessionSecret, nextSession),
  };
}

// ---------------------------------------------------------------------------
// POST /manage/revocation/verify (R2). API-CNS-131. Requiere V3 scope REVOCATION ya correcto
// en esta sesión (session.revocationOtpVerified), posterior a R1 (GRD-RV-05).
// ---------------------------------------------------------------------------
export async function handleVerifyRevocation(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.revocationRef || !session.revocationOtpVerified || !session.revocationVerificationRef) return uniformNotFound();

  try {
    const verified = await verifyRevocationOtp(ports.revocation, session.tenantId, session.revocationRef, session.revocationVerificationRef);
    return { status: 200, body: { revocationRef: verified.revocationRef, status: verified.status } };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      return problem(409, err.code);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// POST /manage/revocation/confirm (R3). API-CNS-132. Confirmación explícita de retiro total;
// en la misma llamada aplica R4 (ver nota en confirmRevocation).
// ---------------------------------------------------------------------------
export async function handleConfirmRevocation(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.revocationRef || !session.manageDecisionMakerRef) return uniformNotFound();

  try {
    const applied = await confirmRevocation(ports.revocation, session.tenantId, session.revocationRef);
    return { status: 200, body: { revocationRef: applied.revocationRef, status: applied.status } };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      return problem(409, err.code);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// POST /manage/revocation/withdraw (R8). API-CNS-133. Retiro explícito de la solicitud;
// independiente del authPath proyectado (basta la sesión MANAGE vigente de la cadena).
// ---------------------------------------------------------------------------
export async function handleWithdrawRevocation(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.revocationRef || !session.manageDecisionMakerRef) return uniformNotFound();

  try {
    const withdrawn = await withdrawRevocation(ports.revocation, session.tenantId, session.revocationRef);
    return { status: 200, body: { revocationRef: withdrawn.revocationRef, status: withdrawn.status } };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      return problem(409, err.code);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// POST /manage/recovery-link (RV0 fuente BEARER). API-CNS-134. Solo exige el handle
// MANAGE_ENTRY (chainRef/revokedDecisionRef de la sesión); no exige V3 MANAGE (se usa desde la
// pantalla bloqueada, antes de poder verificar). Ver nota de alcance en
// revocation.ts issueRecoveryLinkBearer (la PR 2 crea el token real de /r/{token}).
// ---------------------------------------------------------------------------
export async function handleIssueRecoveryLink(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.chainRef || !session.revokedDecisionRef) return uniformNotFound();

  await issueRecoveryLinkBearer(ports.revocation, session.tenantId, session.chainRef, session.revokedDecisionRef, "LIMIT_REACHED");
  // UniformAccepted (contracts/openapi API-CNS-134): nunca revela si el canal existe.
  return { status: 202, body: { result: "RECEIVED" } };
}

// ---------------------------------------------------------------------------
// POST /rights-case/open (RC1 fuente BEARER). Mismo alcance: solo exige el handle MANAGE_ENTRY.
// ---------------------------------------------------------------------------
export async function handleOpenRightsCase(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "rightsCase">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.chainRef || !session.revokedDecisionRef) return uniformNotFound();

  const rightsCase = await openRightsCase(ports.rightsCase, session.tenantId, {
    caseRef: `case-${session.chainRef}`,
    chainRef: session.chainRef,
    revokedDecisionRef: session.revokedDecisionRef,
    origin: "LIMIT_REACHED",
  });
  // InReviewAck (mismo patrón que POST /rights-case/resume en consent-flow-server.ts/server.ts):
  // el solicitante ve "en revisión", nunca el estado interno del caso.
  return { status: 200, body: { result: "IN_REVIEW", caseRef: rightsCase.caseRef } };
}

// ---------------------------------------------------------------------------
// GET /r/{token} (API-CNS-103, P-18, SEC-CNS-014). Canje uniforme SIN transición (INV-CM-08
// reforzado): NUNCA lee la BD (ni recoveryTokenRepo ni ningún otro port), solo hashea el token
// y fija el handle RECOVERY firmado (__Host-cns-recovery, recovery-handle.ts). El 303 a
// /recovery/confirm es bit a bit idéntico sea el token válido, inexistente, consumido, expirado
// o de otro tenant/ciclo: GRD-RV-06/ERR-RV-05 se evalúan en la página destino (render, solo
// lectura) y en POST /recovery/revoke (consumo), nunca aquí. Sin ramas ni logs condicionales.
// ---------------------------------------------------------------------------
export function handleRedeemRecoveryLink(token: string, recoveryHandlePolicy: RecoveryHandlePolicy, recoveryHandleKey: Buffer, recoveryHandleCookieName: string): HttpResult {
  const bounded = token.length > RECOVERY_TOKEN_HASH_MAX_INPUT_LENGTH ? token.slice(0, RECOVERY_TOKEN_HASH_MAX_INPUT_LENGTH) : token;
  const tokenHash = hashRecoveryToken(bounded);
  const expiresAtEpochSeconds = Math.floor((Date.now() + recoveryHandlePolicy.ttlMs) / 1000);
  const cookieValue = encodeRecoveryHandle(recoveryHandleKey, tokenHash, expiresAtEpochSeconds);
  return {
    status: 303,
    body: {},
    location: RECOVERY_CONFIRM_ROUTE,
    setRecoveryHandleCookie: serializeRecoveryHandleCookie(recoveryHandleCookieName, cookieValue, Math.floor(recoveryHandlePolicy.ttlMs / 1000)),
    extraHeaders: { ...REDEMPTION_HEADERS },
  };
}

// ---------------------------------------------------------------------------
// GET /recovery/confirm (UX-CNS-004 33:87/33:106, INV-CM-08, SEC-CNS-014). Solo lectura: evalúa
// GRD-RV-06 (evaluateRecoveryTokenEligibilityByHash) contra el hash del handle RECOVERY vigente,
// sin consumir el token, sin escribir nada, sin emitir eventos. El caller HTTP
// (consent-flow-server.ts) usa `tokenHash` (presente solo si `eligible`) para fijar el CSRF
// ligado al handle (P2).
// ---------------------------------------------------------------------------
export interface RecoveryConfirmView {
  readonly eligible: boolean;
  readonly tokenHash?: string;
}

export async function resolveRecoveryConfirmView(
  ports: Pick<RevocationFlowPorts, "revocation">,
  recoveryHandleKey: Buffer,
  cookieHeader: string | undefined,
  recoveryHandleCookieName: string,
): Promise<RecoveryConfirmView> {
  const cookies = parseCookies(cookieHeader);
  const handle = decodeRecoveryHandle(recoveryHandleKey, cookies[recoveryHandleCookieName]);
  if (!handle) return { eligible: false };
  const eligibility = await evaluateRecoveryTokenEligibilityByHash(ports.revocation, handle.h);
  if (!eligibility) return { eligible: false };
  return { eligible: true, tokenHash: handle.h };
}

// ---------------------------------------------------------------------------
// POST /recovery/revoke (API-CNS-135, SEC-CNS-014). Único POST con handle RECOVERY: R1r+R2r+R3r,
// R10+R3r o R11 (NOOP), según el estado de la Revocation abierta de la cadena (o su ausencia).
// tenantId/chainRef/revokedDecisionRef se resuelven en servidor desde el hash del handle
// vigente (GRD-CM-01, revokeWithRecoveryLinkByHash), nunca desde la cookie ni el body. El CSRF
// double-submit genérico (checkCsrf, GRD-CM-10) se complementa con `verifyRecoveryCsrfToken`
// (P2, fijación de cookie de recuperación): si `__Host-cns-recovery` cambió entre el render de
// 33:87 y este POST, la recomputación con el hash ACTUAL no coincide y el POST se rechaza.
// ---------------------------------------------------------------------------
export async function handleRecoveryRevoke(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  recoveryHandleKey: Buffer,
  recoveryCsrfKey: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const cookies = parseCookies(request.cookieHeader);
  const handle = decodeRecoveryHandle(recoveryHandleKey, cookies[config.recoveryHandleCookieName]);
  if (!handle) return uniformNotFound();

  if (!verifyRecoveryCsrfToken(recoveryCsrfKey, handle.h, request.csrfHeaderToken)) {
    return csrfRejected();
  }

  // RecoveryRevokeRequest (contracts/schemas/api-payloads.schema.json): confirmTotalWithdrawal
  // const true, gesto explícito de confirmación (no dato de identidad: sigue resolviéndose en
  // servidor desde el hash, no este campo). Sin él, rechazo determinista (mismo criterio que
  // ERR-CM-06).
  const body = request.body as { confirmTotalWithdrawal?: unknown } | undefined;
  if (body?.confirmTotalWithdrawal !== true) {
    return problem(422, "ERR-CM-06");
  }

  const outcome = await revokeWithRecoveryLinkByHash(ports.revocation, handle.h);
  if (outcome.kind === "CONFIRMED") {
    return { status: 200, body: { revocationRef: outcome.revocationRef, state: "CONFIRMED", receiptDelivery: "BOUND_CHANNEL" } };
  }
  if (outcome.kind === "IN_PROGRESS") {
    // R11 (NOOP): mismo patrón que 202 UniformAccepted de RV0/RC1, pero 200 porque el contrato
    // (RecoveryRevokeResult) modela IN_PROGRESS como resultado de éxito de esta operación.
    return { status: 200, body: { result: "IN_PROGRESS" } };
  }
  // "UNIFORM" (ERR-RV-05): 202, distinto del 303 de GET /r/{token} (contracts/openapi
  // /recovery/revoke responses: 202 UniformAccepted es la rama de error uniforme del POST).
  return { status: 202, body: { result: "RECEIVED" } };
}
