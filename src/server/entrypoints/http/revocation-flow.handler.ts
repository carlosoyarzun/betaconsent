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
import {
  confirmRevocation,
  issueRecoveryLinkBearer,
  requestRevocation,
  resolveRecoveryTokenForRedeem,
  revokeWithRecoveryLink,
  verifyRevocationOtp,
  withdrawRevocation,
  type RevocationPorts,
} from "../../modules/revocation/revocation.ts";
import { openRightsCase, type RightsCasePorts } from "../../modules/rights-case/rights-case.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";
import { decodeSession, encodeSession, type ConsentSessionPayload } from "./consent-session.ts";
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

/** GET /r/{token} inválido, consumido, expirado o de otro tenant/ciclo (ERR-RV-05, GRD-RV-06):
 * el contrato fija 200 UniformAccepted, a propósito distinto del 404 UniformNotFound de
 * /i/{token} y /m/{token} (openapi.yaml:275-279): GET /r/{token} nunca revela "no existe", solo
 * la respuesta uniforme que invita a usar el enlace de gestión (ERR-RV-05 response). */
function recoveryUniformAccepted(): HttpResult {
  return { status: 200, body: { result: "RECEIVED" }, extraHeaders: { ...REDEMPTION_HEADERS } };
}

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
// GET /m/{token} (API-CNS-102, P-14). Canje sin transición (INV-CM-08): resuelve el handle
// MANAGE_ENTRY y crea la sesión (tenantId, chainRef, revokedDecisionRef); 303 a /manage.
// ---------------------------------------------------------------------------
export function handleRedeemManagementLink(token: string, ports: Pick<RevocationFlowPorts, "tenantHandle">, sessionSecret: Buffer): HttpResult {
  const resolved = ports.tenantHandle.resolve(token);
  if (!resolved) return uniformNotFound();

  const session: ConsentSessionPayload = {
    tenantId: resolved.tenantId,
    chainRef: resolved.chainRef,
    revokedDecisionRef: resolved.revokedDecisionRef,
  };
  return {
    status: 303,
    body: {},
    location: MANAGE_LANDING_ROUTE,
    setSessionCookie: encodeSession(sessionSecret, session),
    // Mismo criterio que GET /i/{token} (consent-flow.handler.ts): RedemptionToken nunca se
    // reenvía a terceros (Referrer-Policy no-referrer); no-store evita reintentos cacheados.
    extraHeaders: { "Referrer-Policy": "no-referrer", "Cache-Control": "no-store" },
  };
}

// ---------------------------------------------------------------------------
// POST /manage/revocation (R1). API-CNS-130. Requiere sesión MANAGE verificada (V3 MANAGE);
// chainRef/revokedDecisionRef SIEMPRE de la sesión, nunca del body.
// ---------------------------------------------------------------------------
export function handleRequestRevocation(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.chainRef || !session.revokedDecisionRef || !session.manageDecisionMakerRef) return uniformNotFound();

  const revocationRef = session.revocationRef ?? `rv-${randomUUID()}`;
  const revocation = requestRevocation(ports.revocation, session.tenantId, {
    revocationRef,
    chainRef: session.chainRef,
    revokedDecisionRef: session.revokedDecisionRef,
  });
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
export function handleVerifyRevocation(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.revocationRef || !session.revocationOtpVerified || !session.revocationVerificationRef) return uniformNotFound();

  try {
    const verified = verifyRevocationOtp(ports.revocation, session.tenantId, session.revocationRef, session.revocationVerificationRef);
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
export function handleConfirmRevocation(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.revocationRef || !session.manageDecisionMakerRef) return uniformNotFound();

  try {
    const applied = confirmRevocation(ports.revocation, session.tenantId, session.revocationRef);
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
export function handleWithdrawRevocation(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.revocationRef || !session.manageDecisionMakerRef) return uniformNotFound();

  try {
    const withdrawn = withdrawRevocation(ports.revocation, session.tenantId, session.revocationRef);
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
export function handleIssueRecoveryLink(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.chainRef || !session.revokedDecisionRef) return uniformNotFound();

  issueRecoveryLinkBearer(ports.revocation, session.tenantId, session.chainRef, session.revokedDecisionRef, "LIMIT_REACHED");
  // UniformAccepted (contracts/openapi API-CNS-134): nunca revela si el canal existe.
  return { status: 202, body: { result: "RECEIVED" } };
}

// ---------------------------------------------------------------------------
// POST /rights-case/open (RC1 fuente BEARER). Mismo alcance: solo exige el handle MANAGE_ENTRY.
// ---------------------------------------------------------------------------
export function handleOpenRightsCase(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "rightsCase">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.chainRef || !session.revokedDecisionRef) return uniformNotFound();

  const rightsCase = openRightsCase(ports.rightsCase, session.tenantId, {
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
// GET /r/{token} (API-CNS-103, P-18). Canje sin transición (INV-CM-08): resuelve el token de
// recuperación y crea la sesión RECOVERY (tenantId, chainRef, revokedDecisionRef,
// recoveryTokenHash) SIN consumirlo; el consumo ocurre solo en POST /recovery/revoke.
// ---------------------------------------------------------------------------
export function handleRedeemRecoveryLink(token: string, ports: Pick<RevocationFlowPorts, "revocation">, sessionSecret: Buffer): HttpResult {
  const resolved = resolveRecoveryTokenForRedeem(ports.revocation, token);
  if (!resolved) return recoveryUniformAccepted(); // ERR-RV-05 (GRD-RV-06 onFail)

  const session: ConsentSessionPayload = {
    tenantId: resolved.tenantId,
    chainRef: resolved.chainRef,
    revokedDecisionRef: resolved.revokedDecisionRef,
    recoveryTokenHash: resolved.tokenHash,
  };
  return {
    status: 303,
    body: {},
    location: RECOVERY_CONFIRM_ROUTE,
    setSessionCookie: encodeSession(sessionSecret, session),
    extraHeaders: { ...REDEMPTION_HEADERS },
  };
}

// ---------------------------------------------------------------------------
// POST /recovery/revoke (API-CNS-135). Único POST con handle/sesión RECOVERY: R1r+R2r+R3r,
// R10+R3r o R11 (NOOP), según el estado de la Revocation abierta de la cadena (o su ausencia).
// tenantId/chainRef/revokedDecisionRef/recoveryTokenHash SIEMPRE de la sesión creada por
// GET /r/{token}, nunca del body.
// ---------------------------------------------------------------------------
export function handleRecoveryRevoke(
  request: RawConsentRequest,
  ports: Pick<RevocationFlowPorts, "revocation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.chainRef || !session.revokedDecisionRef || !session.recoveryTokenHash) return uniformNotFound();

  // RecoveryRevokeRequest (contracts/schemas/api-payloads.schema.json): confirmTotalWithdrawal
  // const true, gesto explícito de confirmación (no dato de identidad: sigue viniendo de la
  // sesión, no este campo). Sin él, rechazo determinista (mismo criterio que ERR-CM-06).
  const body = request.body as { confirmTotalWithdrawal?: unknown } | undefined;
  if (body?.confirmTotalWithdrawal !== true) {
    return problem(422, "ERR-CM-06");
  }

  const outcome = revokeWithRecoveryLink(ports.revocation, session.tenantId, session.chainRef, session.revokedDecisionRef, session.recoveryTokenHash);
  if (outcome.kind === "CONFIRMED") {
    return { status: 200, body: { revocationRef: outcome.revocationRef, state: "CONFIRMED", receiptDelivery: "BOUND_CHANNEL" } };
  }
  if (outcome.kind === "IN_PROGRESS") {
    // R11 (NOOP): mismo patrón que 202 UniformAccepted de RV0/RC1, pero 200 porque el contrato
    // (RecoveryRevokeResult) modela IN_PROGRESS como resultado de éxito de esta operación.
    return { status: 200, body: { result: "IN_PROGRESS" } };
  }
  // "UNIFORM" (ERR-RV-05): 202, distinto del 200 de GET /r/{token} (contracts/openapi
  // /recovery/revoke responses: 202 UniformAccepted es la rama de error uniforme del POST).
  return { status: 202, body: { result: "RECEIVED" } };
}
