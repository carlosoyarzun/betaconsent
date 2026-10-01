// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-101 (GET /i/{token}),
// API-CNS-115 (POST /invitation/open), API-CNS-120 (POST /otp/request), API-CNS-121 (POST
// /otp/submit), API-CNS-126 (POST /decision/steps) y API-CNS-127 (POST /decision/submit);
// specs/state-machines/invitation.spec.yaml I4 (efecto de canje + efecto de apertura),
// specs/state-machines/common.spec.yaml INV-CM-08, otp-challenge.spec.yaml V1/V3,
// consent-decision.spec.yaml C1/C2/C3/C5; common.spec.yaml GRD-CM-10 (D1).
// TEST-CNS-498..TEST-CNS-51x, TEST-CNS-564.. (traceability/test-matrix.csv).
//
// x-scope-note (actualizado, CA-116 /decision): el contrato separa /decision/start,
// /decision/steps y /decision/submit en tres POST. Este archivo ya NO consolida C1+C2 dentro de
// /decision/submit (eso violaba GRD-CD-04/GRD-CD-05: el submit anterior marcaba los 4 pasos de
// C2 como completos sin ningún dato real del usuario). Ahora: POST /decision/steps (C2) inicia
// la decisión (C1) de forma perezosa en su primera llamada de la sesión — sin una ruta
// /decision/start separada, sigue siendo scope reducido — y guarda `consentId` en la sesión;
// POST /decision/submit (C3/C5) exige que la sesión ya tenga `consentId` (pasos ya iniciados) y
// nunca genera uno nuevo. GET /i/{token} (P-12) sí está implementado: crea la sesión LANDING
// (tenantId, invitationRef) sin transicionar Invitation (INV-CM-08); la transición I4
// (SENT -> OPENED) ocurre solo en el POST /invitation/open subsiguiente, que ahora toma la
// invitación de esa sesión y no de un token en el body (contract EmptyCommand).
//
// decisionMakerRef y tenantId SIEMPRE se derivan de la sesión (consent-session.ts, D5) o del
// propio dominio (invitation.recipientChannelRef tras V3); un `decisionMakerRef` en el body de
// /decision/submit o /decision/steps se ignora por completo (nunca se lee del payload, SM R0.2;
// DecisionStepRequest tampoco define ese campo en el contrato).

import { randomUUID } from "node:crypto";
import { deriveDecisionMakerRef as deriveKeyedDecisionMakerRef } from "../../modules/consent-decision/decision-maker-ref.ts";

import { DomainError } from "../../modules/common/errors.ts";
import { assertCsrfAndOrigin } from "../../modules/common/guards.ts";
import {
  openInvitationByRef,
  resolveInvitationForRedeemByHash,
  type InvitationPorts,
} from "../../modules/invitation/invitation.ts";
import {
  requestOtp,
  requestRightsOtp,
  resendOtp,
  submitOtp,
  submitRightsOtp,
  type OtpChallengePorts,
} from "../../modules/otp-challenge/otp-challenge.ts";
import {
  recordDecisionStep,
  startDecision,
  submitDecision,
  type ConsentDecisionPorts,
  type DecisionStepInput,
} from "../../modules/consent-decision/consent-decision.ts";
import type { PurposeChoice } from "../../ports/consent-decision-repository.port.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";
import { decodeSession, encodeSession, type ConsentSessionPayload } from "./consent-session.ts";
import { getServedConsentVersion } from "./served-consent-version.ts";
import {
  decodeLinkHandle,
  encodeLinkHandle,
  hashLinkToken,
  serializeLinkHandleCookie,
  type LinkHandleType,
} from "./link-handle.ts";
import type { InvitationHandlePolicy } from "../../modules/invitation/invitation-handle-policy.config.ts";

export interface ConsentFlowPorts {
  readonly invitation: InvitationPorts;
  readonly otp: OtpChallengePorts;
  readonly decision: ConsentDecisionPorts;
  /** CA-128 (Carlos, 2026-10-01): clave HMAC del decisionMakerRef (decision-maker-ref.ts), por entorno. */
  readonly decisionMakerRefKey: Buffer;
}

export interface RawConsentRequest {
  readonly originHeader: string | undefined;
  readonly csrfHeaderToken: string | undefined;
  readonly cookieHeader: string | undefined;
  readonly body: unknown;
  /** CA-125: cabecera Idempotency-Key (GRD-CM-08); solo la usan las rutas /staff/*. Opcional para
   * no romper a los llamadores existentes. */
  readonly idempotencyKeyHeader?: string | undefined;
}

export interface HttpResult {
  readonly status: 200 | 201 | 202 | 303 | 403 | 404 | 409 | 422;
  readonly body: Readonly<Record<string, unknown>>;
  /** Si está presente, el transporte (server.ts) debe fijar esta cookie de sesión (D5). */
  readonly setSessionCookie?: string;
  /** SEC-CNS-014 (CA-116 PR 2, GET /r/{token}): `Set-Cookie` de `__Host-cns-recovery` ya
   * serializado completo (recovery-handle.ts serializeRecoveryHandleCookie), a diferencia de
   * `setSessionCookie` (que el transporte serializa). Nunca coexiste con `setSessionCookie` en
   * el mismo HttpResult. */
  readonly setRecoveryHandleCookie?: string;
  /** SEC-CNS-014 patrón (Carlos, 2026-09-28, link-handle.ts): `Set-Cookie` de
   * `__Host-cns-i-handle`/`__Host-cns-m-handle` ya serializado completo, mismo criterio que
   * `setRecoveryHandleCookie` (nunca coexiste con `setSessionCookie` en el mismo HttpResult). */
  readonly setLinkHandleCookie?: string;
  /** CA-128 (case-confirmation.handler.ts, API-CNS-138): `Set-Cookie` de `__Host-cns-case` ya
   * serializado completo (case-session.ts serializeCaseSessionCookie), emitido solo por
   * /__dev/staff-login (LOCAL-only). Puede coexistir con setCaseCsrfCookie (no con las demás
   * cookies de sesión de este archivo). */
  readonly setCaseSessionCookie?: string;
  /** CA-128: `Set-Cookie` de la cookie CSRF de la consola CASE (csrf.ts serializeCsrfCookie),
   * emitido junto con setCaseSessionCookie por /__dev/staff-login. */
  readonly setCaseCsrfCookie?: string;
  /** CA-125 (staff-console.handler.ts): `Set-Cookie` de `__Host-cns-staff` ya serializado
   * (staff-session.ts), emitido solo por /__dev/staff-login (LOCAL-only) para TENANT_ADMIN. */
  readonly setStaffSessionCookie?: string;
  /** CA-125: cookie CSRF de la consola STAFF, emitida junto con setStaffSessionCookie. */
  readonly setStaffCsrfCookie?: string;
  /** Solo 303 (RedeemSeeOther): ruta relativa sin token (contracts/openapi Location header). */
  readonly location?: string;
  /** Cabeceras adicionales exigidas por el contrato para esta respuesta (p. ej. RedemptionToken
   * x-sensitive: "Referrer-Policy no-referrer"); nunca content-type ni Set-Cookie, esas las
   * fija siempre el transporte. */
  readonly extraHeaders?: Readonly<Record<string, string>>;
}

function csrfRejected(): HttpResult {
  return { status: 403, body: { code: "CSRF_REJECTED", status: 403, correlationId: randomUUID() } };
}

function uniformNotFound(): HttpResult {
  return { status: 404, body: { status: 404 } };
}

/** DomainErrorCode (ERR-XX-NN interno) -> ErrorCode externo (contracts/common.schema.json
 * $defs/ErrorCode.x-error-ids). El código interno NUNCA sale tal cual en un Problem/OtpRejected
 * (P1: el contrato solo reconoce los nombres de ErrorCode, no los IDs ERR-XX-NN). */
const EXTERNAL_ERROR_CODE: Readonly<Record<string, string>> = {
  "ERR-CM-06": "INVALID_TRANSITION",
  "ERR-OT-02": "OTP_CODE_REJECTED",
  "ERR-OT-03": "OTP_EXPIRED_OR_CONSUMED",
  "ERR-OT-04": "OTP_LOCKED",
  "ERR-OT-09": "OTP_RESEND_LIMIT",
  "ERR-CD-01": "ALREADY_DECIDED",
  "ERR-CD-02": "PURPOSE_SELECTION_INVALID",
  "ERR-CD-04": "DECISION_STEPS_INCOMPLETE",
  "ERR-CD-08": "DECISION_TERMINAL",
  // CA-116: reutilizado por submitRightsOtp para OTP_SCOPE_MISUSE (ERR-OT-05 no existe en
  // DomainErrorCode; ver comentario en otp-challenge.ts submitRightsOtp).
  "ERR-OT-01": "OTP_GENERIC_RESPONSE",
};

/** Problem uniforme (contracts/common.schema.json $defs/Problem): code + status + correlationId
 * siempre los tres (P1: faltaba correlationId y el code sin mapear al ErrorCode externo). */
function problem(status: 409 | 422, domainErrorCode: string): HttpResult {
  const code = EXTERNAL_ERROR_CODE[domainErrorCode];
  if (!code) {
    throw new Error(`consent-flow.handler: sin mapeo externo para ${domainErrorCode} (EXTERNAL_ERROR_CODE)`);
  }
  return { status, body: { code, status, correlationId: randomUUID() } };
}

function readSession(
  request: RawConsentRequest,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): ConsentSessionPayload | null {
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

/** decisionMakerRef derivado del canal ya ligado a la invitación (nunca del cliente, GRD-OT-02
 * + D5). Es una ref opaca `dm:v1:` + HMAC con clave de entorno (decision-maker-ref.ts; Carlos,
 * 2026-10-01), no el canal en claro ni un hash sin sal. */
function deriveDecisionMakerRef(key: Buffer, channelRef: string): string {
  return deriveKeyedDecisionMakerRef(key, channelRef);
}

// ---------------------------------------------------------------------------
// GET /i/{token} (API-CNS-101, P-12, SEC-CNS-014). Canje uniforme SIN transición (INV-CM-08
// reforzado, Carlos 2026-09-28 opción a): NUNCA lee la BD, solo hashea el token y fija el handle
// INVITATION_LANDING firmado (`__Host-cns-i-handle`, link-handle.ts). El 303 a /welcome es bit a
// bit idéntico sea el token válido, inexistente, expirado o de otro tenant: GRD-IV-07 se evalúa
// en GET /welcome (render, solo lectura), nunca aquí. TEST-CNS-509..511, TEST-CNS-610+.
// ---------------------------------------------------------------------------

/** Ruta sin token a la que redirige el canje (contracts/openapi Location, pattern ^/[a-z-]+$). */
const LANDING_ROUTE = "/welcome";

const LINK_REDEMPTION_HEADERS = { "Referrer-Policy": "no-referrer", "Cache-Control": "no-store" } as const;

export function handleRedeemInvitationLink(
  token: string,
  invitationHandlePolicy: InvitationHandlePolicy,
  invitationHandleKey: Buffer,
  invitationHandleCookieName: string,
): HttpResult {
  const tokenHash = hashLinkToken(token);
  const expiresAtEpochSeconds = Math.floor((Date.now() + invitationHandlePolicy.ttlMs) / 1000);
  const cookieValue = encodeLinkHandle(invitationHandleKey, "INVITATION_LANDING", tokenHash, expiresAtEpochSeconds);
  return {
    status: 303,
    body: {},
    location: LANDING_ROUTE,
    setLinkHandleCookie: serializeLinkHandleCookie(invitationHandleCookieName, cookieValue, Math.floor(invitationHandlePolicy.ttlMs / 1000)),
    // RedemptionToken (contracts/openapi parameters.RedemptionToken): "nunca se reenvía a
    // terceros (Referrer-Policy no-referrer)"; Cache-Control evita que un proxy/navegador
    // reintente esta respuesta ligada a un token de un solo canje.
    extraHeaders: { ...LINK_REDEMPTION_HEADERS },
  };
}

// ---------------------------------------------------------------------------
// GET /welcome (UX-CNS-001, SEC-CNS-014, INV-CM-08). Solo lectura. FINDING P1 (Carlos,
// prueba en navegador): el handle INVITATION_LANDING vigente (fijado por el GET /i/{token} MÁS
// RECIENTE) SIEMPRE manda sobre una sesión previa — "el último enlace abierto manda", mismo
// criterio que /recovery/confirm (que solo lee la cookie de recuperación, PR #23). Si el handle
// resuelve a una identidad DISTINTA de la sesión existente (otro invitationRef/tenantId, p. ej.
// el enlace de un segundo hijo), se descarta la sesión vieja y se crea una nueva; si resuelve a
// la MISMA identidad, se reutiliza la sesión existente tal cual (preserva progreso — OTP ya
// solicitado, decisionMakerRef, consentId — que un handle sin cambios no puede reconstruir). Si
// el handle está presente pero es inválido (inexistente/expirado), la sesión previa se borra
// SIEMPRE (aunque fuera válida): nunca se reutiliza el contexto de un enlace distinto al que el
// usuario acaba de abrir. Solo cuando NO hay handle en absoluto se cae de vuelta a la sesión
// existente (navegación dentro del mismo flujo, sin volver a pasar por GET /i/{token}).
// ---------------------------------------------------------------------------
export interface WelcomeLandingView {
  readonly session: ConsentSessionPayload | null;
  /** Presente solo cuando esta llamada resolvió una sesión NUEVA (handle recién resuelto, sea la
   * primera visita o un enlace distinto al de la sesión previa): el caller debe fijar esta
   * cookie en la respuesta. */
  readonly sessionCookieToSet?: string;
  /** true cuando hay que invalidar una cookie de sesión previa (handle presente pero inválido,
   * o handle presente y válido mas de una identidad DISTINTA de la sesión previa): el caller
   * debe fijar `Set-Cookie` con Max-Age=0 para esa cookie. */
  readonly clearSessionCookie?: boolean;
}

const INVITATION_LANDING_HANDLE_TYPE: LinkHandleType = "INVITATION_LANDING";

function sameInvitationIdentity(session: ConsentSessionPayload, tenantId: string, invitationRef: string): boolean {
  return session.tenantId === tenantId && session.invitationRef === invitationRef;
}

export async function resolveWelcomeLandingSession(
  ports: Pick<ConsentFlowPorts, "invitation">,
  sessionSecret: Buffer,
  existingSession: ConsentSessionPayload | null,
  invitationHandleKey: Buffer,
  cookies: Readonly<Record<string, string>>,
  invitationHandleCookieName: string,
): Promise<WelcomeLandingView> {
  const handle = decodeLinkHandle(invitationHandleKey, INVITATION_LANDING_HANDLE_TYPE, cookies[invitationHandleCookieName]);
  if (handle) {
    const found = await resolveInvitationForRedeemByHash(ports.invitation, handle.h);
    if (!found) {
      // Handle inválido: nunca reutiliza una sesión previa, la que sea (P1: "el último enlace
      // abierto manda" incluye el caso "el último enlace es inválido").
      return { session: null, clearSessionCookie: Boolean(existingSession) };
    }
    if (existingSession && existingSession.invitationRef && sameInvitationIdentity(existingSession, found.tenantId, found.invitationRef)) {
      // Mismo enlace que ya generó esta sesión: preserva el progreso (OTP, decisión) en vez de
      // reconstruir una sesión LANDING "en blanco" en cada recarga.
      return { session: existingSession };
    }
    const session: ConsentSessionPayload = { tenantId: found.tenantId, invitationRef: found.invitationRef };
    return { session, sessionCookieToSet: encodeSession(sessionSecret, session) };
  }
  if (existingSession && existingSession.invitationRef) {
    return { session: existingSession };
  }
  return { session: null };
}

// ---------------------------------------------------------------------------
// POST /invitation/open (I4). API-CNS-115: EmptyCommand; la invitación se toma de la sesión
// LANDING creada por GET /i/{token}, nunca de un token en el body.
// ---------------------------------------------------------------------------
export async function handleOpenInvitation(
  request: RawConsentRequest,
  ports: Pick<ConsentFlowPorts, "invitation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.invitationRef) return uniformNotFound();

  try {
    const opened = await openInvitationByRef(ports.invitation, session.tenantId, session.invitationRef);
    const nextSession: ConsentSessionPayload = { tenantId: opened.tenantId, invitationRef: opened.invitationRef };
    return {
      // InvitationOpenedAck (contracts/api-payloads.schema.json:303-315, additionalProperties
      // false): acuse mínimo sin invitationRef ni state (P1, x-scope-note actualizado arriba).
      status: 200,
      body: { result: "OPENED" },
      setSessionCookie: encodeSession(sessionSecret, nextSession),
    };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-IV-01" || err.code === "ERR-CM-01") return uniformNotFound();
      if (err.code === "ERR-CM-06") return problem(409, err.code);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// CA-116 (revocación IT0, UX-CNS-004): POST /otp/request y /otp/submit (V1/V3) también sirven
// scope REVOCATION/MANAGE (contracts/openapi x-guards-by-scope), sobre la MISMA sesión MANAGE
// (chainRef, nunca del cliente). El scope se resuelve SIEMPRE del estado de la sesión, nunca de
// un campo del body: DECISION si la sesión viene de GET /i/{token} (invitationRef, sin
// chainRef); si viene de GET /m/{token} (chainRef presente), MANAGE hasta que exista
// revocationRef (fijado solo por R1, POST /manage/revocation) y REVOCATION desde entonces. El
// channelRef de REVOCATION/MANAGE es un valor opaco derivado del chainRef (nunca del cliente,
// GRD-OT-02 trivialmente satisfecho); ver nota de alcance en otp-challenge.ts
// requestRightsOtp/submitRightsOtp.
// ---------------------------------------------------------------------------

type OtpFlowScope = "DECISION" | "MANAGE" | "REVOCATION";

function resolveOtpScope(session: ConsentSessionPayload): OtpFlowScope | null {
  if (session.chainRef) return session.revocationRef ? "REVOCATION" : "MANAGE";
  if (session.invitationRef) return "DECISION";
  return null;
}

/** Nunca PII: valor opaco estable por chainRef, solo para el sink/canal in-memory de IT0. */
function manageChannelRef(chainRef: string): string {
  return `mgmt:${chainRef}`;
}

// ---------------------------------------------------------------------------
// POST /otp/request (V1). API-CNS-120. Respuesta uniforme (x-uniform-response): 202 siempre
// que la sesión resuelva, sin distinguir ERR-OT-01/ERR-OT-08 del éxito.
// ---------------------------------------------------------------------------
export async function handleRequestOtp(
  request: RawConsentRequest,
  ports: Pick<ConsentFlowPorts, "invitation" | "otp">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session) return uniformNotFound();
  const scope = resolveOtpScope(session);

  if (scope === "MANAGE" || scope === "REVOCATION") {
    const chainRef = session.chainRef;
    if (!chainRef) return uniformNotFound();
    const verificationRef =
      scope === "MANAGE" ? (session.manageVerificationRef ?? randomUUID()) : (session.revocationVerificationRef ?? randomUUID());
    try {
      await requestRightsOtp(ports.otp, session.tenantId, verificationRef, scope, chainRef, manageChannelRef(chainRef));
    } catch (err) {
      if (!(err instanceof DomainError)) throw err;
      // INV-OT-06: RIGHTS nunca deniega (respuesta uniforme igual que el éxito).
    }
    const nextSession: ConsentSessionPayload =
      scope === "MANAGE" ? { ...session, manageVerificationRef: verificationRef } : { ...session, revocationVerificationRef: verificationRef };
    return { status: 202, body: { result: "RECEIVED" }, setSessionCookie: encodeSession(sessionSecret, nextSession) };
  }

  if (scope !== "DECISION" || !session.invitationRef) return uniformNotFound();
  // SEC-CNS-016: la lectura corre BAJO el tenant de la sesión (inTenant), nunca fuera de una tx.
  const invitationRef = session.invitationRef;
  const invitation = await ports.invitation.uow.inTenant(session.tenantId, (tx) => tx.invitationRepo.findByRef(session.tenantId, invitationRef));
  if (!invitation || !invitation.recipientChannelRef) return uniformNotFound();

  let verificationRef = session.verificationRef ?? randomUUID();
  try {
    // La sesion guarda la ref del challenge VIGENTE: si el activo expiro, V1 emite uno nuevo (otp-challenge.spec V5).
    const record = await requestOtp(ports.otp, session.tenantId, verificationRef, session.invitationRef, invitation.recipientChannelRef);
    verificationRef = record.verificationRef;
  } catch (err) {
    if (!(err instanceof DomainError)) throw err;
    // ERR-OT-01/ERR-OT-08: x-uniform-response, no se distingue del éxito (202 igual).
  }
  const nextSession: ConsentSessionPayload = { ...session, verificationRef };
  // UniformAccepted (contracts/common.schema.json $defs/UniformAccepted): result es la
  // constante "RECEIVED" (P1: no "ACCEPTED").
  return { status: 202, body: { result: "RECEIVED" }, setSessionCookie: encodeSession(sessionSecret, nextSession) };
}

// ---------------------------------------------------------------------------
// POST /otp/resend (V2r). API-CNS-122. Reemplaza el código sin reiniciar attempts ni el
// presupuesto (GRD-OT-06); requiere sesión con verificationRef (mismo challenge que V1 creó).
// ---------------------------------------------------------------------------
export async function handleResendOtp(
  request: RawConsentRequest,
  ports: Pick<ConsentFlowPorts, "otp">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.verificationRef) return uniformNotFound();

  try {
    await resendOtp(ports.otp, session.tenantId, session.verificationRef);
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      if (err.code === "ERR-OT-09") return problem(409, err.code);
      // ERR-OT-03/ERR-OT-04 (challenge terminal): respuesta uniforme (mismo patrón que
      // ERR-OT-01/ERR-OT-08 en V1, sin distinguir del éxito genérico de UniformAccepted).
    } else {
      throw err;
    }
  }
  // UniformAccepted (contracts/common.schema.json $defs/UniformAccepted): mismo cuerpo que
  // POST /otp/request (result: "RECEIVED"); no fija cookie nueva (la sesión no cambia en V2r).
  return { status: 202, body: { result: "RECEIVED" } };
}

// ---------------------------------------------------------------------------
// POST /otp/submit (V3). API-CNS-121. Crea la sesión verificada (decisionMakerRef derivado
// del canal ligado, nunca del body, D5/GRD-OT-02).
// ---------------------------------------------------------------------------
export async function handleSubmitOtp(
  request: RawConsentRequest,
  ports: Pick<ConsentFlowPorts, "invitation" | "otp" | "decisionMakerRefKey">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session) return uniformNotFound();
  const scope = resolveOtpScope(session);
  const code = typeof (request.body as { code?: unknown } | null)?.code === "string" ? (request.body as { code: string }).code : "";

  if (scope === "MANAGE" || scope === "REVOCATION") {
    const verificationRef = scope === "MANAGE" ? session.manageVerificationRef : session.revocationVerificationRef;
    if (!verificationRef) return uniformNotFound();
    try {
      await submitRightsOtp(ports.otp, session.tenantId, verificationRef, scope, code);
      const verifiedSession: ConsentSessionPayload =
        scope === "MANAGE"
          ? { ...session, manageDecisionMakerRef: deriveDecisionMakerRef(ports.decisionMakerRefKey, manageChannelRef(session.chainRef ?? "")) }
          : { ...session, revocationOtpVerified: true };
      return {
        status: 200,
        body: { result: "VERIFIED", scope },
        setSessionCookie: encodeSession(sessionSecret, verifiedSession),
      };
    } catch (err) {
      if (err instanceof DomainError) {
        if (err.code === "ERR-CM-01") return uniformNotFound();
        // INV-OT-06: la respuesta de rechazo en RIGHTS nunca dice "denegado"; verify.js decide
        // la variante bloqueada por el propio code (OTP_LOCKED) igual que en scope DECISION.
        return problem(422, err.code);
      }
      throw err;
    }
  }

  if (scope !== "DECISION" || !session.verificationRef || !session.invitationRef) return uniformNotFound();
  // SEC-CNS-016: la lectura corre BAJO el tenant de la sesión (inTenant), nunca fuera de una tx.
  const invitationRef = session.invitationRef;
  const invitation = await ports.invitation.uow.inTenant(session.tenantId, (tx) => tx.invitationRepo.findByRef(session.tenantId, invitationRef));
  if (!invitation || !invitation.recipientChannelRef) return uniformNotFound();

  const decisionMakerRef = deriveDecisionMakerRef(ports.decisionMakerRefKey, invitation.recipientChannelRef);

  try {
    await submitOtp(ports.otp, session.tenantId, session.verificationRef, code, decisionMakerRef);
    const verifiedSession: ConsentSessionPayload = { ...session, decisionMakerRef };
    return {
      // OtpVerified (contracts/api-payloads.schema.json $defs/OtpVerified): scope es requerido
      // (P1: faltaba). IT0 solo implementa scope DECISION (otp-challenge.ts, alcance del archivo).
      status: 200,
      body: { result: "VERIFIED", scope: "DECISION" },
      setSessionCookie: encodeSession(sessionSecret, verifiedSession),
    };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      // ERR-OT-02/03/04 (V2/V4/expirado): rechazo con el code específico de OtpRejected (P1:
      // "OTP_REJECTED" no existe en el enum del contrato; sin distinguir detalle de intentos).
      return problem(422, err.code);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// POST /decision/steps (C2, con C1 perezoso en la primera llamada de la sesión). API-CNS-126.
// decisionMakerRef SIEMPRE de la sesión; DecisionStepRequest no define ese campo (SM R0.2).
// ---------------------------------------------------------------------------
export type SubmitDecisionStepBody =
  | { readonly stepKind?: unknown; readonly relationshipRef?: unknown; readonly authorityDeclared?: unknown; readonly subjectConfirmed?: unknown };

/** Valida la forma de DecisionStepRequest (api-payloads.schema.json:413-487) contra el body
 * crudo del cliente. Cualquier forma que no calce exactamente uno de los 4 stepKind con sus
 * campos requeridos (incluido authorityDeclared/subjectConfirmed !== true, es decir sin
 * preselección real, P06) devuelve `null` -> 422 ERR-CD-04 en el caller. */
function parseDecisionStepInput(body: unknown): DecisionStepInput | null {
  const b = (body ?? {}) as SubmitDecisionStepBody;
  switch (b.stepKind) {
    case "CONTEXT_INFORMATION_VIEWED":
      return { stepKind: "CONTEXT_INFORMATION_VIEWED" };
    case "CONSENT_VERSION_VIEWED":
      return { stepKind: "CONSENT_VERSION_VIEWED" };
    case "DECISION_MAKER_AUTHORITY_DECLARED":
      if (typeof b.relationshipRef === "string" && b.authorityDeclared === true) {
        return { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: b.relationshipRef, authorityDeclared: true };
      }
      return null;
    case "SUBJECT_CONFIRMED":
      if (b.subjectConfirmed === true) {
        return { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true };
      }
      return null;
    default:
      return null;
  }
}

export async function handleRecordDecisionStep(
  request: RawConsentRequest,
  ports: ConsentFlowPorts,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.verificationRef || !session.decisionMakerRef || !session.invitationRef) return uniformNotFound();

  const step = parseDecisionStepInput(request.body);
  if (!step) return problem(422, "ERR-CD-04");

  let consentId = session.consentId;
  let sessionCookieValue: string | undefined;
  if (!consentId) {
    // C1 perezoso (x-scope-note arriba): primera llamada de /decision/steps de esta sesión.
    consentId = randomUUID();
    try {
      await startDecision(ports.decision, session.tenantId, "DECISION_MAKER", {
        consentId,
        invitationRef: session.invitationRef,
        verificationRef: session.verificationRef,
        decisionMakerRef: session.decisionMakerRef, // nunca del body
      });
    } catch (err) {
      if (err instanceof DomainError && (err.code === "ERR-CM-01" || err.code === "ERR-CD-07")) return uniformNotFound();
      throw err;
    }
    sessionCookieValue = encodeSession(sessionSecret, { ...session, consentId });
  }

  try {
    await recordDecisionStep(ports.decision, session.tenantId, "DECISION_MAKER", session.decisionMakerRef, consentId, step);
    // DecisionStepRecorded (contracts/api-payloads.schema.json:517-562): servedVersion solo en
    // CONSENT_VERSION_VIEWED (if/then/else del schema).
    const body: Record<string, unknown> = { stepKind: step.stepKind, state: "PENDING" };
    if (step.stepKind === "CONSENT_VERSION_VIEWED") body.servedVersion = getServedConsentVersion();
    return { status: 200, body, setSessionCookie: sessionCookieValue };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01" || err.code === "ERR-CD-07") return uniformNotFound();
      if (err.code === "ERR-CD-04") return { ...problem(422, err.code), setSessionCookie: sessionCookieValue };
      if (err.code === "ERR-CM-06") return { ...problem(409, err.code), setSessionCookie: sessionCookieValue };
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// POST /decision/submit (C3/C5). API-CNS-127. Exige que la sesión ya tenga `consentId`
// (/decision/steps ya corrió al menos una vez, C1 perezoso); actor y decisionMakerRef SIEMPRE
// de la sesión, decisionMakerRef del body se ignora.
// ---------------------------------------------------------------------------
export interface SubmitDecisionBody {
  readonly purposes?: ReadonlyArray<{ purpose?: unknown; choice?: unknown }>;
  /** Si el cliente lo envía, se ignora por completo (D5, SM R0.2); no se lee más abajo. */
  readonly decisionMakerRef?: unknown;
}

export async function handleSubmitDecision(
  request: RawConsentRequest,
  ports: ConsentFlowPorts,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.verificationRef || !session.decisionMakerRef || !session.consentId) return uniformNotFound();

  const body = (request.body ?? {}) as SubmitDecisionBody;
  const rawPurposes = Array.isArray(body.purposes) ? body.purposes : [];
  const purposes = rawPurposes
    .filter((p) => typeof p.purpose === "string" && (p.choice === "GRANT" || p.choice === "DECLINE"))
    .map((p) => ({ purpose: p.purpose as string, choice: p.choice as PurposeChoice }));

  try {
    const decided = await submitDecision(
      ports.decision,
      session.tenantId,
      "DECISION_MAKER",
      session.decisionMakerRef, // nunca body.decisionMakerRef
      session.consentId,
      purposes,
    );
    // DecisionRecorded (contracts/api-payloads.schema.json $defs/DecisionRecorded): receiptRef
    // es requerido (P1: faltaba); nunca incluye el management_token (va solo al canal ligado).
    return { status: 200, body: { consentId: decided.consentId, state: decided.state, receiptRef: decided.receiptRef } };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01" || err.code === "ERR-CD-07") return uniformNotFound();
      if (err.code === "ERR-CD-02") return problem(422, err.code);
      if (err.code === "ERR-CD-01" || err.code === "ERR-CD-04" || err.code === "ERR-CD-08") return problem(409, err.code);
    }
    throw err;
  }
}
