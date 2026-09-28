// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-101 (GET /i/{token}),
// API-CNS-115 (POST /invitation/open), API-CNS-120 (POST /otp/request), API-CNS-121 (POST
// /otp/submit) y API-CNS-127 (POST /decision/submit, consolida C1/C2/C3/C5 en un solo
// endpoint IT0 — ver x-scope-note más abajo); specs/state-machines/invitation.spec.yaml I4
// (efecto de canje + efecto de apertura), specs/state-machines/common.spec.yaml INV-CM-08,
// otp-challenge.spec.yaml V1/V3, consent-decision.spec.yaml C1/C2/C3/C5; common.spec.yaml
// GRD-CM-10 (D1). TEST-CNS-498..TEST-CNS-51x (traceability/test-matrix.csv).
//
// x-scope-note (reportado a Carlos): el contrato separa /decision/start, /decision/steps y
// /decision/submit en tres POST; esta tarea (CA-116 HTTP) ejecuta C1 (start) y C2 (steps)
// internamente dentro de este mismo POST /decision/submit en vez de exponerse como rutas
// separadas, por alcance. GET /i/{token} (P-12) sí está implementado: crea la sesión LANDING
// (tenantId, invitationRef) sin transicionar Invitation (INV-CM-08); la transición I4
// (SENT -> OPENED) ocurre solo en el POST /invitation/open subsiguiente, que ahora toma la
// invitación de esa sesión y no de un token en el body (contract EmptyCommand).
//
// decisionMakerRef y tenantId SIEMPRE se derivan de la sesión (consent-session.ts, D5) o del
// propio dominio (invitation.recipientChannelRef tras V3); un `decisionMakerRef` en el body de
// /decision/submit se ignora por completo (nunca se lee del payload, SM R0.2).

import { randomUUID, createHash } from "node:crypto";

import { DomainError } from "../../modules/common/errors.ts";
import { assertCsrfAndOrigin } from "../../modules/common/guards.ts";
import {
  openInvitationByRef,
  resolveInvitationForRedeem,
  type InvitationPorts,
} from "../../modules/invitation/invitation.ts";
import { requestOtp, submitOtp, type OtpChallengePorts } from "../../modules/otp-challenge/otp-challenge.ts";
import {
  recordRequiredSteps,
  startDecision,
  submitDecision,
  type ConsentDecisionPorts,
} from "../../modules/consent-decision/consent-decision.ts";
import type { PurposeChoice } from "../../ports/consent-decision-repository.port.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";
import { decodeSession, encodeSession, type ConsentSessionPayload } from "./consent-session.ts";

export interface ConsentFlowPorts {
  readonly invitation: InvitationPorts;
  readonly otp: OtpChallengePorts;
  readonly decision: ConsentDecisionPorts;
}

export interface RawConsentRequest {
  readonly originHeader: string | undefined;
  readonly csrfHeaderToken: string | undefined;
  readonly cookieHeader: string | undefined;
  readonly body: unknown;
}

export interface HttpResult {
  readonly status: 200 | 202 | 303 | 403 | 404 | 409 | 422;
  readonly body: Readonly<Record<string, unknown>>;
  /** Si está presente, el transporte (server.ts) debe fijar esta cookie de sesión (D5). */
  readonly setSessionCookie?: string;
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
  "ERR-CD-01": "ALREADY_DECIDED",
  "ERR-CD-02": "PURPOSE_SELECTION_INVALID",
  "ERR-CD-04": "DECISION_STEPS_INCOMPLETE",
  "ERR-CD-08": "DECISION_TERMINAL",
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
 * + D5). Es una ref opaca, no el canal en claro (cero PII en ledger/sesión más allá de lo que
 * ya persiste el propio canal de la invitación). */
function deriveDecisionMakerRef(channelRef: string): string {
  return `dm:${createHash("sha256").update(channelRef).digest("hex").slice(0, 32)}`;
}

// ---------------------------------------------------------------------------
// GET /i/{token} (API-CNS-101, P-12). Canje: crea la sesión LANDING (tenantId, invitationRef)
// y redirige sin token (INV-CM-08: no transiciona). TEST-CNS-509..511.
// ---------------------------------------------------------------------------

/** Ruta sin token a la que redirige el canje (contracts/openapi Location, pattern ^/[a-z-]+$). */
const LANDING_ROUTE = "/welcome";

export function handleRedeemInvitationLink(
  token: string,
  ports: Pick<ConsentFlowPorts, "invitation">,
  sessionSecret: Buffer,
): HttpResult {
  const found = resolveInvitationForRedeem(ports.invitation, token);
  if (!found) return uniformNotFound();

  const session: ConsentSessionPayload = { tenantId: found.tenantId, invitationRef: found.invitationRef };
  return {
    status: 303,
    body: {},
    location: LANDING_ROUTE,
    setSessionCookie: encodeSession(sessionSecret, session),
    // RedemptionToken (contracts/openapi parameters.RedemptionToken): "nunca se reenvía a
    // terceros (Referrer-Policy no-referrer)"; Cache-Control evita que un proxy/navegador
    // reintente esta respuesta ligada a un token de un solo canje.
    extraHeaders: { "Referrer-Policy": "no-referrer", "Cache-Control": "no-store" },
  };
}

// ---------------------------------------------------------------------------
// POST /invitation/open (I4). API-CNS-115: EmptyCommand; la invitación se toma de la sesión
// LANDING creada por GET /i/{token}, nunca de un token en el body.
// ---------------------------------------------------------------------------
export function handleOpenInvitation(
  request: RawConsentRequest,
  ports: Pick<ConsentFlowPorts, "invitation">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session) return uniformNotFound();

  try {
    const opened = openInvitationByRef(ports.invitation, session.tenantId, session.invitationRef);
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
// POST /otp/request (V1). API-CNS-120. Respuesta uniforme (x-uniform-response): 202 siempre
// que la sesión resuelva, sin distinguir ERR-OT-01/ERR-OT-08 del éxito.
// ---------------------------------------------------------------------------
export function handleRequestOtp(
  request: RawConsentRequest,
  ports: Pick<ConsentFlowPorts, "invitation" | "otp">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session) return uniformNotFound();

  const invitation = ports.invitation.invitationRepo.findByRef(session.tenantId, session.invitationRef);
  if (!invitation || !invitation.recipientChannelRef) return uniformNotFound();

  const verificationRef = session.verificationRef ?? randomUUID();
  try {
    requestOtp(ports.otp, session.tenantId, verificationRef, session.invitationRef, invitation.recipientChannelRef);
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
// POST /otp/submit (V3). API-CNS-121. Crea la sesión verificada (decisionMakerRef derivado
// del canal ligado, nunca del body, D5/GRD-OT-02).
// ---------------------------------------------------------------------------
export function handleSubmitOtp(
  request: RawConsentRequest,
  ports: Pick<ConsentFlowPorts, "invitation" | "otp">,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.verificationRef) return uniformNotFound();

  const invitation = ports.invitation.invitationRepo.findByRef(session.tenantId, session.invitationRef);
  if (!invitation || !invitation.recipientChannelRef) return uniformNotFound();

  const code = typeof (request.body as { code?: unknown } | null)?.code === "string" ? (request.body as { code: string }).code : "";
  const decisionMakerRef = deriveDecisionMakerRef(invitation.recipientChannelRef);

  try {
    submitOtp(ports.otp, session.tenantId, session.verificationRef, code, decisionMakerRef);
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
// POST /decision/submit (C1+C2+C3/C5 en un solo POST, x-scope-note). API-CNS-127.
// actor y decisionMakerRef SIEMPRE de la sesión; decisionMakerRef del body se ignora.
// ---------------------------------------------------------------------------
export interface SubmitDecisionBody {
  readonly purposes?: ReadonlyArray<{ purpose?: unknown; choice?: unknown }>;
  /** Si el cliente lo envía, se ignora por completo (D5, SM R0.2); no se lee más abajo. */
  readonly decisionMakerRef?: unknown;
}

export function handleSubmitDecision(
  request: RawConsentRequest,
  ports: ConsentFlowPorts,
  config: RightsCaseHttpConfig,
  sessionSecret: Buffer,
): HttpResult {
  const csrfFailure = checkCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const session = readSession(request, config, sessionSecret);
  if (!session || !session.verificationRef || !session.decisionMakerRef) return uniformNotFound();

  const body = (request.body ?? {}) as SubmitDecisionBody;
  const rawPurposes = Array.isArray(body.purposes) ? body.purposes : [];
  const purposes = rawPurposes
    .filter((p) => typeof p.purpose === "string" && (p.choice === "GRANT" || p.choice === "DECLINE"))
    .map((p) => ({ purpose: p.purpose as string, choice: p.choice as PurposeChoice }));

  const consentId = randomUUID();
  try {
    startDecision(ports.decision, session.tenantId, "DECISION_MAKER", {
      consentId,
      invitationRef: session.invitationRef,
      verificationRef: session.verificationRef,
      decisionMakerRef: session.decisionMakerRef, // nunca body.decisionMakerRef
    });
    recordRequiredSteps(ports.decision, session.tenantId, consentId);
    const decided = submitDecision(
      ports.decision,
      session.tenantId,
      "DECISION_MAKER",
      session.decisionMakerRef, // nunca body.decisionMakerRef
      consentId,
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
