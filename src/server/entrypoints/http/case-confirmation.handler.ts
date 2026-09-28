// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-138 (POST
// /platform/rights-cases/{caseRef}/confirmation, security: caseSession), RecordCaseConfirmationRequest/
// CaseConfirmationAck (api-payloads.schema.json); specs/state-machines/revocation.spec.yaml RH3
// paso 1 (GRD-RV-10/ERR-RV-20); specs/state-machines/rights-case.spec.yaml GRD-RC-15/ERR-RC-10.
// CA-128.
//
// Mismo patrón que revocation-flow.handler.ts: actor (recordedByRef) y tenant/caseRef SIEMPRE
// de la sesión CASE (nunca del body, GRD-CM-07), GRD-CM-10 (CSRF/Origin) en el POST, 404
// uniforme si la sesión CASE no resuelve o no está ligada a este caseRef (GRD-CM-01, contracts/
// openapi parameters.CaseRef: "Debe coincidir con el caseRef ligado a la sesión CASE; si no,
// 404 uniforme").
//
// Decisión de Carlos, 2026-09-28, opción (ii): sin IdP real en IT0 (APR-IDP PENDING). La
// sesión CASE la emite únicamente /__dev/staff-login (handleDevStaffLogin, más abajo),
// LOCAL-only (GRD-CM-13, mismo guard que /__dev/otp-sink de consent-flow-server.ts), a partir
// de la lista nominal sintética de StaffIdentityPort. LEGAL DECISION LD-03 (quién tiene
// autoridad legal para registrar la confirmación de RH3) NO se resuelve en este archivo:
// handleRecordCaseConfirmation solo aplica los guards técnicos citados arriba.

import { randomUUID } from "node:crypto";

import { DomainError } from "../../modules/common/errors.ts";
import { assertCsrfAndOrigin } from "../../modules/common/guards.ts";
import { recordCaseConfirmationPendingCosign, type RevocationPorts } from "../../modules/revocation/revocation.ts";
import type { RightsCaseRepositoryPort } from "../../ports/rights-case-repository.port.ts";
import type { StaffIdentityPort } from "../../ports/staff-identity.port.ts";
import type { Environment } from "../../modules/common/types.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";
import { decodeCaseSession, encodeCaseSession, serializeCaseSessionCookie, type CaseSessionPayload } from "./case-session.ts";
import { generateCsrfToken, serializeCsrfCookie } from "./csrf.ts";
import type { HttpResult, RawConsentRequest } from "./consent-flow.handler.ts";

export interface CaseConfirmationPorts {
  readonly revocation: RevocationPorts;
  readonly rightsCaseRepo: Pick<RightsCaseRepositoryPort, "findByRef">;
  readonly staffIdentity: StaffIdentityPort;
}

function uniformNotFound(): HttpResult {
  return { status: 404, body: { status: 404 } };
}

function csrfRejected(): HttpResult {
  return { status: 403, body: { code: "CSRF_REJECTED", status: 403, correlationId: randomUUID() } };
}

/** ERR-CM-10 (ACTOR_NOT_ALLOWED): expuesto de forma distinguible solo en consolas STAFF/
 * PLATFORM/CASE (contracts/openapi, "ACTOR_NOT_ALLOWED solo se expone en las consolas STAFF,
 * PLATFORM y CASE"), nunca en rutas del portador. */
function actorNotAllowed(): HttpResult {
  return { status: 403, body: { code: "ERR-CM-10", status: 403, correlationId: randomUUID() } };
}

function problem(status: 409 | 422, code: string): HttpResult {
  return { status, body: { code, status, correlationId: randomUUID() } };
}

function checkCaseCsrf(request: RawConsentRequest, config: RightsCaseHttpConfig): HttpResult | null {
  const cookies = parseCookies(request.cookieHeader);
  try {
    assertCsrfAndOrigin({
      originHeader: request.originHeader,
      allowedOrigin: config.allowedOrigin,
      csrfHeaderToken: request.csrfHeaderToken,
      csrfCookieToken: cookies[config.caseCsrfCookieName],
    });
    return null;
  } catch (err) {
    if (err instanceof DomainError && err.code === "ERR-CM-09") return csrfRejected();
    throw err;
  }
}

// ---------------------------------------------------------------------------
// POST /platform/rights-cases/{caseRef}/confirmation (API-CNS-138, RH3 paso 1). caseRef llega
// del path; GRD-CM-01 exige que coincida con el de la sesión CASE, o 404 uniforme.
// ---------------------------------------------------------------------------
export function handleRecordCaseConfirmation(
  request: RawConsentRequest,
  caseRefFromPath: string,
  ports: CaseConfirmationPorts,
  config: RightsCaseHttpConfig,
  caseSessionKey: Buffer,
): HttpResult {
  const csrfFailure = checkCaseCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const cookies = parseCookies(request.cookieHeader);
  const session = decodeCaseSession(caseSessionKey, cookies[config.caseSessionCookieName]);
  if (!session) return uniformNotFound(); // GRD-CM-01: sin sesión CASE, mismo criterio que el resto del repo.
  if (session.caseRef !== caseRefFromPath) return uniformNotFound(); // caseRef debe coincidir con la sesión (contracts/openapi CaseRef).

  if (session.role !== "RIGHTS_OPERATOR") {
    // GRD-CM-07 (actor_derived_and_allowed): solo RIGHTS_OPERATOR ejecuta record_case_confirmation.
    // LEGAL DECISION LD-03 (revocation.spec.yaml, OPEN-RV-06): este chequeo de rol técnico
    // (RIGHTS_OPERATOR vs. APPROVER en la sesión CASE) es el piso interino de R13-4; quién
    // tiene autoridad LEGAL para registrar/co-firmar la confirmación de RH3 no está resuelto
    // por este código ni por ningún modelo de IA — es human gate de Carlos.
    return actorNotAllowed();
  }

  const body = request.body as { confirmationGivenOnCasePage?: unknown } | undefined;
  if (body?.confirmationGivenOnCasePage !== true) {
    // RecordCaseConfirmationRequest exige el campo const true; sin él, rechazo determinista
    // (mismo criterio que confirmTotalWithdrawal en revocation-flow.handler.ts).
    return problem(422, "ERR-CM-06");
  }

  const rightsCase = ports.rightsCaseRepo.findByRef(session.tenantId, session.caseRef);
  if (!rightsCase || rightsCase.tenantId !== session.tenantId || !rightsCase.revocationRef) {
    return uniformNotFound();
  }

  try {
    const recorded = recordCaseConfirmationPendingCosign(ports.revocation, ports.staffIdentity, session.tenantId, rightsCase.revocationRef, session.caseRef, {
      recordedByPrincipalRef: session.principalRef,
    });
    // CaseConfirmationAck: sin co-firma, cosign = AWAITING_COSIGN y revocationState = VERIFIED
    // (nunca CONFIRMED en este paso: x-state-transition step:record, effect:none).
    return { status: 200, body: { cosign: "AWAITING_COSIGN", revocationState: recorded.status } };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      return problem(409, err.code);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// POST /__dev/staff-login (LOCAL-only, GRD-CM-13; no es parte del contrato OpenAPI, misma
// clase de herramienta de depuración que /__dev/otp-sink). Emite la sesión CASE (cookie
// __Host-cns-case, P-26 provisional) y su cookie CSRF a partir de una ref sintética ya
// existente en el StaffIdentityPort inyectado (dev-local-config.ts / fixtures de test); nunca
// crea identidades nuevas ni decide autoridad legal (LD-03 sigue abierto).
// ---------------------------------------------------------------------------
export interface DevStaffLoginPorts {
  readonly staffIdentity: StaffIdentityPort;
  readonly rightsCaseRepo: Pick<RightsCaseRepositoryPort, "findByRef">;
}

export function handleDevStaffLogin(
  request: RawConsentRequest,
  environment: Environment,
  ports: DevStaffLoginPorts,
  config: RightsCaseHttpConfig,
  caseSessionKey: Buffer,
): HttpResult {
  if (environment !== "LOCAL") {
    // Fail-closed (GRD-CM-13): fuera de LOCAL esta ruta no existe, ni siquiera como 403 (mismo
    // criterio que /__dev/otp-sink, consent-flow-server.ts).
    return { status: 404, body: { status: 404 } };
  }

  const body = request.body as { tenantId?: unknown; caseRef?: unknown; principalRef?: unknown } | undefined;
  const tenantId = typeof body?.tenantId === "string" ? body.tenantId : undefined;
  const caseRef = typeof body?.caseRef === "string" ? body.caseRef : undefined;
  const principalRef = typeof body?.principalRef === "string" ? body.principalRef : undefined;
  if (!tenantId || !caseRef || !principalRef) {
    return { status: 422, body: { status: 422 } };
  }

  const principal = ports.staffIdentity.findByPrincipalRef(principalRef);
  if (!principal) {
    return { status: 422, body: { status: 422 } };
  }

  const rightsCase = ports.rightsCaseRepo.findByRef(tenantId, caseRef);
  if (!rightsCase || rightsCase.caseRef !== caseRef) {
    return { status: 422, body: { status: 422 } };
  }

  const session: CaseSessionPayload = { tenantId, caseRef, principalRef: principal.principalRef, role: principal.role };
  return {
    status: 200,
    body: { principalRef: principal.principalRef, role: principal.role },
    setCaseSessionCookie: serializeCaseSessionCookie(config.caseSessionCookieName, encodeCaseSession(caseSessionKey, session)),
    setCaseCsrfCookie: serializeCsrfCookie(config.caseCsrfCookieName, generateCsrfToken()),
  };
}
