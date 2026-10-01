// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-139 (POST .../confirmation/cosign,
// CosignCaseConfirmationRequest, revocation.spec RH3 paso 2, GRD-RV-26/ERR-RV-18) y API-CNS-138 (POST
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
import {
  approveCaseVerification,
  cosignCaseConfirmation,
  proposeCaseVerification,
  recordCaseConfirmationPendingCosign,
  withdrawCaseVerificationProposal,
  type RevocationPorts,
} from "../../modules/revocation/revocation.ts";
import type { UnitOfWorkPort } from "../../ports/unit-of-work.port.ts";
import type { StaffIdentityPort } from "../../ports/staff-identity.port.ts";
import type { Environment } from "../../modules/common/types.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";
import { decodeCaseSession, encodeCaseSession, serializeCaseSessionCookie, type CaseSessionPayload } from "./case-session.ts";
import { generateCsrfToken, serializeCsrfCookie } from "./csrf.ts";
import type { HttpResult, RawConsentRequest } from "./consent-flow.handler.ts";

export interface CaseConfirmationPorts {
  /** SEC-CNS-016: el caso se lee por `revocation.uow.inTenant` (nunca un repo suelto fuera de una tx). */
  readonly revocation: RevocationPorts;
  readonly staffIdentity: StaffIdentityPort;
}

/** contracts/openapi API-CNS-138 responses: 403/409/4XX -> RightsProblem (allOf Problem +
 * required: [rightsPathsAvailable]); 200 IN_REVIEW de /rights-case/resume usa el mismo trío
 * (rights-case-resume.handler.ts RIGHTS_PATHS_AVAILABLE). "Nunca «denegado»": toda respuesta
 * de error de una ruta RIGHTS ofrece las tres vías. */
const RIGHTS_PATHS_AVAILABLE = ["OTP", "RECOVERY_LINK", "HUMAN_CASE"] as const;

/** DomainErrorCode (ERR-XX-NN interno) -> ErrorCode externo (contracts/schemas/common.schema.json
 * $defs/ErrorCode): el código interno NUNCA sale tal cual en un Problem (mismo criterio que
 * EXTERNAL_ERROR_CODE de consent-flow.handler.ts). Falta de mapeo es un bug de este archivo,
 * nunca un code inventado: lanza en vez de filtrar un ERR-XX-NN crudo al cliente. */
const EXTERNAL_ERROR_CODE: Readonly<Record<string, string>> = {
  "ERR-CM-06": "INVALID_TRANSITION",
  "ERR-CM-10": "ACTOR_NOT_ALLOWED",
  "ERR-RV-18": "RH3_FOUR_EYES_REQUIRED",
  "ERR-RV-20": "RH3_NOT_BOUND_TO_RH2",
  "ERR-RC-10": "ROSTER_INSUFFICIENT",
  "ERR-RV-07": "RH2_SEPARATION_OF_DUTIES_VIOLATION",
};

function uniformNotFound(): HttpResult {
  return { status: 404, body: { status: 404 } };
}

function csrfRejected(): HttpResult {
  return { status: 403, body: { code: "CSRF_REJECTED", status: 403, correlationId: randomUUID(), rightsPathsAvailable: RIGHTS_PATHS_AVAILABLE } };
}

/** ERR-CM-10 (ACTOR_NOT_ALLOWED): expuesto de forma distinguible solo en consolas STAFF/
 * PLATFORM/CASE (contracts/openapi, "ACTOR_NOT_ALLOWED solo se expone en las consolas STAFF,
 * PLATFORM y CASE"), nunca en rutas del portador. */
function actorNotAllowed(): HttpResult {
  return problem(403, "ERR-CM-10");
}

function problem(status: 403 | 409 | 422, domainErrorCode: string): HttpResult {
  const code = EXTERNAL_ERROR_CODE[domainErrorCode];
  if (!code) {
    throw new Error(`case-confirmation.handler: sin mapeo externo para ${domainErrorCode} (EXTERNAL_ERROR_CODE)`);
  }
  return { status, body: { code, status, correlationId: randomUUID(), rightsPathsAvailable: RIGHTS_PATHS_AVAILABLE } };
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

/**
 * X6 (DEC-BR-014 rev. 8 §3; rights-case.spec INV-RC-04): toda lectura del caso por el operador queda en
 * ops.access_log (append-only, sin PII: solo refs opacas, rol y accion), NO en el ledger. El registro y la
 * lectura van en la MISMA tx del tenant y fail-closed: si el log falla, la lectura no se entrega.
 */
function readCaseAsOperator(ports: CaseConfirmationPorts, session: CaseSessionPayload) {
  return ports.revocation.uow.inTenant(session.tenantId, async (tx) => {
    await tx.accessLog.record({
      tenantId: session.tenantId,
      actorRef: session.principalRef,
      actorRole: session.role,
      action: "RIGHTS_CASE_READ",
      resourceType: "RIGHTS_CASE",
      resourceRef: session.caseRef,
    });
    return tx.rightsCaseRepo.findByRef(session.tenantId, session.caseRef);
  });
}

// ---------------------------------------------------------------------------
// POST /platform/rights-cases/{caseRef}/confirmation (API-CNS-138, RH3 paso 1). caseRef llega
// del path; GRD-CM-01 exige que coincida con el de la sesión CASE, o 404 uniforme.
// ---------------------------------------------------------------------------
export async function handleRecordCaseConfirmation(
  request: RawConsentRequest,
  caseRefFromPath: string,
  ports: CaseConfirmationPorts,
  config: RightsCaseHttpConfig,
  caseSessionKey: Buffer,
): Promise<HttpResult> {
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

  // RecordCaseConfirmationRequest (api-payloads.schema.json): additionalProperties: false,
  // única propiedad permitida confirmationGivenOnCasePage (const true). recordedByRef NUNCA es
  // un campo aceptado (se deriva de la sesión, GRD-CM-07); un cliente que lo envíe (p. ej. para
  // intentar suplantar al firmante) viola el schema y se rechaza aquí, no se ignora en
  // silencio (mismo criterio que confirmTotalWithdrawal en revocation-flow.handler.ts para el
  // caso base de "falta el campo").
  const body = request.body as Record<string, unknown> | undefined;
  const bodyKeys = body && typeof body === "object" ? Object.keys(body) : [];
  const hasOnlyAllowedKeys = bodyKeys.every((key) => key === "confirmationGivenOnCasePage");
  if (!hasOnlyAllowedKeys || body?.confirmationGivenOnCasePage !== true) {
    return problem(422, "ERR-CM-06");
  }

  const rightsCase = await readCaseAsOperator(ports, session);
  if (!rightsCase || rightsCase.tenantId !== session.tenantId || !rightsCase.revocationRef) {
    return uniformNotFound();
  }

  try {
    const recorded = await recordCaseConfirmationPendingCosign(ports.revocation, ports.staffIdentity, session.tenantId, rightsCase.revocationRef, session.caseRef, {
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
// POST /platform/rights-cases/{caseRef}/confirmation/cosign (API-CNS-139, RH3 paso 2). Mismo
// patrón que el paso 1; cosignedByRef SIEMPRE de la sesión CASE (GRD-CM-07), nunca del body.
// ---------------------------------------------------------------------------
export async function handleCosignCaseConfirmation(
  request: RawConsentRequest,
  caseRefFromPath: string,
  ports: CaseConfirmationPorts,
  config: RightsCaseHttpConfig,
  caseSessionKey: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCaseCsrf(request, config);
  if (csrfFailure) return csrfFailure;

  const cookies = parseCookies(request.cookieHeader);
  const session = decodeCaseSession(caseSessionKey, cookies[config.caseSessionCookieName]);
  if (!session) return uniformNotFound();
  if (session.caseRef !== caseRefFromPath) return uniformNotFound();

  if (session.role !== "RIGHTS_OPERATOR") {
    // LEGAL DECISION LD-03: revocation.spec RH3 / API-CNS-139 exigen "segundo RIGHTS_OPERATOR
    // distinto" como piso técnico interino (R13-4, R14-B); un APPROVER no co-firma. La regla
    // definitiva de quién tiene autoridad legal para co-firmar es human gate de Carlos, no de
    // este código.
    return actorNotAllowed();
  }

  // CosignCaseConfirmationRequest: additionalProperties: false, sin propiedades. Cualquier campo
  // (p. ej. cosignedByRef para suplantar al co-firmante) se rechaza, no se ignora.
  const body = request.body;
  const isEmptyObject = body === undefined || (typeof body === "object" && body !== null && !Array.isArray(body) && Object.keys(body).length === 0);
  if (!isEmptyObject) {
    return problem(422, "ERR-CM-06");
  }

  const rightsCase = await readCaseAsOperator(ports, session);
  if (!rightsCase || rightsCase.tenantId !== session.tenantId || !rightsCase.revocationRef) {
    return uniformNotFound();
  }

  try {
    const cosigned = await cosignCaseConfirmation(ports.revocation, ports.staffIdentity, session.tenantId, rightsCase.revocationRef, session.caseRef, {
      cosignedByPrincipalRef: session.principalRef,
    });
    // CaseConfirmationAck.revocationState admite APPLIED (Carlos 2026-09-28, opción (a)): R4 síncrono
    // en IT0. Si R4 falla, el error se propaga (catch de abajo) y la Revocation queda CONFIRMED.
    return { status: 200, body: { cosign: "COSIGNED", revocationState: cosigned.status === "APPLIED" ? "APPLIED" : "CONFIRMED" } };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      return problem(409, err.code);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// RH2 con doble control (GRD-RV-09). POST /platform/rights-cases/{caseRef}/verification-proposals (API-CNS-136,
// propose_case_verification, RIGHTS_OPERATOR con sesión CASE) y
// POST /platform/rights-cases/{caseRef}/verification-proposals/{proposalRef}/approval (API-CNS-137,
// approve_case_verification, PRIVACY_LEGAL/SECURITY; en IT0 el roster los modela como APPROVER, OPEN-TC-06).
// Actor SIEMPRE de la sesión (GRD-CM-07/GRD-RV-09: nunca de parámetros). Rol que no corresponde -> 403 ACTOR_NOT_ALLOWED.
// Step-up/aserción del IdP (GRD-RC-12, P-36): APR-IDP PENDING (Carlos / studio). Interino IT0 LOCAL-only (opción (ii),
// Carlos 2026-09-28): se exige `stepUpAssertion` con la forma del contrato (string 1..8192, nunca persistido ni logueado)
// y su presencia cuenta como ATTESTED; sin IdP real NO hay verificación criptográfica de la aserción. FINDING P1 hasta APR-IDP.
// ---------------------------------------------------------------------------
const SCRIPT_VERSION_PATTERN = /^[A-Za-z0-9._-]{1,32}$/;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function isStepUpAssertion(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 8192;
}

function strictBody(body: unknown, allowed: readonly string[]): Record<string, unknown> | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const record = body as Record<string, unknown>;
  return Object.keys(record).every((k) => allowed.includes(k)) ? record : null;
}

export async function handleProposeCaseVerification(
  request: RawConsentRequest,
  caseRefFromPath: string,
  ports: CaseConfirmationPorts,
  config: RightsCaseHttpConfig,
  caseSessionKey: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCaseCsrf(request, config);
  if (csrfFailure) return csrfFailure;
  const cookies = parseCookies(request.cookieHeader);
  const session = decodeCaseSession(caseSessionKey, cookies[config.caseSessionCookieName]);
  if (!session || session.caseRef !== caseRefFromPath) return uniformNotFound();
  if (session.role !== "RIGHTS_OPERATOR") return actorNotAllowed(); // GRD-RV-09: propone el RIGHTS_OPERATOR

  const body = strictBody(request.body, ["verificationScriptVersion", "stepUpAssertion"]);
  if (!body || typeof body.verificationScriptVersion !== "string" || !SCRIPT_VERSION_PATTERN.test(body.verificationScriptVersion) || !isStepUpAssertion(body.stepUpAssertion)) {
    return problem(422, "ERR-CM-06");
  }
  const rightsCase = await readCaseAsOperator(ports, session);
  if (!rightsCase || rightsCase.tenantId !== session.tenantId || !rightsCase.revocationRef) return uniformNotFound();
  try {
    const proposalRef = randomUUID();
    const record = await proposeCaseVerification(ports.revocation, ports.staffIdentity, session.tenantId, rightsCase.revocationRef, session.caseRef, { principalRef: session.principalRef }, {
      proposalRef,
      verificationScriptVersion: body.verificationScriptVersion,
    });
    // ProposalAck: la propuesta no tiene efecto sobre la Revocation hasta la aprobación; PENDING hasta que el aprobador atesta.
    return { status: 201, body: { proposalRef: record.proposal?.proposalRef ?? proposalRef, attestation: "PENDING" } };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      return problem(err.code === "ERR-RV-07" ? 403 : 409, err.code);
    }
    throw err;
  }
}

export async function handleApproveCaseVerification(
  request: RawConsentRequest,
  caseRefFromPath: string,
  proposalRefFromPath: string,
  ports: CaseConfirmationPorts,
  config: RightsCaseHttpConfig,
  caseSessionKey: Buffer,
  environment: Environment = "DEV",
): Promise<HttpResult> {
  const csrfFailure = checkCaseCsrf(request, config);
  if (csrfFailure) return csrfFailure;
  const cookies = parseCookies(request.cookieHeader);
  const session = decodeCaseSession(caseSessionKey, cookies[config.caseSessionCookieName]);
  if (!session || session.caseRef !== caseRefFromPath) return uniformNotFound();
  if (!UUID_V4_PATTERN.test(proposalRefFromPath)) return uniformNotFound();
  if (session.role !== "APPROVER") return actorNotAllowed(); // GRD-RV-09: aprueba PRIVACY_LEGAL/SECURITY (APPROVER en IT0)

  const body = strictBody(request.body, ["stepUpAssertion"]);
  if (!body || !isStepUpAssertion(body.stepUpAssertion)) return problem(422, "ERR-CM-06");
  const rightsCase = await readCaseAsOperator(ports, session);
  if (!rightsCase || rightsCase.tenantId !== session.tenantId || !rightsCase.revocationRef) return uniformNotFound();
  try {
    const result = await approveCaseVerification(
      ports.revocation, ports.staffIdentity, session.tenantId, rightsCase.revocationRef, session.caseRef, proposalRefFromPath,
      { principalRef: session.principalRef },
      environment === "LOCAL", // X6 P2-1: ATTESTED solo en LOCAL (stub, APR-IDP PENDING); fuera de LOCAL queda PENDING, nunca atestado
    );
    return { status: 200, body: { attestation: result.attestation, revocationState: result.record.status === "VERIFIED" ? "VERIFIED" : "REQUESTED" } };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      return problem(err.code === "ERR-RV-07" ? 403 : 409, err.code);
    }
    throw err;
  }
}

/**
 * POST /platform/rights-cases/{caseRef}/verification-proposals/{proposalRef}/withdrawal (API-CNS-140,
 * withdraw_case_verification_proposal; CA-128 X6 P2). Solo el RIGHTS_OPERATOR proponente, desde su sesion CASE, mientras la
 * propuesta esta PENDING. Cuerpo vacio (WithdrawCaseVerificationProposalRequest). Principal SIEMPRE de la sesion (GRD-CM-07).
 * Lectura del caso por el operador queda en ops.access_log (misma tx, INV-RC-04), igual que API-CNS-136/137.
 */
export async function handleWithdrawCaseVerificationProposal(
  request: RawConsentRequest,
  caseRefFromPath: string,
  proposalRefFromPath: string,
  ports: CaseConfirmationPorts,
  config: RightsCaseHttpConfig,
  caseSessionKey: Buffer,
): Promise<HttpResult> {
  const csrfFailure = checkCaseCsrf(request, config);
  if (csrfFailure) return csrfFailure;
  const cookies = parseCookies(request.cookieHeader);
  const session = decodeCaseSession(caseSessionKey, cookies[config.caseSessionCookieName]);
  if (!session || session.caseRef !== caseRefFromPath) return uniformNotFound();
  if (!UUID_V4_PATTERN.test(proposalRefFromPath)) return uniformNotFound();
  if (session.role !== "RIGHTS_OPERATOR") return actorNotAllowed(); // solo el proponente (RIGHTS_OPERATOR) retira

  const body = request.body;
  const isEmptyObject = body === undefined || (typeof body === "object" && body !== null && !Array.isArray(body) && Object.keys(body).length === 0);
  if (!isEmptyObject) return problem(422, "ERR-CM-06");

  const rightsCase = await readCaseAsOperator(ports, session);
  if (!rightsCase || rightsCase.tenantId !== session.tenantId || !rightsCase.revocationRef) return uniformNotFound();
  try {
    const record = await withdrawCaseVerificationProposal(
      ports.revocation, ports.staffIdentity, session.tenantId, rightsCase.revocationRef, session.caseRef, proposalRefFromPath,
      { principalRef: session.principalRef },
    );
    // ProposalWithdrawalAck.revocationState es la constante REQUESTED (schema): cualquier otro estado falla cerrado, sin reflejarlo.
    if (record.status !== "REQUESTED") return problem(409, "ERR-CM-06");
    return { status: 200, body: { proposalState: "WITHDRAWN", revocationState: "REQUESTED" } };
  } catch (err) {
    if (err instanceof DomainError) {
      if (err.code === "ERR-CM-01") return uniformNotFound();
      return problem(err.code === "ERR-RV-07" ? 403 : 409, err.code);
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
  /** SEC-CNS-016: lectura del caso bajo el tenant (inTenant). */
  readonly uow: UnitOfWorkPort;
}

export async function handleDevStaffLogin(
  request: RawConsentRequest,
  environment: Environment,
  ports: DevStaffLoginPorts,
  config: RightsCaseHttpConfig,
  caseSessionKey: Buffer,
): Promise<HttpResult> {
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

  const principal = await ports.staffIdentity.findByPrincipalRef(principalRef);
  if (!principal) {
    return { status: 422, body: { status: 422 } };
  }

  const rightsCase = await ports.uow.inTenant(tenantId, (tx) => tx.rightsCaseRepo.findByRef(tenantId, caseRef));
  if (!rightsCase || rightsCase.caseRef !== caseRef) {
    return { status: 422, body: { status: 422 } };
  }

  if (principal.role === "TENANT_ADMIN") {
    // CA-125: TENANT_ADMIN pertenece a la consola STAFF (staff-console.handler.ts), nunca a la CASE.
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
