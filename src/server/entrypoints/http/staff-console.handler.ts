// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-105 (POST /staff/enrollments),
// API-CNS-110 (POST /staff/invitations), API-CNS-111 (/ready), API-CNS-112 (/send), security
// staffSession; api-payloads.schema.json OpenEnrollmentRequest/EnrollmentOpened/
// CreateInvitationRequest/InvitationCreated/MarkInvitationReadyRequest/InvitationReady/
// EmptyCommand/InvitationSent; tenant-context.spec.yaml EN0; invitation.spec.yaml I1/I2/I3;
// common.spec.yaml GRD-CM-01/02/07/08/10. CA-125.
//
// Autenticación (decisión de Carlos, 2026-09-28, opción (ii): LOCAL + CI, SYNTHETIC DATA ONLY,
// APR-IDP PENDING): la sesión STAFF (cookie `__Host-cns-staff`, staff-session.ts) la emite solo
// /__dev/staff-login (LOCAL-only, GRD-CM-13). Cada request re-valida la membership contra
// StaffIdentityPort (GRD-CM-01: el tenant sale del roster atestado en servidor, nunca del body,
// header ni query). El actor (actorType HUMAN, actorRole INVITER) lo fija el contrato y se deriva
// de la sesión; ningún campo del body puede declararlo (additionalProperties: false -> 422).
// LEGAL DECISION LD-03 (quién opera RC0 y con qué base) y APR-IDP NO se resuelven aquí.
//
// Orden de evaluación: GRD-CM-10 (CSRF/Origin) -> GRD-CM-01 (sesión + membership: 404 uniforme) ->
// GRD-CM-07 (rol TENANT_ADMIN: 403 ACTOR_NOT_ALLOWED, solo distinguible en consola STAFF) ->
// validación del body (422) -> GRD-CM-08 (idempotencia) -> transición.

import { createHash, randomUUID } from "node:crypto";

import { DomainError } from "../../modules/common/errors.ts";
import { assertCsrfAndOrigin } from "../../modules/common/guards.ts";
import type { Environment } from "../../modules/common/types.ts";
import { enrollmentPortsInTx, openEnrollmentTx, type EnrollmentPorts } from "../../modules/tenant-context/enrollment.ts";
import {
  staffCreateInvitationTx,
  staffIssuanceInTx,
  staffMarkInvitationReadyTx,
  staffSendInvitationTx,
  type StaffIssuancePorts,
} from "../../modules/invitation/staff-issuance.ts";
import { InvalidRecipientChannelRefError } from "../../ports/invitation-repository.port.ts";
import type { TenantTxPorts, UnitOfWorkPort } from "../../ports/unit-of-work.port.ts";
import type { StaffIdentityPort } from "../../ports/staff-identity.port.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";
import { generateCsrfToken, serializeCsrfCookie } from "./csrf.ts";
import { decodeStaffSession, encodeStaffSession, serializeStaffSessionCookie, type StaffSessionPayload } from "./staff-session.ts";
import type { HttpResult, RawConsentRequest } from "./consent-flow.handler.ts";

export interface StaffConsolePorts {
  readonly issuance: StaffIssuancePorts;
  readonly enrollment: EnrollmentPorts;
  /** CA-124 PR-E: TODA lectura/escritura de repos, catálogo e idempotencia de la consola corre dentro de
   * `uow.inTenant` (find + ejecutar + store de la Idempotency-Key en la MISMA tx; GRD-CM-08). */
  readonly uow: UnitOfWorkPort;
  readonly staffIdentity: StaffIdentityPort;
}

/** Resultado de un paso de la consola dentro de la tx: la respuesta y, opcionalmente, un efecto externo
 * (entrega del enlace) que se ejecuta SOLO tras el COMMIT y solo en la ejecución real (no en un replay). */
interface StepOutcome {
  readonly result: HttpResult;
  readonly afterCommit?: () => Promise<void>;
}

/** Patrones de contracts/schemas/common.schema.json (Ref, ContextRef, Version, IdempotencyKey). */
const REF_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONTEXT_REF_PATTERN = /^[A-Z][A-Z0-9_]{1,63}$/;
const VERSION_PATTERN = /^[A-Za-z0-9._-]{1,32}$/;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._~-]{16,128}$/;

/** DomainErrorCode -> ErrorCode externo (common.schema.json ErrorCode.x-error-ids). Un código
 * interno sin mapeo es un bug de este archivo: lanza en vez de filtrar un ERR-XX-NN crudo. */
const EXTERNAL_ERROR_CODE: Readonly<Record<string, string>> = {
  "ERR-CM-03": "INVITER_NOT_PARTICIPATING",
  "ERR-CM-04": "ENROLLMENT_NOT_ACTIVE",
  "ERR-CM-05": "CONTEXT_NOT_ACTIVE",
  "ERR-CM-06": "INVALID_TRANSITION",
  "ERR-CM-07": "IDEMPOTENCY_CONFLICT",
  "ERR-CM-10": "ACTOR_NOT_ALLOWED",
  "ERR-CM-12": "GUARD_EVALUATOR_UNAVAILABLE",
  "ERR-TC-03": "ENROLLMENT_ALREADY_ACTIVE",
  "ERR-IV-02": "INVITATION_ALREADY_ACTIVE",
  "ERR-IV-03": "INVITATION_NOT_READY",
  "ERR-IV-04": "VERSION_OR_MODE_GUARD_FAILED",
  "ERR-IV-07": "REISSUE_LIMIT_REACHED",
};

function uniformNotFound(): HttpResult {
  return { status: 404, body: { status: 404 } };
}

function problem(status: 403 | 409 | 422, domainErrorCode: string): HttpResult {
  const code = EXTERNAL_ERROR_CODE[domainErrorCode];
  if (!code) throw new Error(`staff-console.handler: sin mapeo externo para ${domainErrorCode} (EXTERNAL_ERROR_CODE)`);
  return { status, body: { code, status, correlationId: randomUUID() } };
}

/** 422 por cuerpo/cabecera fuera del schema. common.schema.json ErrorCode no tiene un código
 * propio (FINDING P2 de CA-125); se usa INVALID_TRANSITION, igual que case-confirmation.handler. */
function invalidRequest(): HttpResult {
  return problem(422, "ERR-CM-06");
}

function csrfRejected(): HttpResult {
  return { status: 403, body: { code: "CSRF_REJECTED", status: 403, correlationId: randomUUID() } };
}

/** DomainError -> HttpResult de la consola STAFF (403/404/409/422 del contrato). */
function domainFailure(err: unknown): HttpResult {
  // La persistencia no admite ese recipientChannelRef (EXT-B/LD-21 pendiente): 422 uniforme, no 500.
  if (err instanceof InvalidRecipientChannelRefError) return invalidRequest();
  if (err instanceof DomainError) {
    if (err.code === "ERR-CM-01" || err.code === "ERR-CM-02") return uniformNotFound();
    if (err.code === "ERR-CM-10") return problem(403, err.code);
    if (err.code === "ERR-CM-07") return problem(422, err.code);
    return problem(409, err.code);
  }
  throw err;
}

interface AuthenticatedStaff {
  readonly tenantId: string;
  readonly principalRef: string;
}

/** GRD-CM-10 + GRD-CM-01 + GRD-CM-07 para todas las rutas /staff/*. */
async function authenticate(
  request: RawConsentRequest,
  ports: StaffConsolePorts,
  config: RightsCaseHttpConfig,
  staffSessionKey: Buffer,
): Promise<{ readonly ok: true; readonly staff: AuthenticatedStaff } | { readonly ok: false; readonly result: HttpResult }> {
  const cookies = parseCookies(request.cookieHeader);
  try {
    assertCsrfAndOrigin({
      originHeader: request.originHeader,
      allowedOrigin: config.allowedOrigin,
      csrfHeaderToken: request.csrfHeaderToken,
      csrfCookieToken: cookies[config.staffCsrfCookieName],
    });
  } catch (err) {
    if (err instanceof DomainError && err.code === "ERR-CM-09") return { ok: false, result: csrfRejected() };
    throw err;
  }

  const session = decodeStaffSession(staffSessionKey, cookies[config.staffSessionCookieName]);
  if (!session) return { ok: false, result: uniformNotFound() }; // GRD-CM-01
  // Membership vigente: el principal debe seguir en el roster atestado con el mismo rol y el
  // mismo tenant que la sesión. Cualquier discrepancia = sin sesión (404 uniforme).
  const principal = await ports.staffIdentity.findByPrincipalRef(session.principalRef);
  if (!principal || principal.role !== session.role || principal.tenantId === undefined || principal.tenantId !== session.tenantId) {
    return { ok: false, result: uniformNotFound() };
  }
  if (session.role !== "TENANT_ADMIN") {
    // GRD-CM-07: solo TENANT_ADMIN (actorRole INVITER) opera EN0/I1-I3. ACTOR_NOT_ALLOWED solo se
    // expone en las consolas STAFF/PLATFORM/CASE.
    return { ok: false, result: problem(403, "ERR-CM-10") };
  }
  return { ok: true, staff: { tenantId: session.tenantId, principalRef: session.principalRef } };
}

/** Objeto plano con EXACTAMENTE las claves permitidas (additionalProperties: false); si no, null. */
function strictObject(body: unknown, allowed: readonly string[]): Record<string, unknown> | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const record = body as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) return null;
  }
  return record;
}

function isString(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * GRD-CM-08: Idempotency-Key ligada a (tenantRef, principal, operación), almacenada solo como
 * hash. Misma key + mismo payloadHash -> misma respuesta almacenada; misma key + otro payloadHash
 * -> ERR-CM-07 (422). Solo se almacenan respuestas 2xx (un fallo no se congela).
 * CA-124 PR-E: find + ejecutar + store corren en UNA unidad de trabajo del tenant (atómico): si el paso
 * falla (DomainError) nada queda escrito, ni la transición ni la clave; el efecto externo (`afterCommit`)
 * va después del COMMIT. Los DomainError se traducen a HTTP fuera de la tx (tras el ROLLBACK).
 */
async function withIdempotency(
  ports: StaffConsolePorts,
  request: RawConsentRequest,
  staff: AuthenticatedStaff,
  operation: string,
  payload: unknown,
  required: boolean,
  execute: (tx: TenantTxPorts) => Promise<StepOutcome>,
): Promise<HttpResult> {
  const key = request.idempotencyKeyHeader;
  if (key === undefined && required) return invalidRequest();
  if (key !== undefined && !IDEMPOTENCY_KEY_PATTERN.test(key)) return invalidRequest();

  const scopeKeyHash = key === undefined ? undefined : sha256(`${staff.tenantId}\u0000${staff.principalRef}\u0000${operation}\u0000${key}`);
  const payloadHash = sha256(JSON.stringify(payload));
  let afterCommit: (() => Promise<void>) | undefined;
  let result: HttpResult;
  try {
    result = await ports.uow.inTenant(staff.tenantId, async (tx) => {
      afterCommit = undefined; // la tx puede reejecutarse: solo vale el efecto del último intento
      if (scopeKeyHash !== undefined) {
        const stored = await tx.idempotency.find(staff.tenantId, scopeKeyHash);
        if (stored) {
          if (stored.payloadHash !== payloadHash) return problem(422, "ERR-CM-07");
          return { status: stored.status as HttpResult["status"], body: stored.body };
        }
      }
      const outcome = await execute(tx);
      if (scopeKeyHash !== undefined && outcome.result.status >= 200 && outcome.result.status < 300) {
        await tx.idempotency.store(staff.tenantId, scopeKeyHash, { payloadHash, status: outcome.result.status, body: outcome.result.body });
      }
      afterCommit = outcome.afterCommit;
      return outcome.result;
    });
  } catch (err) {
    return domainFailure(err);
  }
  if (afterCommit !== undefined) await afterCommit();
  return result;
}

// ---------------------------------------------------------------------------
// POST /staff/enrollments (API-CNS-105, EN0). OpenEnrollmentRequest: {subjectRef, participationRef}.
// ---------------------------------------------------------------------------
export async function handleOpenEnrollment(
  request: RawConsentRequest,
  ports: StaffConsolePorts,
  config: RightsCaseHttpConfig,
  staffSessionKey: Buffer,
): Promise<HttpResult> {
  const auth = await authenticate(request, ports, config, staffSessionKey);
  if (!auth.ok) return auth.result;

  const body = strictObject(request.body, ["subjectRef", "participationRef"]);
  if (!body || !isString(body.subjectRef, REF_PATTERN) || !isString(body.participationRef, REF_PATTERN)) {
    return invalidRequest();
  }
  const subjectRef = body.subjectRef;
  const participationRef = body.participationRef;

  return withIdempotency(ports, request, auth.staff, "EN0", { subjectRef, participationRef }, false, async (tx) => {
    const { record, sequence } = await openEnrollmentTx(enrollmentPortsInTx(ports.enrollment, tx), auth.staff.tenantId, "INVITER", { subjectRef, participationRef });
    return { result: { status: 201, body: { enrollmentRef: record.enrollmentRef, state: "ACTIVE", sequence } } };
  });
}

// ---------------------------------------------------------------------------
// POST /staff/invitations (API-CNS-110, I1). Idempotency-Key obligatoria (clientRequestId).
// CreateInvitationRequest: sin tenantRef ni organizationRef (additionalProperties: false).
// ---------------------------------------------------------------------------
export async function handleCreateInvitation(
  request: RawConsentRequest,
  ports: StaffConsolePorts,
  config: RightsCaseHttpConfig,
  staffSessionKey: Buffer,
): Promise<HttpResult> {
  const auth = await authenticate(request, ports, config, staffSessionKey);
  if (!auth.ok) return auth.result;

  const body = strictObject(request.body, ["subjectRef", "enrollmentRef", "participationRef", "contextRef", "reissueOfRef"]);
  if (
    !body ||
    !isString(body.subjectRef, REF_PATTERN) ||
    !isString(body.enrollmentRef, REF_PATTERN) ||
    !isString(body.participationRef, REF_PATTERN) ||
    !isString(body.contextRef, CONTEXT_REF_PATTERN) ||
    (body.reissueOfRef !== undefined && !isString(body.reissueOfRef, REF_PATTERN))
  ) {
    return invalidRequest();
  }
  const input = {
    subjectRef: body.subjectRef,
    enrollmentRef: body.enrollmentRef,
    participationRef: body.participationRef,
    contextRef: body.contextRef,
    ...(body.reissueOfRef !== undefined ? { reissueOfRef: body.reissueOfRef as string } : {}),
  };

  return withIdempotency(ports, request, auth.staff, "I1", input, true, async (tx) => {
    const { record, sequence } = await staffCreateInvitationTx(staffIssuanceInTx(ports.issuance, tx), auth.staff.tenantId, "INVITER", input);
    return { result: { status: 201, body: { invitationRef: record.invitationRef, state: "DRAFT", sequence } } };
  });
}

// ---------------------------------------------------------------------------
// POST /staff/invitations/{invitationRef}/ready (API-CNS-111, I2). MarkInvitationReadyRequest:
// {consentVersion, recipientBinding, recipientChannelRef?}; expiresAt NUNCA del cliente (P-10).
// ---------------------------------------------------------------------------
export async function handleMarkInvitationReady(
  request: RawConsentRequest,
  invitationRef: string,
  ports: StaffConsolePorts,
  config: RightsCaseHttpConfig,
  staffSessionKey: Buffer,
): Promise<HttpResult> {
  const auth = await authenticate(request, ports, config, staffSessionKey);
  if (!auth.ok) return auth.result;
  if (!REF_PATTERN.test(invitationRef)) return uniformNotFound();

  const body = strictObject(request.body, ["consentVersion", "recipientBinding", "recipientChannelRef"]);
  if (!body || !isString(body.consentVersion, VERSION_PATTERN)) return invalidRequest();
  if (body.recipientBinding !== "RECIPIENT_CHANNEL" && body.recipientBinding !== "UNBOUND") return invalidRequest();
  const recipientBinding: "RECIPIENT_CHANNEL" | "UNBOUND" = body.recipientBinding;
  // recipientChannelRef si y solo si RECIPIENT_CHANNEL (GRD-IV-03; if/then/else del schema).
  if (recipientBinding === "RECIPIENT_CHANNEL" && !isString(body.recipientChannelRef, REF_PATTERN)) return invalidRequest();
  if (recipientBinding === "UNBOUND" && body.recipientChannelRef !== undefined) return invalidRequest();
  const input = {
    consentVersion: body.consentVersion,
    recipientBinding,
    ...(body.recipientChannelRef !== undefined ? { recipientChannelRef: body.recipientChannelRef as string } : {}),
  };

  return withIdempotency(ports, request, auth.staff, `I2:${invitationRef}`, input, false, async (tx) => {
    const { record, sequence } = await staffMarkInvitationReadyTx(staffIssuanceInTx(ports.issuance, tx), auth.staff.tenantId, "INVITER", invitationRef, input);
    return {
      result: {
        status: 200,
        body: { state: "READY", sequence, ...(record.expiresAt ? { expiresAt: record.expiresAt.toISOString() } : {}) },
      },
    };
  });
}

// ---------------------------------------------------------------------------
// POST /staff/invitations/{invitationRef}/send (API-CNS-112, I3). EmptyCommand. El token NUNCA
// vuelve en la respuesta: solo va al puerto de canal (sink IT0, sin SMTP).
// ---------------------------------------------------------------------------
export async function handleSendInvitation(
  request: RawConsentRequest,
  invitationRef: string,
  ports: StaffConsolePorts,
  config: RightsCaseHttpConfig,
  staffSessionKey: Buffer,
): Promise<HttpResult> {
  const auth = await authenticate(request, ports, config, staffSessionKey);
  if (!auth.ok) return auth.result;
  if (!REF_PATTERN.test(invitationRef)) return uniformNotFound();

  if (!strictObject(request.body, [])) return invalidRequest();

  return withIdempotency(ports, request, auth.staff, `I3:${invitationRef}`, {}, false, async (tx) => {
    const { record, sequence, deliver } = await staffSendInvitationTx(staffIssuanceInTx(ports.issuance, tx), auth.staff.tenantId, "INVITER", invitationRef);
    return {
      result: {
        status: 200,
        // expiresAt es obligatorio en InvitationSent; sendInvitation siempre lo fija (GRD-IV-12).
        body: { state: "SENT", sequence, expiresAt: (record.expiresAt as Date).toISOString() },
      },
      afterCommit: deliver, // el enlace sale por el canal DESPUÉS del COMMIT (nunca en un replay)
    };
  });
}

// ---------------------------------------------------------------------------
// POST /__dev/staff-login para TENANT_ADMIN (LOCAL-only, GRD-CM-13; no es parte del contrato
// OpenAPI, misma clase de herramienta de depuración que /__dev/otp-sink). Emite la sesión STAFF
// (cookie __Host-cns-staff, P-26 provisional) y su cookie CSRF a partir de un principal TENANT_ADMIN
// que ya existe en el StaffIdentityPort inyectado. El tenant sale del roster, NUNCA del body:
// un body con `tenantId` (o cualquier otra clave) se rechaza. No decide LD-03 ni APR-IDP.
// ---------------------------------------------------------------------------
export async function handleDevStaffConsoleLogin(
  request: RawConsentRequest,
  environment: Environment,
  staffIdentity: StaffIdentityPort,
  config: RightsCaseHttpConfig,
  staffSessionKey: Buffer,
): Promise<HttpResult> {
  if (environment !== "LOCAL") return uniformNotFound(); // fail-closed (GRD-CM-13): la ruta no existe fuera de LOCAL

  const body = strictObject(request.body, ["principalRef"]);
  if (!body || typeof body.principalRef !== "string") return { status: 422, body: { status: 422 } };
  const principal = await staffIdentity.findByPrincipalRef(body.principalRef);
  if (!principal || principal.role !== "TENANT_ADMIN" || principal.tenantId === undefined) {
    return { status: 422, body: { status: 422 } };
  }

  const session: StaffSessionPayload = { tenantId: principal.tenantId, principalRef: principal.principalRef, role: principal.role };
  return {
    status: 200,
    body: { principalRef: principal.principalRef, role: principal.role },
    setStaffSessionCookie: serializeStaffSessionCookie(config.staffSessionCookieName, encodeStaffSession(staffSessionKey, session)),
    setStaffCsrfCookie: serializeCsrfCookie(config.staffCsrfCookieName, generateCsrfToken()),
  };
}
