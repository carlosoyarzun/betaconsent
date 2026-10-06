// Gobierna: REQ-CNS-036 / UX-CNS-005 (aprobados por Carlos, 2026-10-02), DEC-BR-019 (Notion), diseno Figma 90:2,
// API-CNS-116 (lista), API-CNS-105/110/111/112 (cadena EN0 -> I1 -> I2 -> I3), common.spec GRD-CM-01/02/07/08/10,
// SEC-CNS-018 rev. 2 (R3/R5), SEC-CNS-019. CA-125.
//
// Pantallas HTML del colegio (rutas bajo /staff/..., server-rendered, sin JS). No duplica dominio ni consulta:
//  - La lista llama a evaluateStaffRoster("html", ...) (staff-roster.handler.ts): mismo gating, mismo orden, misma fila
//    unica de ops.access_log, misma proyeccion colapsada (en Postgres: la vista tras SET LOCAL ROLE staff_roster_reader).
//  - El envio encadena los handlers existentes handleOpenEnrollment -> handleCreateInvitation -> handleMarkInvitationReady
//    -> handleSendInvitation con la sesion STAFF y el CSRF double-submit del navegador: valida, autoriza, aplica CSRF/Origin,
//    idempotencia (GRD-CM-08) y toma el tenant de la sesion exactamente igual que la API. El formulario NO transporta tenant.
//  - Idempotency-Key DETERMINISTA por (tenant, principal, alumno, participacion, contexto, paso): doble clic o recarga
//    reproducen la respuesta guardada, sin segunda matricula ni segunda invitacion (AC-16).
//  - Fallo a mitad de la cadena: se detiene, sin compensar ni reintentar, con aviso (D2/D7, AC-18).
//
// Privacidad (P-1/P-2/D10): subjectRef/participationRef/email/cursor nunca en logs; las refs viajan por POST con campos
// ocultos y CSRF (nunca en la URL); PRG tras el envio; el correo solo aparece en el formulario (si se vuelve a editar) y en el
// resumen, y nunca se refleja en un error. Cookie flash de confirmacion: solo la etiqueta sintetica del alumno.
// APR-IDP PENDING: sin IdP. El unico acceso es el login dev (LOCAL, mismo handleDevStaffConsoleLogin, sin ampliar privilegios).
// LEGAL DECISION: no se redacta copy legal; se renderiza el marcador (staff-ui-pages.ts).

import { createHash, createHmac, hkdfSync, timingSafeEqual } from "node:crypto";


import { DomainError } from "../../modules/common/errors.ts";
import { assertCsrfAndOrigin } from "../../modules/common/guards.ts";
import { isReservedEmail } from "../../modules/common/synthetic-recipient.ts";
import { SUBJECT_LABEL_PATTERN } from "../../ports/subject-directory.port.ts";
import type { Environment } from "../../modules/common/types.ts";
import type { StaffInvitationStatus } from "../../ports/staff-roster.port.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";
import type { HttpResult } from "./consent-flow.handler.ts";
import { serializeCsrfCookie } from "./csrf.ts";
import { evaluateStaffRoster, secFetchAllowed } from "./staff-roster.handler.ts";
import { isSecurityEventWriteError, reportSecurityEventWriteFailure } from "./security-event-failure.ts";
import { decodeStaffSession, hashStaffSid, revokeStaffSessionCookie, staffCsrfMatchesSession, staffCsrfTokenFor } from "./staff-session.ts";
import {
  authenticateStaffSession,
  handleCreateInvitation,
  handleDevStaffConsoleLogin,
  handleMarkInvitationReady,
  handleOpenEnrollment,
  handleSendInvitation,
  type StaffConsolePorts,
} from "./staff-console.handler.ts";
import {
  renderStaffUiPage,
  STAFF_DEV_LOGIN_PATH,
  STAFF_ENTRY_PATH,
  STAFF_INVITE_PATH,
  STAFF_LIST_PATH,
  STAFF_LOGOUT_PATH,
  STAFF_REVIEW_PATH,
  STAFF_SEND_PATH,
  STAFF_SENT_PATH,
  type StaffUiErrorVariant,
  type StaffUiListItem,
  type StaffUiStudent,
  type StaffUiView,
} from "./staff-ui-pages.ts";

export interface StaffUiConfig {
  /** Contexto del estudio (I1). Lo fija el servidor, nunca el staff. */
  readonly contextRef: string;
  /** Version de consentimiento (I2). Lo fija el servidor/adapter (S2), nunca el staff. */
  readonly consentVersion: string;
}

export interface StaffUiDeps {
  readonly environment: string | undefined;
  readonly ui: StaffUiConfig;
  /** Solo LOCAL: principal TENANT_ADMIN sintetico del login dev. Sin el (o fuera de LOCAL) /staff/dev-login no existe. */
  readonly devLoginPrincipalRef: string | undefined;
  readonly staffConsole: StaffConsolePorts;
  readonly config: RightsCaseHttpConfig;
  readonly staffSessionKey: Buffer;
  readonly cursorKey: Buffer;
  readonly nowMs?: () => number;
}

export interface StaffUiRequest {
  readonly method: string;
  readonly path: string;
  /** Query sin "?". Solo la lista lo usa (cursor cifrado); nunca se registra. */
  readonly rawQuery: string;
  readonly originHeader: string | undefined;
  readonly cookieHeader: string | undefined;
  readonly secFetchSiteHeader: string | undefined;
  readonly secFetchModeHeader: string | undefined;
  readonly secFetchDestHeader: string | undefined;
  /** application/x-www-form-urlencoded ya leido (vacio en GET). */
  readonly formBody: string;
}

export interface StaffUiResponse {
  readonly status: number;
  /** Ausente en 303 y en 404 (el servidor responde su 404 JSON uniforme). */
  readonly html?: string;
  readonly setCookies?: readonly string[];
  readonly location?: string;
}

/** Cabeceras de TODA respuesta HTML de /staff/...: CSP estricta sin scripts ni estilos inline. */
export const STAFF_UI_RESPONSE_HEADERS: Readonly<Record<string, string>> = {
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Vary": "Cookie",
  "Content-Security-Policy":
    "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};

const FLASH_COOKIE_NAME = "__Host-cns-staff-flash";
const FLASH_TTL_MS = 120_000;
export const FLASH_HKDF_INFO = "CNS-STAFF-UI-FLASH-v1";

const REF_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
/** Forma minima nombre@dominio (sin espacios, comas ni separadores). El dominio reservado lo decide isReservedEmail (dominio). */
const EMAIL_FORMAT = /^[^\s@,;<>"']+@[^\s@,;<>"']+$/;
const MAX_EMAIL = 254;

const GET_ROUTES: ReadonlySet<string> = new Set([STAFF_ENTRY_PATH, STAFF_LIST_PATH, STAFF_SENT_PATH]);
const POST_ROUTES: ReadonlySet<string> = new Set([STAFF_INVITE_PATH, STAFF_REVIEW_PATH, STAFF_SEND_PATH, STAFF_LOGOUT_PATH, STAFF_DEV_LOGIN_PATH]);

/** ¿Es una ruta de las pantallas del colegio? Cualquier otra combinacion metodo/ruta sigue el ruteo existente (p. ej. los POST JSON /staff/...). */
export function isStaffUiRoute(method: string, path: string): boolean {
  return (method === "GET" && GET_ROUTES.has(path)) || (method === "POST" && POST_ROUTES.has(path));
}

const NOT_FOUND: StaffUiResponse = { status: 404 };

function page(status: number, view: StaffUiView, setCookies?: readonly string[]): StaffUiResponse {
  return { status, html: renderStaffUiPage(view), ...(setCookies ? { setCookies } : {}) };
}

function redirect(location: string, setCookies?: readonly string[]): StaffUiResponse {
  return { status: 303, location, ...(setCookies ? { setCookies } : {}) };
}

function errorPage(status: number, variant: StaffUiErrorVariant, partial = false, csrfToken?: string): StaffUiResponse {
  return page(status, { kind: "error", variant, partial, ...(csrfToken !== undefined ? { csrfToken } : {}) });
}

// --- cookie flash de confirmacion (solo etiqueta sintetica) ---------------------------------------------------

function flashKey(staffSessionKey: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", staffSessionKey, Buffer.alloc(0), FLASH_HKDF_INFO, 32));
}

function flashMac(key: Buffer, body: string): string {
  return createHmac("sha256", key).update(body).digest("base64url");
}

interface FlashPayload {
  /** principalRef de la sesion (ref opaca sintetica): la cookie no sirve con otra sesion. */
  readonly p: string;
  /** CA-138: sha256 del sid de la sesion que la emitio (nunca el sid en claro): la cookie no sirve con otra sesion ni tras un nuevo login. */
  readonly s: string;
  /** Etiqueta sintetica del alumno (ya validada contra el patron) o null. */
  readonly l: string | null;
  /** Expiracion (ms epoch, reloj del servidor). */
  readonly e: number;
  /** La cadena completa se reprodujo desde idempotencia (no hubo envio nuevo). */
  readonly a: boolean;
}

function encodeFlash(key: Buffer, payload: FlashPayload): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${flashMac(key, body)}`;
}

function decodeFlash(key: Buffer, value: string | undefined, principalRef: string, sid: string, nowMs: number): { readonly label: string | null; readonly alreadySent: boolean } | null {
  if (!value) return null;
  const dot = value.indexOf(".");
  if (dot === -1) return null;
  const body = value.slice(0, dot);
  const mac = Buffer.from(value.slice(dot + 1), "utf8");
  const expected = Buffer.from(flashMac(key, body), "utf8");
  if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Record<string, unknown>;
    if (parsed.p !== principalRef || parsed.s !== hashStaffSid(sid) || typeof parsed.e !== "number" || parsed.e < nowMs) return null;
    if (parsed.l !== null && !(typeof parsed.l === "string" && SUBJECT_LABEL_PATTERN.test(parsed.l))) return null;
    return { label: parsed.l as string | null, alreadySent: parsed.a === true };
  } catch {
    return null;
  }
}

const serializeFlashCookie = (value: string): string => `${FLASH_COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${FLASH_TTL_MS / 1000}`;

// --- helpers de negocio -----------------------------------------------------------------------------------------

type EmailCheck = "ok" | "format" | "reserved";

/** Misma regla que I2 (isReservedEmail), antes de crear nada: asi un correo invalido no deja una matricula huerfana. */
function checkEmail(raw: string): { readonly kind: EmailCheck; readonly email: string } {
  const email = raw.trim();
  if (email.length === 0 || email.length > MAX_EMAIL || !EMAIL_FORMAT.test(email)) return { kind: "format", email };
  if (!isReservedEmail(email)) return { kind: "reserved", email };
  return { kind: "ok", email };
}

async function lookupStudent(deps: StaffUiDeps, tenantId: string, subjectRef: string, participationRef: string): Promise<StaffUiStudent> {
  const entry = deps.staffConsole.subjectDirectory ? await deps.staffConsole.subjectDirectory.lookup(tenantId, subjectRef) : null;
  const label = entry !== null && SUBJECT_LABEL_PATTERN.test(entry.label) ? entry.label : null;
  return { label, subjectRef, participationRef };
}

/** Clave determinista por paso; cumple IDEMPOTENCY_KEY_PATTERN (16-128). Se liga ademas a (tenant, principal, operacion) en GRD-CM-08. */
function idempotencyKey(step: "en0" | "i1" | "i2" | "i3", tenantId: string, principalRef: string, student: StaffUiStudent, contextRef: string): string {
  const digest = createHash("sha256")
    .update([tenantId, principalRef, student.subjectRef, student.participationRef ?? "", contextRef].join("\u0000"))
    .digest("hex")
    .slice(0, 40);
  return `staff-ui-${step}-${digest}`;
}

type Step = "EN0" | "I1" | "I2" | "I3";

function failureResponse(step: Step, result: HttpResult, label: string | null, csrfToken: string): StaffUiResponse {
  const code = (result.body as { code?: unknown } | undefined)?.code;
  const partial = step !== "EN0";
  if (result.status === 404) return errorPage(404, "session", partial);
  if (code === "CSRF_REJECTED") return errorPage(403, "csrf", partial);
  if (code === "ACTOR_NOT_ALLOWED") return errorPage(403, "permission", partial);
  // IDEMPOTENCY_CONFLICT: la misma cadena (alumno + participacion) ya se ejecuto con otro correo; es "ya tiene una invitacion".
  if (code === "ENROLLMENT_ALREADY_ACTIVE" || code === "INVITATION_ALREADY_ACTIVE" || code === "IDEMPOTENCY_CONFLICT") return page(409, { kind: "active", csrfToken, label });
  if (code === "INVITER_NOT_PARTICIPATING" || code === "ENROLLMENT_NOT_ACTIVE" || code === "CONTEXT_NOT_ACTIVE" || code === "VERSION_OR_MODE_GUARD_FAILED") {
    return errorPage(409, "not-current", partial, csrfToken);
  }
  if (code === "GUARD_EVALUATOR_UNAVAILABLE") return errorPage(503, "not-configured", partial, csrfToken);
  return errorPage(500, "generic", partial, csrfToken);
}

const ok = (r: HttpResult): boolean => r.status >= 200 && r.status < 300;

// --- handler ------------------------------------------------------------------------------------------------------

export async function handleStaffUi(req: StaffUiRequest, deps: StaffUiDeps): Promise<StaffUiResponse> {
  if (!isStaffUiRoute(req.method, req.path)) return NOT_FOUND;
  const devLogin = deps.environment === "LOCAL" && deps.devLoginPrincipalRef !== undefined;
  const nowMs = deps.nowMs ?? Date.now;

  if (req.method === "GET") {
    if (req.path === STAFF_ENTRY_PATH) return handleEntry(req, deps, devLogin, nowMs);
    if (req.path === STAFF_LIST_PATH) return handleList(req, deps, nowMs);
    return handleSent(req, deps, nowMs());
  }

  // POST: dev-login no tiene sesion previa ni CSRF; solo existe en LOCAL (GRD-CM-13: fuera de LOCAL, 404 como cualquier ruta inexistente).
  if (req.path === STAFF_DEV_LOGIN_PATH) return handleDevLogin(req, deps, devLogin);
  return handlePost(req, deps, nowMs);
}

async function handleEntry(req: StaffUiRequest, deps: StaffUiDeps, devLogin: boolean, nowMs: () => number): Promise<StaffUiResponse> {
  // Con sesion vigente la entrada no tiene nada que mostrar: va a la lista (la lista hace su propio gating completo).
  try {
    const auth = await authenticateStaffSession(req.cookieHeader, { ...deps.staffConsole, nowMs }, deps.config, deps.staffSessionKey);
    if (auth.ok) return redirect(STAFF_LIST_PATH);
  } catch {
    // identidad no disponible: se muestra la entrada (sin datos)
  }
  return page(200, { kind: "entry", devLogin });
}

function csrfCookieOf(req: StaffUiRequest, deps: StaffUiDeps): string | undefined {
  const value = parseCookies(req.cookieHeader)[deps.config.staffCsrfCookieName];
  return value !== undefined && value.length > 0 ? value : undefined;
}

async function handleList(req: StaffUiRequest, deps: StaffUiDeps, nowMs: () => number): Promise<StaffUiResponse> {
  const evaluation = await evaluateStaffRoster(
    "html",
    {
      cookieHeader: req.cookieHeader,
      originHeader: req.originHeader,
      secFetchSiteHeader: req.secFetchSiteHeader,
      secFetchModeHeader: req.secFetchModeHeader,
      secFetchDestHeader: req.secFetchDestHeader,
      rawQuery: req.rawQuery,
    },
    deps.staffConsole,
    deps.config,
    deps.staffSessionKey,
    deps.cursorKey,
    nowMs,
  );
  const existingCsrf = csrfCookieOf(req, deps);
  if (!evaluation.ok) {
    const status = evaluation.result.status;
    // Con 422/503 la sesion ya paso el gating: se conserva el encabezado con sesion.
    if (status === 404) return errorPage(404, "session");
    if (status === 403) return errorPage(403, "permission");
    if (status === 422) return errorPage(422, "query", false, existingCsrf);
    return errorPage(503, "list-unavailable", false, existingCsrf);
  }
  // CA-138: el token CSRF es el ligado al sid de esta sesion; si el navegador trae otro (o ninguno), se vuelve a fijar.
  const csrfToken = staffCsrfTokenFor(deps.staffSessionKey, evaluation.staff.sid);
  const items: StaffUiListItem[] = [];
  for (const item of evaluation.page.items) {
    // El contrato solo expone participationRef en NOT_INVITED; para retomar un "Envio incompleto" la UI lo toma del directorio del servidor.
    let participationRef = item.participationRef;
    if (item.invitationStatus === "PENDING_SEND" && deps.staffConsole.subjectDirectory) {
      const entry = await deps.staffConsole.subjectDirectory.lookup(evaluation.staff.tenantId, item.subjectRef);
      participationRef = entry?.participationRef !== undefined && entry.participationRef !== null && REF_PATTERN.test(entry.participationRef) ? entry.participationRef : null;
    }
    items.push({ label: item.subjectLabel, subjectRef: item.subjectRef, participationRef, status: item.invitationStatus });
  }
  return page(
    200,
    { kind: "list", csrfToken, items, nextCursor: evaluation.page.nextCursor },
    existingCsrf !== csrfToken ? [serializeCsrfCookie(deps.config.staffCsrfCookieName, csrfToken)] : undefined,
  );
}

async function handleSent(req: StaffUiRequest, deps: StaffUiDeps, nowMsValue: number): Promise<StaffUiResponse> {
  const nowMs = (): number => nowMsValue;
  if (!secFetchAllowed("html", req)) return errorPage(404, "session");
  if (req.originHeader !== undefined && req.originHeader !== deps.config.allowedOrigin) return errorPage(404, "session");
  let auth: Awaited<ReturnType<typeof authenticateStaffSession>>;
  try {
    auth = await authenticateStaffSession(req.cookieHeader, { ...deps.staffConsole, nowMs }, deps.config, deps.staffSessionKey);
  } catch {
    return errorPage(503, "list-unavailable");
  }
  if (!auth.ok) return auth.result.status === 403 ? errorPage(403, "permission") : errorPage(404, "session");
  const csrfToken = csrfCookieOf(req, deps);
  const flash = decodeFlash(flashKey(deps.staffSessionKey), parseCookies(req.cookieHeader)[FLASH_COOKIE_NAME], auth.staff.principalRef, auth.staff.sid, nowMsValue);
  // Sin confirmacion vigente (recarga tardia, otra sesion): nada que confirmar, se vuelve a la lista.
  if (csrfToken === undefined || flash === null) return redirect(STAFF_LIST_PATH);
  return page(200, { kind: "sent", csrfToken, label: flash.label, alreadySent: flash.alreadySent });
}

async function handleDevLogin(req: StaffUiRequest, deps: StaffUiDeps, enabled: boolean): Promise<StaffUiResponse> {
  if (!enabled || deps.devLoginPrincipalRef === undefined) return NOT_FOUND;
  // Sin sesion previa no hay token CSRF: solo se exige Origin exacto (los navegadores lo envian en todo POST).
  if (req.originHeader !== deps.config.allowedOrigin) return errorPage(403, "csrf");
  const result = await handleDevStaffConsoleLogin(
    { originHeader: req.originHeader, csrfHeaderToken: undefined, cookieHeader: req.cookieHeader, body: { principalRef: deps.devLoginPrincipalRef } },
    (deps.environment ?? "DEV") as Environment, // el gating real (LOCAL + fixture) ya se evaluo en `enabled`
    { ...deps.staffConsole, ...(deps.nowMs ? { nowMs: deps.nowMs } : {}) },
    deps.config,
    deps.staffSessionKey,
  );
  if (result.status === 503) return errorPage(503, "login-failed"); // CA-141: sin evento de seguridad no hay sesion ni Set-Cookie
  if (result.status !== 200 || !result.setStaffSessionCookie || !result.setStaffCsrfCookie) return errorPage(403, "permission");
  return redirect(STAFF_LIST_PATH, [result.setStaffSessionCookie, result.setStaffCsrfCookie]);
}

async function handlePost(req: StaffUiRequest, deps: StaffUiDeps, nowMs: () => number): Promise<StaffUiResponse> {
  const form = new URLSearchParams(req.formBody);
  const cookies = parseCookies(req.cookieHeader);
  const csrfCookie = cookies[deps.config.staffCsrfCookieName];

  // GRD-CM-10 ANTES de cualquier otra validacion o efecto. Sec-Fetch-Site, si viene, debe ser same-origin (defensa extra: SameSite=Lax).
  if (req.secFetchSiteHeader !== undefined && req.secFetchSiteHeader !== "same-origin") return errorPage(403, "csrf");
  try {
    assertCsrfAndOrigin({
      originHeader: req.originHeader,
      allowedOrigin: deps.config.allowedOrigin,
      csrfHeaderToken: form.get("csrf_token") ?? undefined,
      csrfCookieToken: csrfCookie,
    });
  } catch (err) {
    if (err instanceof DomainError && err.code === "ERR-CM-09") return errorPage(403, "csrf");
    throw err;
  }
  const csrfToken = csrfCookie as string; // assertCsrfAndOrigin garantiza que existe y que el campo coincide

  if (req.path === STAFF_LOGOUT_PATH) {
    // CA-138: cerrar REVOCA el sid en servidor (la cookie copiada o robada deja de servir de inmediato) y ademas borra las cookies del
    // navegador. Si la cookie trae una sesion firmada, el token CSRF debe ser el de ESA sesion. Sin sesion valida solo se borran cookies.
    const cookieValue = cookies[deps.config.staffSessionCookieName];
    const closing = decodeStaffSession(deps.staffSessionKey, cookieValue);
    if (closing !== null && !staffCsrfMatchesSession(deps.staffSessionKey, closing.sid, csrfCookie)) return errorPage(403, "csrf");
    try {
      await revokeStaffSessionCookie({ sessions: deps.staffConsole.sessions, staffSessionKey: deps.staffSessionKey, nowMs }, cookieValue);
    } catch (error) {
      // CA-141 (D-3): sin evento de seguridad no se revoca (la tx se revierte): la sesion SIGUE abierta, no se borran cookies y NUNCA se muestra exito.
      if (isSecurityEventWriteError(error)) reportSecurityEventWriteFailure(error);
      return errorPage(503, "logout-failed", false, csrfToken); // no se pudo revocar: NO se finge un cierre exitoso
    }
    const expire = "Path=/; Secure; SameSite=Lax; Max-Age=0";
    return redirect(STAFF_ENTRY_PATH, [
      `${deps.config.staffSessionCookieName}=; ${expire}; HttpOnly`,
      `${deps.config.staffCsrfCookieName}=; ${expire}`,
      `${FLASH_COOKIE_NAME}=; ${expire}; HttpOnly`,
    ]);
  }

  let auth: Awaited<ReturnType<typeof authenticateStaffSession>>;
  try {
    // CA-138/CA-140: el token CSRF debe ser el de ESTA sesion (ligado al sid) y se valida antes del touch (GRD-SE-08).
    auth = await authenticateStaffSession(req.cookieHeader, { ...deps.staffConsole, nowMs }, deps.config, deps.staffSessionKey, { value: csrfCookie });
  } catch {
    return errorPage(503, "generic");
  }
  if (!auth.ok) {
    if (auth.csrfRejected === true) return errorPage(403, "csrf");
    return auth.result.status === 403 ? errorPage(403, "permission") : errorPage(404, "session");
  }
  const staff = auth.staff;

  const subjectRef = form.get("subject") ?? "";
  const participationRef = form.get("participation") ?? "";
  // Refs mal formadas = alumno no disponible (404 uniforme: no se distingue de "no existe en tu colegio").
  if (!REF_PATTERN.test(subjectRef) || !REF_PATTERN.test(participationRef)) return errorPage(404, "session");
  const student = await lookupStudent(deps, staff.tenantId, subjectRef, participationRef);

  if (req.path === STAFF_INVITE_PATH) {
    // Primer paso (desde la lista) o "Volver a editar" (desde el resumen, con el correo ya escrito).
    const prior = (form.get("guardian_email") ?? "").trim();
    return page(200, { kind: "form", csrfToken, student, ...(prior.length > 0 && prior.length <= MAX_EMAIL ? { email: prior } : {}) });
  }

  const check = checkEmail(form.get("guardian_email") ?? "");
  // El valor invalido NO se refleja ni se persiste (EXT-B (i), P-4).
  if (check.kind !== "ok") return page(422, { kind: "form", csrfToken, student, error: check.kind });

  if (req.path === STAFF_REVIEW_PATH) return page(200, { kind: "review", csrfToken, student, email: check.email });

  return sendInvitation(req, deps, staff, student, check.email, csrfToken);
}

const RESUMABLE: ReadonlySet<StaffInvitationStatus> = new Set(["NOT_INVITED", "PENDING_SEND", "SENT"]);

/** Estado colapsado de la fila (alumno, contexto del estudio) si la participacion enviada corresponde a la del servidor y el estado
 * admite iniciar o retomar la cadena (SENT: solo para reproducirla por idempotencia). null = no aplica. Lanza si el puerto falla. */
async function resumableStatus(deps: StaffUiDeps, staff: { readonly tenantId: string; readonly principalRef: string }, student: StaffUiStudent): Promise<StaffInvitationStatus | null> {
  const roster = deps.staffConsole.roster;
  if (roster === undefined) throw new Error("roster no configurado");
  const entry = deps.staffConsole.subjectDirectory ? await deps.staffConsole.subjectDirectory.lookup(staff.tenantId, student.subjectRef) : null;
  let after: { subjectRef: string; contextRef: string } | null = null;
  for (;;) {
    const rows = await roster.readPage({ tenantId: staff.tenantId, principalRef: staff.principalRef, actorRole: "TENANT_ADMIN", after, rowLimit: 100 });
    const row = rows.find((r) => r.subjectRef === student.subjectRef && r.contextRef === deps.ui.contextRef);
    if (row !== undefined) {
      const known = [row.activeEnrollmentParticipationRef, entry?.participationRef ?? null];
      return RESUMABLE.has(row.staffStatus) && known.includes(student.participationRef) ? row.staffStatus : null;
    }
    const last = rows[rows.length - 1];
    if (rows.length < 100 || last === undefined) return null;
    after = { subjectRef: last.subjectRef, contextRef: last.contextRef };
  }
}

async function sendInvitation(
  req: StaffUiRequest,
  deps: StaffUiDeps,
  staff: { readonly tenantId: string; readonly principalRef: string; readonly sid: string },
  student: StaffUiStudent,
  email: string,
  csrfToken: string,
): Promise<StaffUiResponse> {
  const { config, staffSessionKey, staffConsole, ui } = deps;
  const key = (step: "en0" | "i1" | "i2" | "i3"): string => idempotencyKey(step, staff.tenantId, staff.principalRef, student, ui.contextRef);
  // El token CSRF del formulario ya se verifico: se reenvia como cabecera double-submit a los handlers (que lo vuelven a exigir).
  const base = { originHeader: req.originHeader, csrfHeaderToken: csrfToken, cookieHeader: req.cookieHeader };
  const subjectRef = student.subjectRef;
  const participationRef = student.participationRef as string; // validado con REF_PATTERN arriba

  // P2-2 (SEC-CNS-020): antes de EN0, (subjectRef, participationRef) debe ser una fila retomable del roster del tenant. Misma proyeccion
  // colapsada del puerto (sin duplicar el mapeo); si no, el mismo error uniforme que una ref ajena, sin crear nada.
  let before: StaffInvitationStatus | null;
  try {
    before = await resumableStatus(deps, staff, student);
  } catch {
    return errorPage(503, "not-configured");
  }
  if (before === null) return errorPage(404, "session");

  const en0 = await handleOpenEnrollment({ ...base, idempotencyKeyHeader: key("en0"), body: { subjectRef, participationRef } }, staffConsole, config, staffSessionKey);
  if (!ok(en0)) return failureResponse("EN0", en0, student.label, csrfToken);
  const enrollmentRef = (en0.body as { enrollmentRef: string }).enrollmentRef;

  const i1 = await handleCreateInvitation(
    { ...base, idempotencyKeyHeader: key("i1"), body: { subjectRef, enrollmentRef, participationRef, contextRef: ui.contextRef } },
    staffConsole,
    config,
    staffSessionKey,
  );
  if (!ok(i1)) return failureResponse("I1", i1, student.label, csrfToken);
  const invitationRef = (i1.body as { invitationRef: string }).invitationRef;

  const i2 = await handleMarkInvitationReady(
    { ...base, idempotencyKeyHeader: key("i2"), body: { consentVersion: ui.consentVersion, recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: email } },
    invitationRef,
    staffConsole,
    config,
    staffSessionKey,
  );
  if (!ok(i2)) return failureResponse("I2", i2, student.label, csrfToken);

  const i3 = await handleSendInvitation({ ...base, idempotencyKeyHeader: key("i3"), body: {} }, invitationRef, staffConsole, config, staffSessionKey);
  if (!ok(i3)) return failureResponse("I3", i3, student.label, csrfToken);

  // PRG: la confirmacion es un GET aparte; la cookie flash lleva solo la etiqueta sintetica.
  const nowMs = (deps.nowMs ?? Date.now)();
  // Si ya estaba SENT antes de la cadena, todo vino de idempotencia: la confirmacion dice que ya habia sido enviada.
  const flash = encodeFlash(flashKey(staffSessionKey), { p: staff.principalRef, s: hashStaffSid(staff.sid), l: student.label, e: nowMs + FLASH_TTL_MS, a: before === "SENT" });
  return redirect(STAFF_SENT_PATH, [serializeFlashCookie(flash)]);
}
