// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-116 (GET /staff/roster, operationId listRosterInvitationStatus),
// api-payloads.schema.json StaffRosterPage / StaffRosterRow / StaffInvitationStatus, REQ-CNS-036 AC-04..AC-09, UX-CNS-005,
// DEC-BR-019 (Notion), diseno api-cns-116-staff-list-design.md rev. 2 §2/§3/§4/§7/§8, SEC-CNS-018 rev. 2 (R3, R4, R5),
// common.spec.yaml GRD-CM-01/02/07 e INV-CM-05/08/09 (ERR-CM-13 LIST_QUERY_INVALID). Solo JSON (la pagina HTML 90:33 es otra PR).
//
// Lectura pura (INV-CM-08): no transiciona, no emite, no escribe ledger ni outbox; su unica escritura es UNA fila
// STAFF_ROSTER_READ en ops.access_log, dentro de la misma tx que el SELECT (la hace el adaptador del puerto).
//
// Orden FIJO del GET (R3; el adaptador cubre los pasos 2-7):
//   (1) gating completo FUERA de la tx: Sec-Fetch-Site same-origin (obligatorio en JSON; ausente/distinto -> 404 uniforme),
//       Origin identico a la consola si viene (si no -> 404), sesion STAFF + membership (404), rol TENANT_ADMIN (403),
//       query valida y cursor valido (422 uniforme). Un gating fallido NO escribe access_log.
//   (2..7) puerto: BEGIN -> access_log -> SET LOCAL ROLE staff_roster_reader -> current_user -> SELECT de la vista -> COMMIT.
//       Cualquier fallo -> 503 GUARD_EVALUATOR_UNAVAILABLE sin datos.
// Cabeceras en TODA respuesta de la ruta: Cache-Control no-store, CORP same-origin, CSP frame-ancestors 'none', Vary Cookie,
// Referrer-Policy no-referrer, nosniff; sin ETag/Last-Modified; sin CORS.

import { randomUUID } from "node:crypto";

import {
  decodeRosterCursor,
  encodeRosterCursor,
  RosterCursorInvalidError,
  type RosterCursorScope,
  type RosterCursorPosition,
} from "../../modules/staff-roster/roster-cursor.ts";
import { StaffRosterUnavailableError, type StaffRosterProjectionRow } from "../../ports/staff-roster.port.ts";
import { SUBJECT_LABEL_PATTERN } from "../../ports/subject-directory.port.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import type { HttpResult } from "./consent-flow.handler.ts";
import { authenticateStaffSession, type StaffConsolePorts } from "./staff-console.handler.ts";

export const STAFF_ROSTER_PATH = "/staff/roster";
export const STAFF_ROSTER_DEFAULT_LIMIT = 50;
export const STAFF_ROSTER_MAX_LIMIT = 100;

/** Espejo de common.schema.json#/$defs/Ref. */
const REF_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export interface RawStaffRosterRequest {
  readonly cookieHeader: string | undefined;
  readonly originHeader: string | undefined;
  /** Sec-Fetch-Site tal cual llego (Node une duplicados con ", "; cualquier valor distinto de same-origin -> 404). */
  readonly secFetchSiteHeader: string | undefined;
  /** Query string sin el "?" (puede ser ""). Nunca se registra en logs. */
  readonly rawQuery: string;
  /** Solo la variante HTML (R5): Sec-Fetch-Mode / Sec-Fetch-Dest tal cual llegaron. */
  readonly secFetchModeHeader?: string | undefined;
  readonly secFetchDestHeader?: string | undefined;
}

/** Variante de borde: `json` exige Sec-Fetch-Site same-origin; `html` (pagina 90:33, R5) acepta same-origin y `none` SOLO
 * con Sec-Fetch-Mode=navigate y Sec-Fetch-Dest=document (navegacion directa del usuario). El resto del orden es identico. */
export type StaffRosterEdge = "json" | "html";

/** Fila ya colapsada (misma forma que StaffRosterRow del contrato). */
export interface StaffRosterItem {
  readonly subjectRef: string;
  readonly participationRef: string | null;
  readonly subjectLabel: string | null;
  readonly invitationStatus: StaffRosterProjectionRow["staffStatus"];
}

export interface StaffRosterPageData {
  readonly items: readonly StaffRosterItem[];
  readonly nextCursor: string | null;
}

export type StaffRosterEvaluation =
  | { readonly ok: true; readonly page: StaffRosterPageData; readonly staff: { readonly tenantId: string; readonly principalRef: string } }
  | { readonly ok: false; readonly result: HttpResult };

/** Cabeceras de seguridad de TODA respuesta de la ruta (2xx y errores): iguales para que no sirvan de oraculo. */
export const STAFF_ROSTER_RESPONSE_HEADERS: Readonly<Record<string, string>> = {
  "Cache-Control": "no-store",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": "frame-ancestors 'none'",
  "Vary": "Cookie",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

function withHeaders(result: HttpResult): HttpResult {
  return { ...result, extraHeaders: { ...(result.extraHeaders ?? {}), ...STAFF_ROSTER_RESPONSE_HEADERS } };
}

function uniformNotFound(): HttpResult {
  return { status: 404, body: { status: 404 } };
}

/** ERR-CM-13 LIST_QUERY_INVALID: cuerpo identico en todos los casos (sin eco de parametro ni de causa). */
function listQueryInvalid(): HttpResult {
  return { status: 422, body: { code: "LIST_QUERY_INVALID", status: 422, correlationId: randomUUID() } };
}

/** ERR-CM-12 GUARD_EVALUATOR_UNAVAILABLE: fallo de BD, access_log, SET ROLE, reloj, estado desconocido o directorio. */
function unavailable(): HttpResult {
  return { status: 503, body: { code: "GUARD_EVALUATOR_UNAVAILABLE", status: 503, correlationId: randomUUID() } };
}

interface ParsedQuery {
  readonly limit: number;
  readonly cursor: string | null;
}

/** Solo `limit` (1-100, def. 50) y `cursor`, cada uno a lo sumo una vez; cualquier otro parametro -> null (422). */
function parseQuery(rawQuery: string): ParsedQuery | null {
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(rawQuery);
  } catch {
    return null;
  }
  let limit = STAFF_ROSTER_DEFAULT_LIMIT;
  let cursor: string | null = null;
  const seen = new Set<string>();
  for (const [key, value] of params) {
    if (seen.has(key)) return null;
    seen.add(key);
    if (key === "limit") {
      if (!/^[0-9]{1,3}$/.test(value)) return null;
      limit = Number(value);
      if (limit < 1 || limit > STAFF_ROSTER_MAX_LIMIT) return null;
    } else if (key === "cursor") {
      if (value.length === 0) return null;
      cursor = value;
    } else {
      return null;
    }
  }
  return { limit, cursor };
}

export async function handleListStaffRoster(
  request: RawStaffRosterRequest,
  ports: StaffConsolePorts,
  config: RightsCaseHttpConfig,
  staffSessionKey: Buffer,
  cursorKey: Buffer,
  nowMs: () => number = Date.now,
): Promise<HttpResult> {
  const outcome = await evaluateStaffRoster("json", request, ports, config, staffSessionKey, cursorKey, nowMs);
  return withHeaders(outcome.ok ? { status: 200, body: { items: outcome.page.items, nextCursor: outcome.page.nextCursor } } : outcome.result);
}

/** R5: la navegacion directa (URL escrita, marcador) llega con Sec-Fetch-Site none; solo asi se acepta en la variante HTML. */
export function secFetchAllowed(edge: StaffRosterEdge, request: Pick<RawStaffRosterRequest, "secFetchSiteHeader" | "secFetchModeHeader" | "secFetchDestHeader">): boolean {
  if (request.secFetchSiteHeader === "same-origin") return true;
  return edge === "html" && request.secFetchSiteHeader === "none" && request.secFetchModeHeader === "navigate" && request.secFetchDestHeader === "document";
}

/**
 * Orden FIJO unico del GET (JSON y HTML comparten esta funcion: mismo gating, misma consulta, mismo mapeo, misma fila de
 * access_log; el HTML solo cambia la representacion). Devuelve la pagina ya colapsada o el HttpResult de error.
 */
export async function evaluateStaffRoster(
  edge: StaffRosterEdge,
  request: RawStaffRosterRequest,
  ports: StaffConsolePorts,
  config: RightsCaseHttpConfig,
  staffSessionKey: Buffer,
  cursorKey: Buffer,
  nowMs: () => number = Date.now,
): Promise<StaffRosterEvaluation> {
  const fail = (result: HttpResult): StaffRosterEvaluation => ({ ok: false, result });
  // (1) gating completo, fuera de la tx.
  // SameSite=Lax deja pasar la cookie en un GET cross-site de nivel superior: se exige same-origin (HTML: o navegacion directa).
  if (!secFetchAllowed(edge, request)) return fail(uniformNotFound());
  if (request.originHeader !== undefined && request.originHeader !== config.allowedOrigin) return fail(uniformNotFound());

  let auth: Awaited<ReturnType<typeof authenticateStaffSession>>;
  try {
    auth = await authenticateStaffSession(request.cookieHeader, ports.staffIdentity, config, staffSessionKey);
  } catch {
    return fail(unavailable()); // el roster de identidad no responde: fail-closed, sin datos
  }
  if (!auth.ok) return fail(auth.result);
  const staff = auth.staff;

  const query = parseQuery(request.rawQuery);
  if (query === null) return fail(listQueryInvalid());
  const scope: RosterCursorScope = { tenantId: staff.tenantId, principalRef: staff.principalRef, role: "TENANT_ADMIN" };
  let after: RosterCursorPosition | null = null;
  if (query.cursor !== null) {
    try {
      after = decodeRosterCursor(cursorKey, scope, query.cursor, nowMs());
    } catch (error) {
      if (error instanceof RosterCursorInvalidError) return fail(listQueryInvalid());
      throw error;
    }
  }

  // (2..7) un unico puerto abre la tx y hace access_log -> SET ROLE -> SELECT -> COMMIT.
  const roster = ports.roster;
  if (roster === undefined) return fail(unavailable());
  let rows: readonly StaffRosterProjectionRow[];
  try {
    rows = await roster.readPage({
      tenantId: staff.tenantId,
      principalRef: staff.principalRef,
      actorRole: "TENANT_ADMIN",
      after,
      rowLimit: query.limit + 1,
    });
  } catch (error) {
    if (error instanceof StaffRosterUnavailableError) return fail(unavailable());
    return fail(unavailable()); // cualquier otro fallo del puerto: tambien 503 sin datos ni detalle
  }

  const page = rows.slice(0, query.limit);
  const items: StaffRosterItem[] = [];
  try {
    for (const row of page) {
      const entry = ports.subjectDirectory ? await ports.subjectDirectory.lookup(staff.tenantId, row.subjectRef) : null;
      // Etiqueta: solo "Alumno de prueba N"; fuera del patron -> null (la UI dice "Alumno sin etiqueta").
      const label = entry !== null && SUBJECT_LABEL_PATTERN.test(entry.label) ? entry.label : null;
      // participationRef solo en NOT_INVITED: matricula ACTIVE -> puerto de roster -> null.
      let participationRef: string | null = null;
      if (row.staffStatus === "NOT_INVITED") {
        const candidate = row.activeEnrollmentParticipationRef ?? entry?.participationRef ?? null;
        participationRef = candidate !== null && REF_PATTERN.test(candidate) ? candidate : null;
      }
      items.push({ subjectRef: row.subjectRef, participationRef, subjectLabel: label, invitationStatus: row.staffStatus });
    }
  } catch {
    return fail(unavailable()); // puerto de etiquetas caido
  }

  const last = page[page.length - 1];
  const nextCursor =
    rows.length > query.limit && last !== undefined
      ? encodeRosterCursor(cursorKey, scope, { subjectRef: last.subjectRef, contextRef: last.contextRef }, nowMs())
      : null;
  return { ok: true, page: { items, nextCursor }, staff };
}
