// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.1 (step-up: principal de la sesion validada), §5.4 (P-50, P-51), §6 (grants P6-3), §10 fila 6d; GRD-RC-10, GRD-RC-12;
// contracts/openapi/consent-platform.openapi.yaml (issueStepUp, requestCaseGrant, approveCaseGrant); db/migrations/0060-0062.
//
// Rutas POST del proceso platform (platform_rw, sin egress) para el step-up de caso y los grants. Reglas comunes (igual que session-routes.ts):
//  - Solo origen permitido (allowlist CIDR) y SOLO MISMO ORIGEN (`Origin` exacto; `Sec-Fetch-Site` presente = same-origin). Cualquier otra cosa = 404 uniforme, ANTES de tocar la base.
//  - Sesion PLATFORM de la cookie `__Host-` validada EN LA BASE; P-50 (30/min) por el principal de la sesion validada. El principal y el tenant NUNCA salen de la request ni del cuerpo.
//  - Cualquier fallo, incluido un error de base: 404 uniforme (sin motivo). P-51 se cuenta en la base.
//  - POST /platform/step-up {action, targetRef}: emite el nonce (base), inicia STEP_UP (base) y responde 303 al IdP (max_age=0 + prompt=login) con la cookie `state` (Lax). El nonce solo viaja al IdP.
//  - POST /platform/rights-cases/{caseRef}/grant-requests: request_grant (consume el step-up REQUEST_GRANT en la misma tx). 200 {requestRef}.
//  - POST /platform/rights-cases/{caseRef}/grant-requests/{ref}/approval {validSeconds?}: approve_grant (consume APPROVE_GRANT). 200 {grantRef}.

import { randomBytes, createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { OidcAuthorizationPort } from "../../ports/oidc-exchange.port.ts";
import type { CaseStepUpAction, PlatformGrantPort, StepUpLimit } from "../../ports/platform-grant.port.ts";
import type { PlatformSessionPort } from "../../ports/platform-session.port.ts";
import { CASE_REF_RE, idpAuthorizationUrl, OIDC_STATE_COOKIE } from "./auth-routes.ts";
import type { IdpRedirectConfig } from "./auth-routes.ts";
import { COMMON, cookie, json, notFound, p50Allows, parseCookies, PLATFORM_SESSION_COOKIE, tooManyRequests } from "./http-util.ts";
import type { OperatorLimitDeps } from "./http-util.ts";
import type { Cidr } from "./rate-limit.ts";
import { ipInCidrs } from "./rate-limit.ts";

export const GRANT_ROUTES = { stepUp: "/platform/step-up" } as const;
const GRANT_REQUESTS_RE = /^\/platform\/rights-cases\/([0-9a-f-]{36})\/grant-requests$/;
const GRANT_APPROVAL_RE = /^\/platform\/rights-cases\/([0-9a-f-]{36})\/grant-requests\/([0-9a-f-]{36})\/approval$/;

export interface GrantRoutesDeps extends OperatorLimitDeps {
  readonly grants: PlatformGrantPort;
  readonly sessions: PlatformSessionPort;
  readonly authorization: OidcAuthorizationPort;
  readonly allowedCidrs: readonly Cidr[];
  readonly publicOrigin: string | undefined;
  readonly idp?: IdpRedirectConfig;
  /** P-51 (aprobado 5 / 10 min; configurable): la base lo cuenta. */
  readonly p51: StepUpLimit;
  readonly flowTtlSeconds: number;
}

const MAX_BODY_BYTES = 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SID_RE = /^[0-9a-f]{64}$/;
const ACTIONS: ReadonlySet<string> = new Set(["REQUEST_GRANT", "APPROVE_GRANT", "PROPOSE_CASE_VERIFICATION", "APPROVE_CASE_VERIFICATION", "WITHDRAW_CASE_VERIFICATION"]);
const b64u = (n: number): string => randomBytes(n).toString("base64url");
const sha256Hex = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  const type = (req.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
  if (type !== "application/json") return null;
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(chunk as Buffer);
  }
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Devuelve true si la ruta fue atendida. El resto cae al 404 del proceso. */
export async function handleGrantRoute(req: IncomingMessage, res: ServerResponse, deps: GrantRoutesDeps): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://platform.invalid");
  const path = url.pathname;
  const isStepUp = path === GRANT_ROUTES.stepUp;
  const requestsMatch = GRANT_REQUESTS_RE.exec(path);
  const approvalMatch = GRANT_APPROVAL_RE.exec(path);
  if (!isStepUp && requestsMatch === null && approvalMatch === null) return false;
  if (req.method !== "POST" || url.search !== "") return notFound(res), true;
  const remote = req.socket.remoteAddress ?? "";
  if (deps.allowedCidrs.length > 0 && !ipInCidrs(remote, deps.allowedCidrs)) return notFound(res), true;
  if (deps.publicOrigin === undefined || req.headers.origin !== deps.publicOrigin) return notFound(res), true;
  const site = req.headers["sec-fetch-site"];
  if (site !== undefined && site !== "same-origin") return notFound(res), true;

  const sid = parseCookies(req.headers.cookie).get(PLATFORM_SESSION_COOKIE);
  if (sid === undefined || !SID_RE.test(sid)) return notFound(res), true;
  try {
    // La sesion se valida EN LA BASE (el principal es el de la fila; nunca de la request). P-50 por ese principal.
    const session = await deps.sessions.validate({ sid, kind: "PLATFORM" });
    if (session === null) return notFound(res), true;
    if (!p50Allows(deps, session.principalRef)) return tooManyRequests(res), true;
    const body = (await readJsonBody(req)) ?? {};

    if (isStepUp) {
      const action = body.action;
      const targetRef = body.targetRef;
      // Contrato (additionalProperties: false): solo {action, targetRef}; cualquier campo extra = 404 uniforme.
      if (Object.keys(body).some((k) => k !== "action" && k !== "targetRef")) return notFound(res), true;
      if (deps.idp === undefined || typeof action !== "string" || !ACTIONS.has(action) || typeof targetRef !== "string") return notFound(res), true;
      if (!(action === "REQUEST_GRANT" ? CASE_REF_RE.test(targetRef) : UUID_RE.test(targetRef))) return notFound(res), true;
      const nonce = await deps.grants.issueStepUpNonce({ sid, action: action as CaseStepUpAction, targetRef, ttlSeconds: deps.flowTtlSeconds });
      if (nonce === null) return notFound(res), true;
      const state = b64u(24);
      const verifier = b64u(48);
      // P-51 en la base: el inicio de step-up cuenta; sobre el limite la base deniega (404 uniforme). El principal sale de la sesion (sid), no de la request.
      await deps.authorization.begin({
        kind: "STEP_UP",
        state,
        bindingHex: sha256Hex(nonce),
        pkceVerifier: verifier,
        ttlSeconds: deps.flowTtlSeconds,
        maxAwaiting: null,
        sessionSid: sid,
        stepUpLimit: { max: deps.p51.max, windowSeconds: deps.p51.windowSeconds },
      });
      const target = idpAuthorizationUrl(deps.idp, { state, nonce, verifier });
      res.writeHead(303, { ...COMMON, location: target.toString(), "set-cookie": cookie(OIDC_STATE_COOKIE, state, "Lax", deps.flowTtlSeconds) });
      res.end();
      return true;
    }

    if (requestsMatch !== null) {
      const caseRef = requestsMatch[1] ?? "";
      if (!CASE_REF_RE.test(caseRef)) return notFound(res), true;
      const requestRef = await deps.grants.requestGrant({ sid, caseRef, limit: deps.p51 });
      if (requestRef === null) return notFound(res), true;
      json(res, 200, { requestRef });
      return true;
    }

    const caseRef = approvalMatch?.[1] ?? "";
    const requestRef = approvalMatch?.[2] ?? "";
    const valid = body.validSeconds;
    if (!CASE_REF_RE.test(caseRef) || !UUID_RE.test(requestRef)) return notFound(res), true;
    if (valid !== undefined && (typeof valid !== "number" || !Number.isInteger(valid))) return notFound(res), true;
    const grantRef = await deps.grants.approveGrant({ sid, caseRef, requestRef, validSeconds: valid ?? null, limit: deps.p51 });
    if (grantRef === null) return notFound(res), true;
    json(res, 200, { grantRef });
    return true;
  } catch {
    return notFound(res), true; // fallo cerrado, sin detalle
  }
}
