// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.a, §4.2.d, §5.4 (P-50, P-51), §6 (P6-5), §10 fila 6d y opcion A de Carlos (2026-10-15: `/platform/*` sale de `web`);
// contracts/openapi/consent-platform.openapi.yaml (proposeCaseVerification, approveCaseVerification, withdrawCaseVerificationProposal, recordCaseConfirmation, cosignCaseConfirmation, closeRightsCase);
// GRD-RC-10, GRD-RC-12; db/migrations/0069-0070.
//
// Rutas POST del proceso platform (platform_rw, sin egress) para las acciones de caso. Reglas comunes (igual que session-routes.ts / grant-routes.ts):
//  - Solo origen permitido (CIDR) y SOLO MISMO ORIGEN (`Origin` exacto). Cualquier otra cosa = 404 uniforme ANTES de tocar la base.
//  - La sesion (CASE o PLATFORM, segun la accion) se valida EN LA BASE; el actor, el tenant y la Revocation salen de la sesion y del caso real, NUNCA de la request ni del cuerpo. P-50 por el principal validado.
//  - El step-up (RH2) se consume en la base en la MISMA tx que el efecto (GRD-RC-12): el cuerpo ya no lleva `stepUpAssertion`. RH3 sin step-up (LD-03).
//  - Un fallo de sesion, de rol o de step-up = 404 uniforme; un guard de dominio = 403/409 con codigo; el agotamiento de R4 (G-3) = 503 uniforme sin acuse de exito; nunca texto para el titular (LEGAL DECISION).
//  POST .../verification-proposals {proposalRef, verificationScriptVersion}  |  .../{proposalRef}/approval {}  |  .../{proposalRef}/withdrawal {}  |  .../confirmation {confirmationGivenOnCasePage: true}
//  POST .../confirmation/cosign {}  |  .../close {outcome}

import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { RevocationApplyUnavailableError } from "../../modules/revocation/apply-guard.ts";
import type { CaseOutcome, PlatformCasePort } from "../../ports/platform-case.port.ts";
import type { StepUpLimit } from "../../ports/platform-grant.port.ts";
import type { PlatformSessionPort, SessionKind } from "../../ports/platform-session.port.ts";
import { CASE_REF_RE } from "./auth-routes.ts";
import { CASE_SESSION_COOKIE, COMMON, isUnavailable, json, notFound, p50Allows, parseCookies, PLATFORM_SESSION_COOKIE, serviceUnavailable, tooManyRequests } from "./http-util.ts";
import type { OperatorLimitDeps } from "./http-util.ts";
import type { Cidr } from "./rate-limit.ts";
import { ipInCidrs } from "./rate-limit.ts";

const PROPOSALS_RE = /^\/platform\/rights-cases\/([0-9a-f-]{36})\/verification-proposals$/;
const PROPOSAL_ACTION_RE = /^\/platform\/rights-cases\/([0-9a-f-]{36})\/verification-proposals\/([0-9a-f-]{36})\/(approval|withdrawal)$/;
const CONFIRMATION_RE = /^\/platform\/rights-cases\/([0-9a-f-]{36})\/confirmation(\/cosign)?$/;
const CLOSE_RE = /^\/platform\/rights-cases\/([0-9a-f-]{36})\/close$/;

export interface CaseRoutesDeps extends OperatorLimitDeps {
  readonly cases: PlatformCasePort;
  readonly sessions: PlatformSessionPort;
  readonly allowedCidrs: readonly Cidr[];
  readonly publicOrigin: string | undefined;
  readonly p51: StepUpLimit;
}

const MAX_BODY_BYTES = 1024;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SID_RE = /^[0-9a-f]{64}$/;
const SCRIPT_VERSION = /^[A-Za-z0-9._-]{1,32}$/;
const RIGHTS_PATHS_AVAILABLE = ["OTP", "RECOVERY_LINK", "HUMAN_CASE"] as const;

/** DomainErrorCode -> ErrorCode externo (common.schema.json); un codigo sin mapeo falla cerrado como 409 INVALID_TRANSITION. */
const EXTERNAL: Readonly<Record<string, { status: 403 | 409; code: string }>> = {
  "ERR-CM-06": { status: 409, code: "INVALID_TRANSITION" },
  "ERR-CM-10": { status: 403, code: "ACTOR_NOT_ALLOWED" },
  "ERR-RV-18": { status: 409, code: "RH3_FOUR_EYES_REQUIRED" },
  "ERR-RV-20": { status: 409, code: "RH3_NOT_BOUND_TO_RH2" },
  "ERR-RC-10": { status: 409, code: "ROSTER_INSUFFICIENT" },
  "ERR-RV-07": { status: 403, code: "RH2_SEPARATION_OF_DUTIES_VIOLATION" },
  "ERR-RC-03": { status: 409, code: "CASE_CLOSE_PRECONDITION_FAILED" },
};

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

const onlyKeys = (b: Record<string, unknown>, allowed: readonly string[]): boolean => Object.keys(b).every((k) => allowed.includes(k));

function problem(res: ServerResponse, status: number, code: string): void {
  res.writeHead(status, { ...COMMON, "content-type": "application/json" });
  res.end(JSON.stringify({ code, status, correlationId: randomUUID(), rightsPathsAvailable: RIGHTS_PATHS_AVAILABLE }));
}

function reply(res: ServerResponse, outcome: CaseOutcome, ok: () => { status: number; body: unknown }): void {
  if (outcome.ok) {
    const r = ok();
    json(res, r.status, r.body);
    return;
  }
  const mapped = EXTERNAL[outcome.reason];
  if (mapped !== undefined) return problem(res, mapped.status, mapped.code);
  if (outcome.reason === "ERR-CM-01") return notFound(res); // caso/propuesta ajena: 404 uniforme (no 409), sin oraculo
  if (outcome.reason.startsWith("ERR-")) return problem(res, 409, "INVALID_TRANSITION");
  notFound(res); // NOT_FOUND / STEP_UP: 404 uniforme
}

/** Devuelve true si la ruta fue atendida. El resto cae al 404 del proceso. */
export async function handleCaseRoute(req: IncomingMessage, res: ServerResponse, deps: CaseRoutesDeps): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://platform.invalid");
  const path = url.pathname;
  const proposals = PROPOSALS_RE.exec(path);
  const proposalAction = PROPOSAL_ACTION_RE.exec(path);
  const confirmation = CONFIRMATION_RE.exec(path);
  const close = CLOSE_RE.exec(path);
  if (proposals === null && proposalAction === null && confirmation === null && close === null) return false;
  if (req.method !== "POST" || url.search !== "") return notFound(res), true;
  const remote = req.socket.remoteAddress ?? "";
  if (deps.allowedCidrs.length > 0 && !ipInCidrs(remote, deps.allowedCidrs)) return notFound(res), true;
  if (deps.publicOrigin === undefined || req.headers.origin !== deps.publicOrigin) return notFound(res), true;
  const site = req.headers["sec-fetch-site"];
  if (site !== undefined && site !== "same-origin") return notFound(res), true;

  const caseRef = proposals?.[1] ?? proposalAction?.[1] ?? confirmation?.[1] ?? close?.[1] ?? "";
  const proposalRef = proposalAction?.[2] ?? "";
  const action = proposalAction?.[3];
  if (!CASE_REF_RE.test(caseRef) || (proposalAction !== null && !UUID_V4.test(proposalRef))) return notFound(res), true;
  // La aprobacion de RH2 usa la sesion PLATFORM (aprobador); el resto, la sesion CASE (operador).
  const kind: SessionKind = action === "approval" ? "PLATFORM" : "CASE";
  const sid = parseCookies(req.headers.cookie).get(kind === "PLATFORM" ? PLATFORM_SESSION_COOKIE : CASE_SESSION_COOKIE);
  if (sid === undefined || !SID_RE.test(sid)) return notFound(res), true;
  try {
    const session = await deps.sessions.validate({ sid, kind });
    if (session === null) return notFound(res), true;
    if (kind === "CASE" && session.caseRef !== caseRef) return notFound(res), true;
    if (!p50Allows(deps, session.principalRef)) return tooManyRequests(res), true;
    const body = (await readJsonBody(req)) ?? {};
    const limit = deps.p51;

    if (proposals !== null) {
      const ref = body.proposalRef;
      const v = body.verificationScriptVersion;
      if (!onlyKeys(body, ["proposalRef", "verificationScriptVersion"]) || typeof ref !== "string" || !UUID_V4.test(ref) || typeof v !== "string" || !SCRIPT_VERSION.test(v)) return problem(res, 409, "INVALID_TRANSITION"), true;
      reply(res, await deps.cases.propose({ sid, caseRef, proposalRef: ref, scriptVersion: v, limit }), () => ({ status: 201, body: { proposalRef: ref, attestation: "PENDING" } }));
      return true;
    }
    if (proposalAction !== null) {
      if (Object.keys(body).length !== 0) return problem(res, 409, "INVALID_TRANSITION"), true;
      if (action === "approval") {
        reply(res, await deps.cases.approve({ sid, caseRef, proposalRef, limit }), () => ({ status: 200, body: { attestation: "ATTESTED", revocationState: "VERIFIED" } }));
      } else {
        reply(res, await deps.cases.withdraw({ sid, caseRef, proposalRef, limit }), () => ({ status: 200, body: { proposalState: "WITHDRAWN", revocationState: "REQUESTED" } }));
      }
      return true;
    }
    if (confirmation !== null) {
      if (confirmation[2] === "/cosign") {
        if (Object.keys(body).length !== 0) return problem(res, 409, "INVALID_TRANSITION"), true;
        reply(res, await deps.cases.cosign({ sid, caseRef }), () => ({ status: 200, body: { cosign: "COSIGNED", revocationState: "APPLIED" } }));
      } else {
        if (!onlyKeys(body, ["confirmationGivenOnCasePage"]) || body.confirmationGivenOnCasePage !== true) return problem(res, 409, "INVALID_TRANSITION"), true;
        reply(res, await deps.cases.record({ sid, caseRef }), () => ({ status: 200, body: { cosign: "AWAITING_COSIGN", revocationState: "VERIFIED" } }));
      }
      return true;
    }
    const outcome = body.outcome;
    if (!onlyKeys(body, ["outcome"]) || (outcome !== "RESOLVED" && outcome !== "WITHDRAWN")) return problem(res, 409, "INVALID_TRANSITION"), true;
    reply(res, await deps.cases.close({ sid, caseRef, outcome }), () => ({ status: 200, body: { caseState: outcome } }));
    return true;
  } catch (error) {
    if (error instanceof RevocationApplyUnavailableError) {
      // G-3: agotados los reintentos de R3/RH3 + R4: error uniforme, SIN acuse de exito y sin texto para el titular (LEGAL DECISION F-PR6-25).
      res.writeHead(503, { ...COMMON, "content-type": "application/json" });
      res.end(JSON.stringify({ code: "GUARD_EVALUATOR_UNAVAILABLE", status: 503, correlationId: randomUUID() }));
      return true;
    }
    // PR-7a (F-PR7-10, T-10): indisponibilidad de la base = 503 uniforme (nunca "no existe"); el resto, fallo cerrado 404 sin detalle.
    if (isUnavailable(error)) return serviceUnavailable(res), true;
    return notFound(res), true; // fallo cerrado, sin detalle
  }
}
