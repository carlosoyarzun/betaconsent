// Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19), plan v2 H1-05 (HTTP del apoderado) y H1-07 (revocación por HTTP).
// Contrato de formas y códigos: contracts/openapi/consent-it0.openapi.yaml + contracts/schemas/{api-payloads,common}.schema.json (cotejado con el contrato, no con los tests del origen).
// origen (ideas y tablas): src/server/entrypoints/http/consent-flow-server.ts@9345b78 (L739-985 + POST: canje 303 sin BD, páginas con 404 uniforme, CSRF double-submit),
// consent-flow.handler.ts@9345b78 (códigos externos, UniformAccepted, problem()) y revocation-flow.handler.ts@9345b78 (flujo MANAGE -> REVOCATION -> confirm).
// Se reescribe sobre los puertos de H1-04: no hay tenant-context, step-up, rights-case ni staff.
//
// Un solo proceso, node:http, sin frameworks. `createApp` es una función pura de dependencias (puertos, mailer, lookup de destinatario, outbox): los tests la corren con
// adaptadores en memoria y con PostgreSQL real.
//
// DESVIACIONES / DECISIONES PENDIENTES (reportadas):
//  - D-1 Enlace de gestión /m/{token}: la base NO tiene tabla ni función de tokens de gestión (0002/0003). Se usa un token SIN ESTADO firmado (HMAC, HKDF de CNS_SESSION_SECRET) que
//    lleva el consentId y un vencimiento (30 días, BORRADOR). No se puede rotar ni invalidar individualmente (solo cambiando CNS_SESSION_SECRET) y no consume nada. El token solo da
//    derecho a PEDIR un OTP al correo ligado: la autoridad sigue siendo el OTP. Requiere decisión de arquitectura (ADR) antes de datos reales.
//  - D-2 /decision/subject-mismatch: no existe función SQL de cancelación (I9) => 501 sin efecto.
//  - D-3 Estados REQUESTED/VERIFIED de la revocación viven SOLO en la sesión firmada (la base registra la revocación ya APPLIED en revoke_decision): los ack de /manage/revocation y
//    /verify no llevan revocationRef (no existe todavía); el de /confirm sí.
//  - D-4 Los pasos de /decision/steps viven en la sesión (no hay tabla de pasos): son coherencia de UX, no evidencia.
//  - D-5 OTP_LOCKED y presupuesto agotado responden 422 (OtpRejected.status const 422 en el contrato; ORIGEN.md/encargo decían 423/409).

import { createHash, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import { deriveDecisionMakerRef } from "../domain/crypto.ts";
import { isDomainError } from "../domain/errors.ts";
import type { DomainErrorCode } from "../domain/errors.ts";
import { receiptRefFor } from "../domain/receipt.ts";
import type { Config } from "../config.ts";
import { ALLOWED_RELATIONSHIP_REFS, getServedConsentVersion, REQUIRED_PURPOSES } from "../consent/served-consent-version.ts";
import type { Mailer } from "../mail/mailer.port.ts";
import { OtpSendError, OtpSuppressedError, sendOtpNow } from "../mail/otp.ts";
import type { RecipientPolicy } from "../mail/recipient-policy.ts";
import type { Ports } from "../ports/index.ts";
import { parseCookies } from "./cookies.ts";
import {
  boundToken, createCodecs, handlePrefix, hashLinkToken, HANDLE_TTL_SECONDS, MANAGE_TOKEN_TTL_SECONDS, SESSION_TTL_SECONDS, verifyManageToken,
} from "./handles.ts";
import type { Session } from "./handles.ts";
import {
  CSRF_COOKIE, CSRF_HEADER, generateCsrfToken, INVITATION_HANDLE_COOKIE, MANAGE_HANDLE_COOKIE, safeEqual, securityHeaders, serializeClearCookie,
  serializeCsrfCookie, serializeHttpOnlyCookie, SESSION_COOKIE,
} from "./http-security.ts";
import type { Logger } from "./log.ts";
import { normalizeRoute } from "./log.ts";
import type { RecipientLookup } from "./recipients.ts";
import type { SpaBundle } from "./spa-assets.ts";

export const MAX_BODY_BYTES = 16 * 1024;

export interface OutboxEnqueuer {
  enqueue(input: { kind: "RECOVERY_LINK"; invitationRef: string; dedupeKey: string; payload: Record<string, unknown> }): Promise<void>;
}

export interface AppDeps {
  readonly config: Pick<Config, "publicOrigin" | "sessionSecret" | "environment">;
  readonly ports: Ports;
  readonly recipients: RecipientLookup;
  readonly mailer: Mailer;
  readonly policy: RecipientPolicy;
  readonly outbox: OutboxEnqueuer;
  readonly spa: SpaBundle;
  readonly logger: Logger;
  /** SELECT 1 contra la base (GET /healthz). */
  readonly checkHealth: () => Promise<void>;
}

export interface App {
  handle(req: IncomingMessage, res: ServerResponse): Promise<void>;
}

const HTML_ROUTES = new Set(["/welcome", "/verify", "/decision", "/manage", "/manage/verify", "/manage/revocation/verify", "/manage/revocation/confirm", "/recovery/confirm"]);
const DECISION_STEPS = ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"] as const;

interface Reply {
  status: number;
  body?: unknown;
  html?: string;
  location?: string;
  cookies?: string[];
}

const uniform404 = (): Reply => ({ status: 404, body: { status: 404 } });
const problem = (status: number, code: string): Reply => ({ status, body: { code, status, correlationId: randomUUID() }, });
const accepted = (): Reply => ({ status: 202, body: { result: "RECEIVED" } });

class BodyTooLarge extends Error {}
class BadBody extends Error {}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const b = chunk as Buffer;
    size += b.length;
    if (size > MAX_BODY_BYTES) throw new BodyTooLarge();
    chunks.push(b);
  }
  if (size === 0) return {};
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new BadBody();
    return parsed as Record<string, unknown>;
  } catch {
    throw new BadBody();
  }
}

const header = (req: IncomingMessage, name: string): string | undefined => {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
};

export function createApp(deps: AppDeps): App {
  const { config, ports, logger } = deps;
  const codecs = createCodecs(config.sessionSecret);
  const secure = (): string[] => [];
  void secure;

  // ---------------------------------------------------------------- contexto de la petición
  interface Ctx {
    readonly cookies: Record<string, string>;
    readonly now: number;
  }
  const nowSeconds = (): number => Math.floor(Date.now() / 1000);

  /** Sesión válida del tipo pedido Y ligada al handle vigente ("el último enlace abierto manda"). */
  function sessionFor(ctx: Ctx, kind: "D" | "M"): Session | null {
    const s = codecs.session.decode(ctx.cookies[SESSION_COOKIE]);
    if (!s || s.k !== kind) return null;
    const hp = currentHandlePrefix(ctx, kind);
    return hp !== null && hp === s.hp ? s : null;
  }

  function currentHandlePrefix(ctx: Ctx, kind: "D" | "M"): string | null {
    if (kind === "D") {
      const h = codecs.invitation.decode(ctx.cookies[INVITATION_HANDLE_COOKIE]);
      return h ? handlePrefix(h.h) : null;
    }
    const h = codecs.manage.decode(ctx.cookies[MANAGE_HANDLE_COOKIE]);
    return h ? handlePrefix(createHash("sha256").update(h.t).digest("hex")) : null;
  }

  const sessionCookie = (s: Omit<Session, "exp">): string =>
    serializeHttpOnlyCookie(SESSION_COOKIE, codecs.session.encode({ ...s, exp: nowSeconds() + SESSION_TTL_SECONDS }), SESSION_TTL_SECONDS);

  /** consentId del handle de gestión (verifica la firma del token), o null. */
  function manageConsentId(ctx: Ctx): string | null {
    const h = codecs.manage.decode(ctx.cookies[MANAGE_HANDLE_COOKIE]);
    return h ? verifyManageToken(config.sessionSecret, h.t) : null;
  }

  // ---------------------------------------------------------------- páginas (shell SPA)
  async function pageReady(route: string, ctx: Ctx): Promise<boolean> {
    switch (route) {
      case "/welcome":
        return codecs.invitation.decode(ctx.cookies[INVITATION_HANDLE_COOKIE]) !== null;
      case "/verify": {
        const s = sessionFor(ctx, "D");
        return s?.ver !== undefined && s.sc === "DECISION";
      }
      case "/decision": {
        const s = sessionFor(ctx, "D");
        return s?.vok === true && s.inv !== undefined && (await decisionContext(s)) !== null;
      }
      case "/manage": {
        const con = manageConsentId(ctx);
        if (!con) return false;
        const ms = await ports.revocations.getManageState(con);
        return ms !== null && ms.state !== "DECLINED";
      }
      case "/manage/verify": {
        const s = sessionFor(ctx, "M");
        return s?.ver !== undefined && s.sc === "MANAGE";
      }
      case "/manage/revocation/verify": {
        const s = sessionFor(ctx, "M");
        return s?.rq === true && s.ver !== undefined && s.sc === "REVOCATION";
      }
      case "/manage/revocation/confirm": {
        const s = sessionFor(ctx, "M");
        return s?.rq === true && s.vok === true && s.sc === "REVOCATION";
      }
      default:
        return false; // /recovery/confirm: recuperación es H2-01 (404 uniforme)
    }
  }

  async function pageReply(route: string, ctx: Ctx): Promise<Reply> {
    const ready = await pageReady(route, ctx);
    return ready
      ? { status: 200, html: deps.spa.indexReady, cookies: [serializeCsrfCookie(generateCsrfToken())] }
      : { status: 404, html: deps.spa.indexUniformError, cookies: [serializeCsrfCookie(generateCsrfToken())] };
  }

  // ---------------------------------------------------------------- GET
  async function get(pathname: string, ctx: Ctx): Promise<Reply> {
    if (pathname === "/healthz") {
      try {
        await deps.checkHealth();
        return { status: 200, body: { status: "ok" } };
      } catch {
        return { status: 503, body: { status: "unavailable" } };
      }
    }
    if (pathname.startsWith("/assets/")) {
      return uniform404(); // los assets se resuelven antes (ver handle); aquí solo los inexistentes
    }

    // Canje 303: SIEMPRE el mismo resultado, sin leer la BD y sin consumir el token (F-RB-02): escáneres de buzón y apoderado dan lo mismo.
    const redeem = /^\/(i|m|r)\/([^/]+)$/.exec(pathname);
    if (redeem) {
      const kind = redeem[1];
      let token: string;
      try {
        token = decodeURIComponent(redeem[2] ?? "");
      } catch {
        token = redeem[2] ?? "";
      }
      if (kind === "i") {
        const handle = codecs.invitation.encode({ h: hashLinkToken(token), exp: nowSeconds() + HANDLE_TTL_SECONDS });
        return { status: 303, location: "/welcome", cookies: [serializeHttpOnlyCookie(INVITATION_HANDLE_COOKIE, handle, HANDLE_TTL_SECONDS), serializeClearCookie(SESSION_COOKIE)] };
      }
      if (kind === "m") {
        const handle = codecs.manage.encode({ t: boundToken(token), exp: nowSeconds() + HANDLE_TTL_SECONDS });
        return { status: 303, location: "/manage", cookies: [serializeHttpOnlyCookie(MANAGE_HANDLE_COOKIE, handle, HANDLE_TTL_SECONDS), serializeClearCookie(SESSION_COOKIE)] };
      }
      return { status: 404, html: deps.spa.indexUniformError }; // /r/: recuperación es H2-01
    }

    if (HTML_ROUTES.has(pathname)) return pageReply(pathname, ctx);

    if (pathname === "/decision/page-state") {
      const s = sessionFor(ctx, "D");
      if (!s?.vok || !s.inv || (await decisionContext(s)) === null) return uniform404();
      const v = getServedConsentVersion();
      return {
        status: 200,
        body: { relationshipRefs: [...ALLOWED_RELATIONSHIP_REFS], servedVersion: { consentVersion: v.consentVersion, privacyNoticeVersion: v.privacyNoticeVersion, text: v.text } },
      };
    }

    if (pathname === "/manage/page-state") {
      const con = manageConsentId(ctx);
      const hp = currentHandlePrefix(ctx, "M");
      if (!con || hp === null) return uniform404();
      const ms = await ports.revocations.getManageState(con);
      if (!ms || ms.state === "DECLINED") return uniform404();
      const existing = sessionFor(ctx, "M");
      const cookies: string[] = [];
      let s = existing;
      if (!s) {
        s = { k: "M", hp, exp: 0, con };
        cookies.push(sessionCookie({ k: "M", hp, con }));
      }
      const variant = ms.state === "REVOKED" ? "revoked" : s.vok === true && s.sc === "MANAGE" ? "status" : "entry";
      return { status: 200, body: { variant }, cookies };
    }

    return uniform404();
  }

  /** Contexto de decisión: la invitación debe estar VERIFIED y sin decisión. */
  async function decisionContext(s: Session): Promise<{ invitationRef: string } | null> {
    if (!s.inv) return null;
    const ps = await ports.decisions.getPageState(s.inv);
    return ps && ps.invitationState === "VERIFIED" && ps.decision === null ? { invitationRef: s.inv } : null;
  }

  // ---------------------------------------------------------------- POST
  const otpScope = (s: Session): "DECISION" | "MANAGE" | "REVOCATION" => (s.k === "D" ? "DECISION" : s.rq === true ? "REVOCATION" : "MANAGE");
  const parentOf = (s: Session): string | undefined => (s.k === "D" ? s.inv : s.con);

  /** Emite (o reemite) el OTP y lo envía síncrono: el código nunca pasa por el outbox, el log ni la sesión. */
  async function issueAndSend(ctx: Ctx, mode: "request" | "resend"): Promise<Reply> {
    const kind: "D" | "M" = codecs.session.decode(ctx.cookies[SESSION_COOKIE])?.k ?? "D";
    const s = sessionFor(ctx, kind);
    if (!s) return uniform404();
    const parent = parentOf(s);
    if (!parent) return uniform404();
    if (mode === "resend" && !s.ver) return uniform404();
    const scope = otpScope(s);
    const to = s.k === "D" ? await deps.recipients.forInvitation(parent) : await deps.recipients.forConsent(parent);
    if (!to) return uniform404();
    let issued;
    try {
      issued = await (mode === "resend" ? ports.otp.resend : ports.otp.issue)({ parentRef: parent, scope });
    } catch (e) {
      if (isDomainError(e)) {
        switch (e.code) {
          case "PARENT_NOT_ELIGIBLE":
          case "INVITATION_NOT_FOUND":
            return uniform404();
          case "OTP_RESEND_TOO_SOON":
          case "OTP_SEND_LIMIT":
            // request: respuesta uniforme (el código vigente sigue valiendo); resend: límite explícito (la SPA muestra "resend-limit").
            return mode === "resend" ? problem(409, "OTP_RESEND_LIMIT") : accepted();
          case "OTP_BUDGET_EXHAUSTED":
          case "OTP_EXHAUSTED":
            return problem(422, scope === "DECISION" ? "OTP_BUDGET_EXHAUSTED_DECISION" : "OTP_BUDGET_EXHAUSTED_RIGHTS");
          default:
            throw e;
        }
      }
      throw e;
    }
    try {
      await sendOtpNow(deps.mailer, to, issued.code, { policy: deps.policy });
    } catch (e) {
      if (e instanceof OtpSuppressedError) {
        logger.info("otp: destinatario suprimido por allowlist", { scope });
      } else if (e instanceof OtpSendError) {
        logger.warn("otp: fallo de envío", { scope, code: "OTP_SEND_ERROR" });
        return { status: 503, body: { status: 503, correlationId: randomUUID() } };
      } else {
        throw e;
      }
    }
    return { ...accepted(), cookies: [sessionCookie({ ...strip(s), ver: issued.verificationRef, sc: scope })] };
  }

  const strip = (s: Session): Omit<Session, "exp"> => {
    const { exp: _exp, ...rest } = s;
    void _exp;
    return rest;
  };

  async function post(pathname: string, body: Record<string, unknown>, ctx: Ctx): Promise<Reply> {
    switch (pathname) {
      case "/invitation/open": {
        const handle = codecs.invitation.decode(ctx.cookies[INVITATION_HANDLE_COOKIE]);
        if (!handle) return uniform404();
        const opened = await ports.invitations.openByTokenHash(handle.h);
        if (!opened) return uniform404();
        const hp = handlePrefix(handle.h);
        const existing = sessionFor(ctx, "D");
        // Reabrir no reinicia una sesión ya ligada a la misma invitación (conserva OTP y pasos).
        const base: Omit<Session, "exp"> = existing?.inv === opened.invitationRef ? strip(existing) : { k: "D", hp, inv: opened.invitationRef };
        return { status: 200, body: { result: "OPENED" }, cookies: [sessionCookie(base)] };
      }

      case "/otp/request":
        return issueAndSend(ctx, "request");
      case "/otp/resend":
        return issueAndSend(ctx, "resend");

      case "/otp/submit":
        return submitOtp(body, ctx);

      case "/decision/steps":
        return decisionStep(body, ctx);
      case "/decision/submit":
        return decisionSubmit(body, ctx);
      case "/decision/subject-mismatch": {
        const s = sessionFor(ctx, "D");
        if (!s?.vok) return uniform404();
        return problem(501, "TRANSITION_DISABLED_IN_CONTEXT"); // D-2: sin función SQL de cancelación (I9)
      }

      case "/manage/revocation":
        return manageRequestRevocation(ctx);
      case "/manage/revocation/verify": {
        const s = sessionFor(ctx, "M");
        if (!s?.rq || !s.vok || s.sc !== "REVOCATION") return uniform404();
        return { status: 200, body: { state: "VERIFIED" } }; // R2: la verificación ya ocurrió en /otp/submit (idempotente)
      }
      case "/manage/revocation/confirm":
        return manageConfirm(ctx);
      case "/manage/revocation/withdraw":
        return manageWithdraw(ctx);

      // H2-01: recuperación sin efecto en H1 (respuesta uniforme, sin enlace ni evento).
      case "/manage/recovery-link":
        return accepted();
      case "/recovery/revoke":
        return uniform404();

      default:
        return uniform404();
    }
  }

  async function submitOtp(body: Record<string, unknown>, ctx: Ctx): Promise<Reply> {
    const kind: "D" | "M" = codecs.session.decode(ctx.cookies[SESSION_COOKIE])?.k ?? "D";
    const s = sessionFor(ctx, kind);
    if (!s?.ver || !s.sc || s.vok) return uniform404();
    const code = typeof body.code === "string" && /^[0-9A-Za-z]{1,16}$/.test(body.code) ? body.code : null;
    if (code === null) return problem(422, "OTP_CODE_REJECTED");
    let decisionMakerRef: string;
    if (s.k === "D") {
      const to = s.inv ? await deps.recipients.forInvitation(s.inv) : null;
      if (!to) return uniform404();
      decisionMakerRef = deriveDecisionMakerRef(config.sessionSecret, to);
    } else {
      // El OTP de gestión/revocación se verifica con el seudónimo que quedó en la decisión (revoke_decision exige igualdad).
      const ms = s.con ? await ports.revocations.getManageState(s.con) : null;
      if (!ms) return uniform404();
      decisionMakerRef = ms.decisionMakerRef;
    }
    const result = await ports.otp.verify({ verificationRef: s.ver, code, decisionMakerRef });
    const rights = s.sc !== "DECISION";
    switch (result.outcome) {
      case "VERIFIED":
        return { status: 200, body: { result: "VERIFIED", scope: s.sc }, cookies: [sessionCookie({ ...strip(s), vok: true })] };
      case "WRONG_CODE":
        return problem(422, "OTP_CODE_REJECTED");
      case "LOCKED":
        return problem(422, "OTP_LOCKED");
      case "EXPIRED":
      case "NOT_ACTIVE":
        return problem(422, "OTP_EXPIRED_OR_CONSUMED");
      case "BUDGET_EXHAUSTED":
        return problem(422, rights ? "OTP_BUDGET_EXHAUSTED_RIGHTS" : "OTP_BUDGET_EXHAUSTED_DECISION");
    }
  }

  async function decisionStep(body: Record<string, unknown>, ctx: Ctx): Promise<Reply> {
    const s = sessionFor(ctx, "D");
    if (!s?.vok || (await decisionContext(s)) === null) return uniform404();
    const kind = body.stepKind;
    if (typeof kind !== "string" || !(DECISION_STEPS as readonly string[]).includes(kind)) return problem(422, "DECISION_STEPS_INCOMPLETE");
    let rel = s.rel;
    if (kind === "DECISION_MAKER_AUTHORITY_DECLARED") {
      if (body.authorityDeclared !== true || typeof body.relationshipRef !== "string" || !ALLOWED_RELATIONSHIP_REFS.includes(body.relationshipRef)) return problem(422, "DECISION_STEPS_INCOMPLETE");
      rel = body.relationshipRef;
    }
    if (kind === "SUBJECT_CONFIRMED" && body.subjectConfirmed !== true) return problem(422, "DECISION_STEPS_INCOMPLETE");
    const steps = [...new Set([...(s.steps ?? []), kind])];
    const out: Record<string, unknown> = { stepKind: kind, state: "PENDING" };
    if (kind === "CONSENT_VERSION_VIEWED") {
      const v = getServedConsentVersion();
      out.servedVersion = { consentVersion: v.consentVersion, privacyNoticeVersion: v.privacyNoticeVersion, text: v.text };
    }
    return { status: 200, body: out, cookies: [sessionCookie({ ...strip(s), steps, ...(rel !== undefined ? { rel } : {}) })] };
  }

  async function decisionSubmit(body: Record<string, unknown>, ctx: Ctx): Promise<Reply> {
    const s = sessionFor(ctx, "D");
    if (!s?.vok || !s.inv || !s.ver) return uniform404();
    const ps = await ports.decisions.getPageState(s.inv);
    // Un reintento de una decisión ya tomada (misma clave) debe devolver lo mismo: se deja pasar a record() si ya hay decisión.
    if (!ps || (ps.invitationState !== "VERIFIED" && ps.decision === null)) return uniform404();
    if (!DECISION_STEPS.every((k) => s.steps?.includes(k))) return problem(422, "DECISION_STEPS_INCOMPLETE");
    const choices = parsePurposeChoices(body.purposes);
    if (!choices) return problem(422, "PURPOSE_SELECTION_INVALID");
    const outcome = choices.every((c) => c.choice === "GRANT") ? "GRANTED" : "DECLINED";
    const granted = choices.filter((c) => c.choice === "GRANT").map((c) => c.purpose);
    const served = getServedConsentVersion();
    let rec;
    try {
      rec = await ports.decisions.record({
        invitationRef: s.inv,
        verificationRef: s.ver,
        outcome,
        consentVersion: served.consentVersion,
        consentTextHash: served.consentTextHash,
        idempotencyKey: `dec:${s.inv}:${s.ver}`,
        purposes: granted,
      });
    } catch (e) {
      if (isDomainError(e)) return mapDecisionError(e.code);
      throw e;
    }
    if (rec.state === "GRANTED" && !rec.deduped) {
      // Enlace de gestión por correo (outbox, sin token en la tabla: lo arma el worker). Un fallo aquí no revierte la decisión (queda registrado).
      try {
        await deps.outbox.enqueue({ kind: "RECOVERY_LINK", invitationRef: s.inv, dedupeKey: `mgmt-link:${rec.consentId}`, payload: { consentId: rec.consentId, purpose: "MANAGE" } });
      } catch {
        logger.warn("outbox: no se encoló el enlace de gestión", { code: "ENQUEUE_FAILED" });
      }
    }
    return { status: 200, body: { consentId: rec.consentId, state: rec.state, receiptRef: receiptRefFor(rec.consentId) } };
  }

  function mapDecisionError(code: DomainErrorCode): Reply {
    switch (code) {
      case "ALREADY_DECIDED":
        return problem(409, "ALREADY_DECIDED");
      case "INVALID_PURPOSES":
        return problem(422, "PURPOSE_SELECTION_INVALID");
      case "IDEMPOTENCY_KEY_REUSED":
        return problem(409, "IDEMPOTENCY_CONFLICT");
      default:
        return uniform404(); // VERIFICATION_REQUIRED, INVITATION_NOT_FOUND, ...
    }
  }

  function parsePurposeChoices(raw: unknown): { purpose: string; choice: "GRANT" | "DECLINE" }[] | null {
    if (!Array.isArray(raw) || raw.length !== REQUIRED_PURPOSES.length) return null;
    const out: { purpose: string; choice: "GRANT" | "DECLINE" }[] = [];
    for (const x of raw) {
      const o = x as { purpose?: unknown; choice?: unknown } | null;
      if (typeof o?.purpose !== "string" || (o.choice !== "GRANT" && o.choice !== "DECLINE")) return null;
      out.push({ purpose: o.purpose, choice: o.choice });
    }
    return new Set(out.map((c) => c.purpose)).size === REQUIRED_PURPOSES.length && REQUIRED_PURPOSES.every((p) => out.some((c) => c.purpose === p)) ? out : null;
  }

  // ---- revocación (H1-07)
  async function manageState(s: Session) {
    return s.con ? ports.revocations.getManageState(s.con) : null;
  }

  async function manageRequestRevocation(ctx: Ctx): Promise<Reply> {
    const s = sessionFor(ctx, "M");
    if (!s) return uniform404();
    const ms = await manageState(s);
    if (!ms || ms.state === "DECLINED") return uniform404();
    if (ms.state === "REVOKED") return problem(409, "INVALID_TRANSITION");
    // R1: la solicitud explícita vive en la sesión (D-3). Se descarta cualquier OTP MANAGE previo: la revocación exige un OTP fresco de scope REVOCATION.
    const { ver: _v, sc: _s, vok: _o, ...rest } = strip(s);
    void _v; void _s; void _o;
    return { status: 200, body: { state: "REQUESTED" }, cookies: [sessionCookie({ ...rest, rq: true })] };
  }

  async function manageConfirm(ctx: Ctx): Promise<Reply> {
    const s = sessionFor(ctx, "M");
    if (!s?.rq || !s.vok || s.sc !== "REVOCATION" || !s.con || !s.ver) return uniform404();
    try {
      // Clave de idempotencia derivada de la sesión (consentId + OTP verificado): doble confirm => misma revocación.
      const r = await ports.revocations.revoke({ consentId: s.con, verificationRef: s.ver, idempotencyKey: `rev:${s.con}:${s.ver}` });
      return { status: 200, body: { revocationRef: r.revocationRef, state: "CONFIRMED" } };
    } catch (e) {
      if (isDomainError(e)) {
        switch (e.code) {
          case "ALREADY_REVOKED":
            return problem(409, "INVALID_TRANSITION");
          case "IDEMPOTENCY_KEY_REUSED":
            return problem(409, "IDEMPOTENCY_CONFLICT");
          default:
            return uniform404(); // VERIFICATION_REQUIRED, NOT_REVOCABLE_DECLINED, DECISION_NOT_FOUND
        }
      }
      logger.error("revocation: confirm falló", { code: errorCode(e) });
      return problem(503, "GUARD_EVALUATOR_UNAVAILABLE"); // sin acuse de éxito (contrato G-3)
    }
  }

  async function manageWithdraw(ctx: Ctx): Promise<Reply> {
    const s = sessionFor(ctx, "M");
    if (!s?.rq) return uniform404();
    const ms = await manageState(s);
    if (!ms) return uniform404();
    if (ms.state === "REVOKED") return problem(409, "INVALID_TRANSITION"); // ya confirmada: no se puede retirar la solicitud
    const { ver: _v, sc: _s, vok: _o, rq: _r, ...rest } = strip(s);
    void _v; void _s; void _o; void _r;
    return { status: 200, body: { state: "FAILED" }, cookies: [sessionCookie(rest)] };
  }

  // ---------------------------------------------------------------- transporte
  function errorCode(e: unknown): string {
    const c = (e as { code?: unknown } | null)?.code;
    return typeof c === "string" && /^[A-Za-z0-9_]{1,40}$/.test(c) ? c : (e as { name?: unknown } | null)?.name === "string" ? String((e as { name: string }).name).slice(0, 40) : "ERROR";
  }

  function csrfOk(req: IncomingMessage, ctx: Ctx): boolean {
    const origin = header(req, "origin");
    if (origin !== config.publicOrigin) return false; // fail-closed: el navegador siempre envía Origin en POST same-origin
    return safeEqual(ctx.cookies[CSRF_COOKIE], header(req, CSRF_HEADER));
  }

  function write(res: ServerResponse, reply: Reply, requestId: string): void {
    const headers: Record<string, string | string[]> = { ...securityHeaders(), "x-request-id": requestId };
    if (reply.location) headers.location = reply.location;
    if (reply.cookies && reply.cookies.length > 0) headers["set-cookie"] = reply.cookies;
    let payload: string | Buffer = "";
    if (reply.html !== undefined) {
      headers["content-type"] = "text/html; charset=utf-8";
      payload = reply.html;
    } else if (reply.body !== undefined) {
      headers["content-type"] = reply.status >= 400 && reply.status !== 404 ? "application/problem+json; charset=utf-8" : "application/json; charset=utf-8";
      payload = JSON.stringify(reply.body);
    }
    headers["content-length"] = String(Buffer.byteLength(payload));
    res.writeHead(reply.status, headers);
    res.end(payload);
  }

  async function dispatch(req: IncomingMessage, res: ServerResponse, requestId: string): Promise<number> {
    const method = req.method ?? "GET";
    // Solo el pathname: la query nunca se interpreta ni se registra.
    const pathname = (req.url ?? "/").split("?")[0] ?? "/";
    const ctx: Ctx = { cookies: parseCookies(header(req, "cookie")), now: Date.now() };
    let reply: Reply;
    try {
      if (method === "GET" || method === "HEAD") {
        const asset = pathname.startsWith("/assets/") ? deps.spa.assets.get(pathname) : undefined;
        if (asset) {
          res.writeHead(200, {
            "content-type": asset.contentType,
            "cache-control": "public, max-age=31536000, immutable",
            "x-content-type-options": "nosniff",
            "content-length": String(asset.content.length),
            "x-request-id": requestId,
          });
          res.end(method === "HEAD" ? undefined : asset.content);
          return 200;
        }
        reply = await get(pathname, ctx);
      } else if (method === "POST") {
        let body: Record<string, unknown>;
        try {
          body = await readBody(req);
        } catch (e) {
          reply = e instanceof BodyTooLarge ? problem(413, "CSRF_REJECTED") : problem(400, "CSRF_REJECTED");
          reply = e instanceof BodyTooLarge ? { status: 413, body: { status: 413, correlationId: randomUUID() } } : { status: 400, body: { status: 400, correlationId: randomUUID() } };
          if (e instanceof BodyTooLarge) res.setHeader("connection", "close");
          write(res, reply, requestId);
          return reply.status;
        }
        reply = csrfOk(req, ctx) ? await post(pathname, body, ctx) : problem(403, "CSRF_REJECTED");
      } else {
        reply = { status: 405, body: { status: 405, correlationId: randomUUID() } };
      }
    } catch (e) {
      logger.error("request: error no controlado", { code: errorCode(e) });
      reply = { status: 500, body: { status: 500, correlationId: randomUUID() } };
    }
    write(res, reply, requestId);
    return reply.status;
  }

  return {
    async handle(req, res) {
      const started = process.hrtime.bigint();
      const requestId = randomUUID();
      const pathname = (req.url ?? "/").split("?")[0] ?? "/";
      let status = 500;
      try {
        status = await dispatch(req, res, requestId);
      } finally {
        logger.info("request", {
          method: (req.method ?? "GET").slice(0, 8),
          route: normalizeRoute(pathname),
          status,
          ms: Number((process.hrtime.bigint() - started) / 1_000_000n),
          requestId,
        });
      }
    },
  };
}

export { MANAGE_TOKEN_TTL_SECONDS };
