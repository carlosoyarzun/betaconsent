// Gobierna: ADR-001 §11 (adaptadores solo importados por src/server/entrypoints/**). Único
// punto de cableado in-memory IT0 del flujo invitación -> OTP -> decisión sobre node:http
// puro (sin frameworks, sin dependencias nuevas), análogo a server.ts (RC2u).

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";

import { createInMemoryConsentDecisionRepository } from "../../../infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryEligibilityAdapter } from "../../../infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryInvitationRepository } from "../../../infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryOtpChannelSink } from "../../../infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import type { InMemoryOtpChannelSink } from "../../../infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { LECTORPRO_BETA_CONFIG } from "../../modules/consent-decision/lectorpro-beta.config.ts";
import type { DecisionRelationshipConfig } from "../../modules/consent-decision/decision-relationship.config.ts";
import type { Environment } from "../../modules/common/types.ts";
import type { InvitationPorts } from "../../modules/invitation/invitation.ts";
import type { OtpChallengePorts, OtpPolicy } from "../../modules/otp-challenge/otp-challenge.ts";
import type { ConsentDecisionPorts } from "../../modules/consent-decision/consent-decision.ts";
import { loadRightsCaseHttpConfig, type RightsCaseHttpConfig } from "./config.ts";
import {
  handleOpenInvitation,
  handleRecordDecisionStep,
  handleRedeemInvitationLink,
  handleRequestOtp,
  handleResendOtp,
  handleSubmitDecision,
  handleSubmitOtp,
  type ConsentFlowPorts,
  type HttpResult,
  type RawConsentRequest,
} from "./consent-flow.handler.ts";
import { parseCookies } from "./cookies.ts";
import { decodeSession } from "./consent-session.ts";
import { generateCsrfToken, serializeCsrfCookie } from "./csrf.ts";
import { renderWelcomePage, renderWelcomeUniformErrorPage } from "./welcome-page.ts";
import { renderVerifyPage, renderVerifyUniformErrorPage } from "./verify-page.ts";
import { renderDecisionPage, renderDecisionUniformErrorPage } from "./decision-page.ts";
import { resolveStaticAsset } from "./static-assets.ts";

export interface ConsentFlowHttpServerOptions {
  readonly config?: Partial<RightsCaseHttpConfig>;
  readonly ports?: ConsentFlowPorts;
  /** Secreto HMAC de la sesión (D5). Si se omite, se genera uno aleatorio por proceso (solo
   * válido mientras el proceso vive; nunca se persiste ni se loguea). */
  readonly sessionSecret?: Buffer;
  /** P-01/P-02/P-03 (otp-policy.config.ts); requerido si no se inyectan `ports` propios. */
  readonly otpPolicy?: OtpPolicy;
  /** GRD-CD-04 (decision-relationship.config.ts); requerido si no se inyectan `ports` propios. */
  readonly relationshipConfig?: DecisionRelationshipConfig;
  /**
   * Entorno de ejecución (GRD-CM-13). Solo cuando es exactamente "LOCAL" este servidor expone
   * GET /__dev/otp-sink (dev.ts, D4/D5 report a Carlos: sink de depuración, cero PII más allá
   * de la ya presente en el canal sintético de la invitación). Cualquier otro valor, incluido
   * "undefined", deja la ruta fuera (fail-closed).
   */
  readonly environment?: Environment;
}

/** `relationshipConfig` es obligatorio, mismo patrón fail-closed que `otpPolicy` (D4,
 * decision-relationship.config.ts): sin default de producción en esta función; el caller
 * (dev.ts LOCAL, o tests) siempre pasa un override explícito. */
export function createDefaultConsentFlowPorts(otpPolicy: OtpPolicy, relationshipConfig: DecisionRelationshipConfig): ConsentFlowPorts {
  const ledger = createInMemoryLedgerAdapter();
  const invitation: InvitationPorts = {
    invitationRepo: createInMemoryInvitationRepository(),
    eligibility: createInMemoryEligibilityAdapter(),
    ledger,
  };
  const otp: OtpChallengePorts = {
    otpRepo: createInMemoryOtpVerificationRepository(),
    channel: createInMemoryOtpChannelSink(),
    ledger,
    invitation,
    policy: otpPolicy,
    secret: randomBytes(32),
  };
  const decision: ConsentDecisionPorts = {
    repo: createInMemoryConsentDecisionRepository(),
    ledger,
    invitation,
    config: LECTORPRO_BETA_CONFIG,
    relationships: relationshipConfig,
  };
  return { invitation, otp, decision };
}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function serializeSessionCookie(config: RightsCaseHttpConfig, value: string): string {
  return `${config.sessionCookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

/** P1: contracts/openapi/consent-it0.openapi.yaml fija application/problem+json en
 * components.responses.CsrfRejected (403), components.responses.Problem (409/422 genérico) y
 * en el 422 de /otp/submit (OtpRejected); el resto (incluida UniformNotFound, 404) es
 * application/json. En los dos entrypoints de este repo (consent-flow-server.ts, server.ts)
 * los únicos usos de 403/409/422 son, precisamente, esos tres. */
function contentTypeForStatus(status: number): string {
  return status === 403 || status === 409 || status === 422 ? "application/problem+json" : "application/json";
}

/** Cabeceras de las páginas HTML servidas por este entrypoint (/welcome, /verify): CLAUDE.md
 * UX-CNS-001. CSP estricta sin scripts inline (todo el JS/CSS de la app va como estático bajo
 * /assets/**, static-assets.ts); `no-store` evita que un proxy/navegador cachee una pantalla
 * ligada a una sesión de un solo uso; `no-referrer` evita filtrar la URL a terceros. */
function writeHtmlSecurityHeaders(res: ServerResponse): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
}

function writeResult(res: ServerResponse, config: RightsCaseHttpConfig, result: HttpResult): void {
  if (result.setSessionCookie) {
    res.setHeader("Set-Cookie", serializeSessionCookie(config, result.setSessionCookie));
  }
  if (result.extraHeaders) {
    for (const [name, value] of Object.entries(result.extraHeaders)) {
      res.setHeader(name, value);
    }
  }
  if (result.location) {
    res.setHeader("Location", result.location);
  }
  res.writeHead(result.status, { "content-type": contentTypeForStatus(result.status) });
  res.end(JSON.stringify(result.body));
}

export function createConsentFlowHttpServer(options: ConsentFlowHttpServerOptions = {}): Server {
  const config = loadRightsCaseHttpConfig(options.config);
  const sessionSecret = options.sessionSecret ?? randomBytes(32);
  const ports =
    options.ports ??
    (() => {
      if (!options.otpPolicy || !options.relationshipConfig) {
        throw new Error(
          "createConsentFlowHttpServer requiere `ports` o ambos `otpPolicy` (D4, otp-policy.config.ts) y " +
            "`relationshipConfig` (GRD-CD-04, decision-relationship.config.ts).",
        );
      }
      return createDefaultConsentFlowPorts(options.otpPolicy, options.relationshipConfig);
    })();

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? "";
    const path = url.split("?", 1)[0] ?? "";

    if (req.method === "GET" && path.startsWith("/i/") && path.length > "/i/".length) {
      // API-CNS-101 (P-12): único GET de canje de este entrypoint IT0 (INV-CM-08, GRD-IV-07).
      let token: string | undefined;
      try {
        token = decodeURIComponent(path.slice("/i/".length));
      } catch {
        token = undefined;
      }
      const result = token ? handleRedeemInvitationLink(token, ports, sessionSecret) : { status: 404 as const, body: { status: 404 } };
      writeResult(res, config, result);
      return;
    }

    if (req.method === "GET" && path === "/welcome") {
      // UX-CNS-001: GET /welcome exige la sesión LANDING creada por GET /i/{token} (INV-CM-08:
      // esta ruta nunca transiciona nada, solo lee la sesión). Sin sesión válida, se sirve el
      // estado de error uniforme de la propia pantalla (INV-CM-05: sin distinguir causa), nunca
      // un 404 crudo del framework.
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderWelcomeUniformErrorPage());
        return;
      }
      // Cookie CSRF del double-submit (csrf.ts): legible por welcome.js, distinta de la cookie
      // de sesión (siempre HttpOnly).
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderWelcomePage());
      return;
    }

    if (req.method === "GET" && path === "/verify") {
      // UX-CNS-002: GET /verify exige la sesión con el OTP ya solicitado (V1, session.
      // verificationRef); sin ella, se sirve el estado de error uniforme de la propia pantalla
      // (INV-CM-05), nunca un 404 crudo (mismo patrón que /welcome).
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.verificationRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderVerifyUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderVerifyPage());
      return;
    }

    if (req.method === "GET" && path === "/decision") {
      // UX-CNS-003: GET /decision exige la sesión verificada (post-V3, session.decisionMakerRef);
      // sin ella, se sirve el estado de error uniforme de la propia pantalla (INV-CM-05), mismo
      // patrón que /welcome y /verify. verify.js redirige acá cuando /otp/submit responde 200.
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.verificationRef || !session.decisionMakerRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderDecisionUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderDecisionPage(ports.decision.relationships.allowedRelationshipRefs));
      return;
    }

    if (req.method === "GET" && path.startsWith("/assets/")) {
      // Lista blanca cerrada (static-assets.ts): el lookup es por igualdad exacta, nunca por
      // join de filesystem, así que un intento de traversal (`../`, codificado o no) nunca
      // resuelve a una entrada y cae directo al 404 de abajo.
      let decodedPath: string | undefined;
      try {
        decodedPath = decodeURIComponent(path);
      } catch {
        decodedPath = undefined;
      }
      const asset = decodedPath ? resolveStaticAsset(decodedPath) : null;
      if (!asset) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
      }
      res.writeHead(200, { "content-type": asset.contentType, "cache-control": "no-store" });
      res.end(asset.content);
      return;
    }

    if (req.method === "GET" && path === "/__dev/otp-sink") {
      if (options.environment !== "LOCAL") {
        // Fail-closed (GRD-CM-13): fuera de LOCAL esta ruta no existe, ni siquiera como 403.
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
      }
      const sink = ports.otp.channel as InMemoryOtpChannelSink;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ sent: sink.sent }));
      return;
    }

    if (req.method !== "POST") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: 404 }));
      return;
    }

    const body = await readBody(req);
    const request: RawConsentRequest = {
      originHeader: headerValue(req.headers.origin),
      csrfHeaderToken: headerValue(req.headers[config.csrfHeaderName]),
      cookieHeader: headerValue(req.headers.cookie),
      body,
    };

    let result: HttpResult;
    switch (path) {
      case "/invitation/open":
        result = handleOpenInvitation(request, ports, config, sessionSecret);
        break;
      case "/otp/request":
        result = handleRequestOtp(request, ports, config, sessionSecret);
        break;
      case "/otp/resend":
        result = handleResendOtp(request, ports, config, sessionSecret);
        break;
      case "/otp/submit":
        result = handleSubmitOtp(request, ports, config, sessionSecret);
        break;
      case "/decision/steps":
        result = handleRecordDecisionStep(request, ports, config, sessionSecret);
        break;
      case "/decision/submit":
        result = handleSubmitDecision(request, ports, config, sessionSecret);
        break;
      default:
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
    }
    writeResult(res, config, result);
  });
}
