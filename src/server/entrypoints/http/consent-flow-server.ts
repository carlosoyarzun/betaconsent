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
import type { Environment } from "../../modules/common/types.ts";
import type { InvitationPorts } from "../../modules/invitation/invitation.ts";
import type { OtpChallengePorts, OtpPolicy } from "../../modules/otp-challenge/otp-challenge.ts";
import type { ConsentDecisionPorts } from "../../modules/consent-decision/consent-decision.ts";
import { loadRightsCaseHttpConfig, type RightsCaseHttpConfig } from "./config.ts";
import {
  handleOpenInvitation,
  handleRedeemInvitationLink,
  handleRequestOtp,
  handleSubmitDecision,
  handleSubmitOtp,
  type ConsentFlowPorts,
  type HttpResult,
  type RawConsentRequest,
} from "./consent-flow.handler.ts";

export interface ConsentFlowHttpServerOptions {
  readonly config?: Partial<RightsCaseHttpConfig>;
  readonly ports?: ConsentFlowPorts;
  /** Secreto HMAC de la sesión (D5). Si se omite, se genera uno aleatorio por proceso (solo
   * válido mientras el proceso vive; nunca se persiste ni se loguea). */
  readonly sessionSecret?: Buffer;
  /** P-01/P-02/P-03 (otp-policy.config.ts); requerido si no se inyectan `ports` propios. */
  readonly otpPolicy?: OtpPolicy;
  /**
   * Entorno de ejecución (GRD-CM-13). Solo cuando es exactamente "LOCAL" este servidor expone
   * GET /__dev/otp-sink (dev.ts, D4/D5 report a Carlos: sink de depuración, cero PII más allá
   * de la ya presente en el canal sintético de la invitación). Cualquier otro valor, incluido
   * "undefined", deja la ruta fuera (fail-closed).
   */
  readonly environment?: Environment;
}

export function createDefaultConsentFlowPorts(otpPolicy: OtpPolicy): ConsentFlowPorts {
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
  res.writeHead(result.status, { "content-type": "application/json" });
  res.end(JSON.stringify(result.body));
}

export function createConsentFlowHttpServer(options: ConsentFlowHttpServerOptions = {}): Server {
  const config = loadRightsCaseHttpConfig(options.config);
  const sessionSecret = options.sessionSecret ?? randomBytes(32);
  const ports =
    options.ports ??
    (() => {
      if (!options.otpPolicy) {
        throw new Error("createConsentFlowHttpServer requiere `ports` u `otpPolicy` (D4, otp-policy.config.ts).");
      }
      return createDefaultConsentFlowPorts(options.otpPolicy);
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
      case "/otp/submit":
        result = handleSubmitOtp(request, ports, config, sessionSecret);
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
