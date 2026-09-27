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
import { LECTORPRO_BETA_CONFIG } from "../../modules/consent-decision/lectorpro-beta.config.ts";
import type { InvitationPorts } from "../../modules/invitation/invitation.ts";
import type { OtpChallengePorts, OtpPolicy } from "../../modules/otp-challenge/otp-challenge.ts";
import type { ConsentDecisionPorts } from "../../modules/consent-decision/consent-decision.ts";
import { loadRightsCaseHttpConfig, type RightsCaseHttpConfig } from "./config.ts";
import {
  handleOpenInvitation,
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
    const path = url.split("?", 1)[0];

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
