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
import { createInMemoryRecoveryLinkChannelSink } from "../../../infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import type { InMemoryRecoveryLinkChannelSink } from "../../../infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryTenantHandleAdapter } from "../../../infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../infra/adapters/in-memory-staff-identity.adapter.ts";
import { LECTORPRO_BETA_CONFIG } from "../../modules/consent-decision/lectorpro-beta.config.ts";
import type { DecisionRelationshipConfig } from "../../modules/consent-decision/decision-relationship.config.ts";
import type { Environment } from "../../modules/common/types.ts";
import type { InvitationPorts } from "../../modules/invitation/invitation.ts";
import type { OtpChallengePorts, OtpPolicy } from "../../modules/otp-challenge/otp-challenge.ts";
import type { ConsentDecisionPorts } from "../../modules/consent-decision/consent-decision.ts";
import type { RecoveryTokenPolicy } from "../../modules/revocation/recovery-token-policy.config.ts";
import type { RecoveryHandlePolicy } from "../../modules/revocation/recovery-handle-policy.config.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { ConsentDecisionRepositoryPort } from "../../ports/consent-decision-repository.port.ts";
import type { StaffIdentityPort } from "../../ports/staff-identity.port.ts";
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
import {
  handleConfirmRevocation,
  handleIssueRecoveryLink,
  handleOpenRightsCase,
  handleRecoveryRevoke,
  handleRedeemManagementLink,
  handleRedeemRecoveryLink,
  handleRequestRevocation,
  handleVerifyRevocation,
  handleWithdrawRevocation,
  resolveRecoveryConfirmView,
  type RevocationFlowPorts,
} from "./revocation-flow.handler.ts";
import { handleDevStaffLogin, handleRecordCaseConfirmation, type CaseConfirmationPorts } from "./case-confirmation.handler.ts";
import { parseCookies } from "./cookies.ts";
import { decodeSession } from "./consent-session.ts";
import { deriveCaseSessionKey } from "./case-session.ts";
import { generateCsrfToken, serializeCsrfCookie } from "./csrf.ts";
import { deriveRecoveryCsrfKey, deriveRecoveryHandleKey, generateRecoveryCsrfToken } from "./recovery-handle.ts";
import { renderWelcomePage, renderWelcomeUniformErrorPage } from "./welcome-page.ts";
import { renderVerifyPage, renderVerifyUniformErrorPage } from "./verify-page.ts";
import { renderDecisionPage, renderDecisionUniformErrorPage } from "./decision-page.ts";
import { renderManageEntryPage, renderManageStatusPage, renderManageUniformErrorPage } from "./manage-page.ts";
import { renderRevocationConfirmPage, renderRevocationUniformErrorPage } from "./revocation-page.ts";
import { renderRecoveryConfirmPage, renderRecoveryUniformErrorPage } from "./recovery-page.ts";
import { getServedConsentVersion } from "./served-consent-version.ts";
import { resolveStaticAsset } from "./static-assets.ts";

export interface ConsentFlowHttpServerOptions {
  readonly config?: Partial<RightsCaseHttpConfig>;
  readonly ports?: ConsentFlowPorts;
  /** CA-116 (revocación IT0): ports de GET /m/{token} y el flujo self-service R1-R3/R8/RV0/RC1.
   * Si se omite junto con `ports`, se construye con createDefaultRevocationFlowPorts (mismo
   * ledger que `ports.decision.ledger`, TenantHandlePort in-memory vacío: dev.ts/los tests
   * siembran handles explícitamente con `.issue()`). */
  readonly revocationPorts?: RevocationFlowPorts;
  /** Secreto HMAC de la sesión (D5). Si se omite, se genera uno aleatorio por proceso (solo
   * válido mientras el proceso vive; nunca se persiste ni se loguea). */
  readonly sessionSecret?: Buffer;
  /** P-01/P-02/P-03 (otp-policy.config.ts); requerido si no se inyectan `ports` propios. */
  readonly otpPolicy?: OtpPolicy;
  /** GRD-CD-04 (decision-relationship.config.ts); requerido si no se inyectan `ports` propios. */
  readonly relationshipConfig?: DecisionRelationshipConfig;
  /** P-15 (recovery-token-policy.config.ts, CA-116 PR 2); si se omite junto con
   * `revocationPorts`, createDefaultRevocationFlowPorts exige pasarlo explícito (fail-closed,
   * mismo patrón que otpPolicy). */
  readonly recoveryTokenPolicy?: RecoveryTokenPolicy;
  /** P-18 (recovery-handle-policy.config.ts, ADR-006 §6.2, SEC-CNS-014). Si se omite, este
   * servidor usa DEFAULT_TEST_RECOVERY_HANDLE_POLICY (mismo criterio D4 que
   * DEFAULT_TEST_RECOVERY_TOKEN_POLICY: LOCAL/test-only, nunca un default de producción). */
  readonly recoveryHandlePolicy?: RecoveryHandlePolicy;
  /**
   * Entorno de ejecución (GRD-CM-13). Solo cuando es exactamente "LOCAL" este servidor expone
   * GET /__dev/otp-sink (dev.ts, D4/D5 report a Carlos: sink de depuración, cero PII más allá
   * de la ya presente en el canal sintético de la invitación). Cualquier otro valor, incluido
   * "undefined", deja la ruta fuera (fail-closed).
   */
  readonly environment?: Environment;
  /**
   * CA-128 (API-CNS-138, RH3 paso 1). StaffIdentityPort: lista nominal sintética de RIGHTS_OPERATOR
   * y aprobadores (GRD-RC-15), inyectada por dev.ts (LOCAL_ONLY_DEV_STAFF_ROSTER) o los tests.
   * Si se omite, un adaptador in-memory con roster vacío: fail-closed por defecto (GRD-RC-15
   * ERR-RC-10 siempre, mismo criterio D4 que tenantHandle vacío en createDefaultRevocationFlowPorts),
   * nunca una lista de producción hardcodeada.
   */
  readonly staffIdentity?: StaffIdentityPort;
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

/** Convenience LOCAL/test-only (nunca de producción real: esta función entera solo construye
 * adaptadores in-memory): a diferencia de `loadRecoveryTokenPolicyConfig` (fail-closed, D4, sin
 * default), la mayoría de los tests HTTP de este repo no ejercitan recovery y no deberían tener
 * que pasar un P-15 explícito solo para construir el servidor. Mismo criterio que el default
 * `sessionSecret ?? randomBytes(32)` de createConsentFlowHttpServer: válido solo mientras el
 * proceso vive, nunca persistido ni usado como recomendación de producto. dev.ts y los tests que
 * SÍ prueban recovery pasan su propio override vía `loadRecoveryTokenPolicyConfig`. */
const DEFAULT_TEST_RECOVERY_TOKEN_POLICY: RecoveryTokenPolicy = { ttlMs: 15 * 60_000 };

/** Mismo criterio D4/LOCAL-test-only que DEFAULT_TEST_RECOVERY_TOKEN_POLICY (arriba), pero para
 * P-18 (handle RECOVERY de la cookie, ADR-006 §6.2: 10 minutos), no P-15 (token en BD). */
const DEFAULT_TEST_RECOVERY_HANDLE_POLICY: RecoveryHandlePolicy = { ttlMs: 10 * 60_000 };

/** CA-116: ports de GET /m/{token} + R1-R3/R8/RV0(BEARER)/RC1(BEARER), y (PR 2) GET /r/{token}
 * + POST /recovery/revoke (R1r/R2r/R3r/R10/R11). `ledger` compartido con
 * `createDefaultConsentFlowPorts` (mismo proceso in-memory) si el caller lo pasa; si no, uno
 * nuevo. El `TenantHandlePort` nace vacío: dev.ts y los tests siembran handles con `.issue()`
 * (import { createInMemoryTenantHandleAdapter } directamente para poder sembrar).
 * `consentDecisionRepo` (SEC-CNS-014, FINDING P1-01): por defecto uno in-memory vacío, propio
 * de este proceso (suficiente para los tests que nunca ejercitan revokeWithRecoveryLink); los
 * callers que SÍ lo hacen (createConsentFlowHttpServer, dev.ts, recovery-http.test.ts) deben
 * pasar el mismo `ports.decision.repo` del flujo de consentimiento, para que
 * `findActiveGrantByChain` vea la GRANTED real de la cadena. */
export function createDefaultRevocationFlowPorts(
  recoveryTokenPolicy: RecoveryTokenPolicy = DEFAULT_TEST_RECOVERY_TOKEN_POLICY,
  ledger: LedgerPort = createInMemoryLedgerAdapter(),
  consentDecisionRepo: ConsentDecisionRepositoryPort = createInMemoryConsentDecisionRepository(),
): RevocationFlowPorts {
  return {
    tenantHandle: createInMemoryTenantHandleAdapter(),
    revocation: {
      revocationRepo: createInMemoryRevocationRepository(),
      ledger,
      recoveryTokenRepo: createInMemoryRecoveryTokenRepository(),
      recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
      recoveryTokenPolicy,
      consentDecisionRepo,
    },
    rightsCase: { rightsCaseRepo: createInMemoryRightsCaseRepository(), ledger },
  };
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

/** SEC-CNS-014 (APROBADO CON CAMBIOS, FINDING P1-02; Carlos 2026-09-28, opción b):
 * SameSite=Lax, no Strict. Sin esto, la cookie de sesión nunca llega en la navegación GET de
 * nivel superior que sigue a la redirección 303 de GET /r/{token} (o GET /i/, /m/) cuando el
 * enlace se abre desde fuera del origen de la app (p. ej. un cliente de correo): con Strict el
 * navegador la omite en esa primera navegación cross-site. Lax sigue sin enviar la cookie en un
 * POST cross-site (solo en navegación GET de nivel superior), así que GRD-CM-10
 * (csrf_and_origin: token CSRF double-submit + Origin exacto) sigue siendo la única defensa
 * real de los POST, sin debilitarse. */
function serializeSessionCookie(config: RightsCaseHttpConfig, value: string): string {
  return `${config.sessionCookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax`;
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

/** GET /recovery/confirm (SEC-CNS-014): además de las cabeceras de writeHtmlSecurityHeaders,
 * frame-ancestors 'none' (nunca en un iframe de terceros) y COOP same-origin (aísla el
 * `window` de esta pestaña de cualquier ventana abierta por un origen ajeno). Ambas páginas
 * (200 y 404) las llevan. */
function writeRecoveryHtmlSecurityHeaders(res: ServerResponse): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
}

/** Piso de tiempo (ms) para la rama UniformNotFound de GET /recovery/confirm (SEC-CNS-014):
 * intento de mitigación de canal lateral de temporización entre las causas (inexistente,
 * consumido, expirado, otro ciclo, sin cookie) — no es una garantía criptográfica de tiempo
 * constante, solo un piso mínimo sobre trabajo que ya es mayormente uniforme (un solo lookup en
 * memoria por causa). */
const RECOVERY_CONFIRM_UNIFORM_FLOOR_MS = 5;

function floorDelay(startedAt: bigint, floorMs: number): Promise<void> {
  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
  const remaining = floorMs - elapsedMs;
  if (remaining <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, remaining));
}

function writeResult(res: ServerResponse, config: RightsCaseHttpConfig, result: HttpResult): void {
  // CA-128: setCaseSessionCookie/setCaseCsrfCookie pueden coexistir entre sí (dos cookies del
  // mismo /__dev/staff-login); nunca con setSessionCookie/setRecoveryHandleCookie (documentado
  // en consent-flow.handler.ts). Node admite un arreglo para varias líneas Set-Cookie.
  const cookies: string[] = [];
  if (result.setSessionCookie) cookies.push(serializeSessionCookie(config, result.setSessionCookie));
  if (result.setRecoveryHandleCookie) cookies.push(result.setRecoveryHandleCookie);
  if (result.setCaseSessionCookie) cookies.push(result.setCaseSessionCookie);
  if (result.setCaseCsrfCookie) cookies.push(result.setCaseCsrfCookie);
  if (cookies.length > 0) {
    res.setHeader("Set-Cookie", cookies);
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
  const revocationPorts =
    options.revocationPorts ?? createDefaultRevocationFlowPorts(options.recoveryTokenPolicy, ports.decision.ledger, ports.decision.repo);
  const recoveryHandlePolicy = options.recoveryHandlePolicy ?? DEFAULT_TEST_RECOVERY_HANDLE_POLICY;
  // P2-02 (SEC-CNS-014): dos claves HKDF propias derivadas de sessionSecret, cada una con un
  // `info` distinto (recovery-handle.ts) y distinto también de la firma HMAC de
  // consent-session.ts: comprometer una nunca compromete las otras.
  const recoveryHandleKey = deriveRecoveryHandleKey(sessionSecret);
  const recoveryCsrfKey = deriveRecoveryCsrfKey(sessionSecret);
  // CA-128: clave propia de la sesión CASE (case-session.ts), aislada de las dos de arriba.
  const caseSessionKey = deriveCaseSessionKey(sessionSecret);
  // LOCAL + CI / SYNTHETIC DATA ONLY — APR-IDP PENDING: roster vacío por defecto (fail-closed,
  // GRD-RC-15 ERR-RC-10 siempre sin override explícito).
  const staffIdentity: StaffIdentityPort = options.staffIdentity ?? createInMemoryStaffIdentityAdapter([]);
  const caseConfirmationPorts: CaseConfirmationPorts = {
    revocation: revocationPorts.revocation,
    rightsCaseRepo: revocationPorts.rightsCase.rightsCaseRepo,
    staffIdentity,
  };

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
      res.end(renderDecisionPage(ports.decision.relationships.allowedRelationshipRefs, getServedConsentVersion()));
      return;
    }

    // -------------------------------------------------------------------
    // CA-116 (revocación IT0, UX-CNS-004): GET /m/{token} + páginas MANAGE/REVOCATION.
    // -------------------------------------------------------------------
    if (req.method === "GET" && path.startsWith("/m/") && path.length > "/m/".length) {
      // API-CNS-102 (P-14): único GET de canje del handle MANAGE_ENTRY (INV-CM-08, no transiciona).
      let token: string | undefined;
      try {
        token = decodeURIComponent(path.slice("/m/".length));
      } catch {
        token = undefined;
      }
      const result = token
        ? handleRedeemManagementLink(token, revocationPorts, sessionSecret)
        : { status: 404 as const, body: { status: 404 } };
      writeResult(res, config, result);
      return;
    }

    if (req.method === "GET" && path.startsWith("/r/") && path.length > "/r/".length) {
      // API-CNS-103 (P-18, SEC-CNS-014): único GET de canje del token de recuperación
      // (INV-CM-08 reforzado: no lee la BD, no valida, no transiciona ni consume). Un token no
      // decodificable se hashea igual, tal cual llega en el path (P2-04): SIEMPRE el mismo 303,
      // nunca un 404 crudo ni una rama distinta.
      const rawSegment = path.slice("/r/".length);
      let token: string;
      try {
        token = decodeURIComponent(rawSegment);
      } catch {
        token = rawSegment;
      }
      const result = handleRedeemRecoveryLink(token, recoveryHandlePolicy, recoveryHandleKey, config.recoveryHandleCookieName);
      writeResult(res, config, result);
      return;
    }

    if (req.method === "GET" && path === "/manage") {
      // UX-CNS-004 §1 (33:2 entrada / 33:21 estado): una sola ruta, dos renders según la
      // sesión (INV-CM-08: este GET nunca transiciona, solo lee la sesión ya creada por
      // GET /m/{token} y, si corresponde, por V3 scope MANAGE).
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.chainRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderManageUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(session.manageDecisionMakerRef ? renderManageStatusPage() : renderManageEntryPage());
      return;
    }

    if (req.method === "GET" && path === "/manage/verify") {
      // Exige el OTP scope MANAGE ya solicitado (V1); mismo patrón de error uniforme que /verify.
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.manageVerificationRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderVerifyUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderVerifyPage("MANAGE"));
      return;
    }

    if (req.method === "GET" && path === "/manage/revocation/verify") {
      // Exige el OTP scope REVOCATION ya solicitado (V1, posterior a R1).
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.revocationVerificationRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderVerifyUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderVerifyPage("REVOCATION"));
      return;
    }

    if (req.method === "GET" && path === "/manage/revocation/confirm") {
      // Exige V3 scope REVOCATION ya correcto (R2 lo ejecuta revocation.js al cargar).
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.revocationOtpVerified || !session.revocationRef || !session.manageDecisionMakerRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderRevocationUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderRevocationConfirmPage());
      return;
    }

    if (req.method === "GET" && path === "/recovery/confirm") {
      // SEC-CNS-014 (UX-CNS-004 33:87/33:106): GRD-RV-06 se evalúa AQUÍ, en solo lectura
      // (resolveRecoveryConfirmView -> evaluateRecoveryTokenEligibilityByHash), a partir del
      // hash fijado por GET /r/{token} en la cookie __Host-cns-recovery (nunca de la sesión de
      // consent-session.ts, que ya no lleva recoveryTokenHash). Sin handle válido, inexistente,
      // consumido, expirado o de otro ciclo: 404 byte-idéntico (UniformNotFound, mismo criterio
      // INV-CM-05), con un piso de tiempo común para no distinguir la causa por temporización.
      const startedAt = process.hrtime.bigint();
      const view = resolveRecoveryConfirmView(revocationPorts, recoveryHandleKey, headerValue(req.headers.cookie), config.recoveryHandleCookieName);
      writeRecoveryHtmlSecurityHeaders(res);
      if (!view.eligible || !view.tokenHash) {
        await floorDelay(startedAt, RECOVERY_CONFIRM_UNIFORM_FLOOR_MS);
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderRecoveryUniformErrorPage());
        return;
      }
      // P2 (fijación de cookie): el CSRF de esta página queda ligado al hash vigente ahora
      // mismo; POST /recovery/revoke lo recalcula contra la cookie __Host-cns-recovery ACTUAL
      // (recovery-handle.ts verifyRecoveryCsrfToken).
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateRecoveryCsrfToken(recoveryCsrfKey, view.tokenHash)));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderRecoveryConfirmPage());
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

    if (req.method === "GET" && path === "/__dev/recovery-sink") {
      // Mismo patrón fail-closed que /__dev/otp-sink (GRD-CM-13): CA-116 PR 2, único lugar
      // donde el enlace /r/<token> en claro es legible en LOCAL (Cero PII: nunca en la
      // respuesta HTTP de /manage/recovery-link ni en logs).
      if (options.environment !== "LOCAL") {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
      }
      const sink = revocationPorts.revocation.recoveryLinkChannel as InMemoryRecoveryLinkChannelSink;
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

    if (path === "/__dev/staff-login") {
      // CA-128 (Carlos 2026-09-28, opción (ii)): mismo guard GRD-CM-13 que /__dev/otp-sink;
      // handleDevStaffLogin ya rechaza fuera de LOCAL, aquí solo se enruta.
      const result = handleDevStaffLogin(
        request,
        options.environment ?? "DEV",
        { staffIdentity, rightsCaseRepo: revocationPorts.rightsCase.rightsCaseRepo },
        config,
        caseSessionKey,
      );
      writeResult(res, config, result);
      return;
    }

    if (path.startsWith("/platform/rights-cases/") && path.endsWith("/confirmation")) {
      // API-CNS-138: caseRef es el único segmento intermedio; un path con "/" adicional
      // (intento de traversal o de apuntar a otra sub-ruta) nunca resuelve, cae al 404 genérico.
      const caseRef = path.slice("/platform/rights-cases/".length, path.length - "/confirmation".length);
      if (caseRef.length > 0 && !caseRef.includes("/")) {
        const result = handleRecordCaseConfirmation(request, caseRef, caseConfirmationPorts, config, caseSessionKey);
        writeResult(res, config, result);
        return;
      }
    }

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
      case "/manage/revocation":
        result = handleRequestRevocation(request, revocationPorts, config, sessionSecret);
        break;
      case "/manage/revocation/verify":
        result = handleVerifyRevocation(request, revocationPorts, config, sessionSecret);
        break;
      case "/manage/revocation/confirm":
        result = handleConfirmRevocation(request, revocationPorts, config, sessionSecret);
        break;
      case "/manage/revocation/withdraw":
        result = handleWithdrawRevocation(request, revocationPorts, config, sessionSecret);
        break;
      case "/manage/recovery-link":
        result = handleIssueRecoveryLink(request, revocationPorts, config, sessionSecret);
        break;
      case "/recovery/revoke":
        result = handleRecoveryRevoke(request, revocationPorts, config, recoveryHandleKey, recoveryCsrfKey);
        break;
      case "/rights-case/open":
        result = handleOpenRightsCase(request, revocationPorts, config, sessionSecret);
        break;
      default:
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
    }
    writeResult(res, config, result);
  });
}
