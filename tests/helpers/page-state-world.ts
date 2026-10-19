// Gobierna: ADR-001 rev. 8 F1 (fase B), API-CNS-194/195 (GET /decision/page-state, GET /manage/page-state).
// Mundo sintético compartido por tests/integration/consent-flow/page-state-http.test.ts y
// tests/contract/http/page-state-contract.test.ts: servidor HTTP real en puerto efímero (SPA) con puertos en
// memoria, una invitación sintética enviada y una decisión GRANTED sembrada para /manage. Sin PII.
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../src/server/entrypoints/http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "../../src/server/entrypoints/http/revocation-flow.handler.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../src/server/modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { InMemoryOtpChannelSink } from "../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import type { InMemoryTenantHandleAdapter } from "../../src/infra/adapters/in-memory-tenant-handle.adapter.ts";
import { SYNTHETIC_SPA_DIST_DIR } from "./synthetic-spa-dist.ts";
import { fixtureUuid } from "../contract/uuid-fixture.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY, TEST_GUEST_CHANNEL } from "./test-ref-keys.ts";

export const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
export const CSRF_COOKIE_NAME = "__Host-cns-csrf";
export const SESSION_COOKIE_NAME = "__Host-cns-session";
export const INVITATION_HANDLE_COOKIE_NAME = "__Host-cns-i-handle";
export const MANAGE_ENTRY_HANDLE_COOKIE_NAME = "__Host-cns-m-handle";
export const TENANT_ID = "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73";
export const VALID_CSRF = { origin: ALLOWED_ORIGIN, csrfHeader: "csrf-token-abcdefgh", csrfCookie: "csrf-token-abcdefgh" };

const OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000 };
const RELATIONSHIPS = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };

export interface World {
  readonly baseUrl: string;
  readonly ports: ConsentFlowPorts;
  readonly revocationPorts: RevocationFlowPorts;
  close(): Promise<void>;
}

export interface WorldOptions {
  /** Default: el dist sintético compartido (la SPA es el único modo; el web no arranca sin dist/). */
  readonly spaDistDir?: string;
}

export async function startWorld(options: WorldOptions = {}): Promise<World> {
  const ports = createDefaultConsentFlowPorts(OTP_POLICY, RELATIONSHIPS, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  const revocationPorts = createDefaultRevocationFlowPorts({ ttlMs: 60_000 }, ports.decision.ledger, ports.decision.repo);
  const server: Server = createConsentFlowHttpServer({
    guestMessageChannel: TEST_GUEST_CHANNEL,
    sessionSecret: TEST_SESSION_SECRET,
    staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
    config: { allowedOrigin: ALLOWED_ORIGIN },
    ports,
    revocationPorts,
    environment: "LOCAL",
    spaDistDir: options.spaDistDir ?? SYNTHETIC_SPA_DIST_DIR,
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({ baseUrl: `http://127.0.0.1:${address.port}`, ports, revocationPorts, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

export function parseSetCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of res.headers.getSetCookie()) {
    const first = raw.split(";")[0] ?? "";
    const eq = first.indexOf("=");
    if (eq !== -1 && !out[first.slice(0, eq).trim()]) out[first.slice(0, eq).trim()] = first.slice(eq + 1).trim();
  }
  return out;
}

export function post(baseUrl: string, path: string, sessionCookie: string | undefined, body: unknown = {}): Promise<Response> {
  const cookies = [`${CSRF_COOKIE_NAME}=${VALID_CSRF.csrfCookie}`];
  if (sessionCookie !== undefined) cookies.push(`${SESSION_COOKIE_NAME}=${sessionCookie}`);
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: VALID_CSRF.origin, "x-csrf-token": VALID_CSRF.csrfHeader, cookie: cookies.join("; ") },
    body: JSON.stringify(body),
  });
}

/** Invitación sintética enviada -> GET /i/{token} -> GET /welcome. Devuelve la sesión LANDING (sin OTP verificado). */
export async function landingSession(world: World, tag: string): Promise<string> {
  const invitationRef = fixtureUuid(`inv-${tag}`);
  await createInvitation(world.ports.invitation, TENANT_ID, "INVITER", {
    enrollmentRef: fixtureUuid(`enr-${tag}`),
    participationRef: fixtureUuid(`part-${tag}`),
    invitationRef,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid(`subject-${tag}`),
  });
  await markInvitationReady(world.ports.invitation, TENANT_ID, "INVITER", invitationRef, {
    consentVersion: "v1",
    expiresAt: new Date(Date.now() + 60_000),
    recipientChannelRef: `test+${tag}@example.invalid`,
  });
  const { token } = await sendInvitation(world.ports.invitation, TENANT_ID, "INVITER", invitationRef, { deliveryChannel: "CONSENT_APP_EMAIL" });
  const redeemed = await fetch(`${world.baseUrl}/i/${token}`, { redirect: "manual" });
  const handle = parseSetCookies(redeemed)[INVITATION_HANDLE_COOKIE_NAME];
  const welcome = await fetch(`${world.baseUrl}/welcome`, { headers: { cookie: `${INVITATION_HANDLE_COOKIE_NAME}=${handle}` } });
  const session = parseSetCookies(welcome)[SESSION_COOKIE_NAME];
  if (!session) throw new Error("landingSession: GET /welcome no fijó sesión");
  return session;
}

/** LANDING -> POST /invitation/open -> V1 -> V3. Devuelve la cookie de sesión verificada (post-V3, scope DECISION). */
export async function verifiedDecisionSession(world: World, tag: string): Promise<string> {
  const landing = await landingSession(world, tag);
  const opened = await post(world.baseUrl, "/invitation/open", landing);
  const afterOpen = parseSetCookies(opened)[SESSION_COOKIE_NAME] ?? landing;
  const requested = await post(world.baseUrl, "/otp/request", afterOpen);
  const afterRequest = parseSetCookies(requested)[SESSION_COOKIE_NAME] ?? afterOpen;
  const sink = world.ports.otp.channel as InMemoryOtpChannelSink;
  const submitted = await post(world.baseUrl, "/otp/submit", afterRequest, { code: sink.sent[sink.sent.length - 1]?.code ?? "" });
  const verified = parseSetCookies(submitted)[SESSION_COOKIE_NAME];
  if (!verified) throw new Error("verifiedDecisionSession: V3 no fijó la sesión verificada");
  return verified;
}

/** Siembra una decisión GRANTED y el handle de gestión `mgmtToken` (mismo patrón que manage-revocation-http.test.ts). */
export async function seedManageChain(world: World, tag: string, mgmtToken: string, state: "GRANTED" | "REVOKED" = "GRANTED"): Promise<{ readonly consentId: string }> {
  const consentId = fixtureUuid(`consent-${tag}`);
  const chainRef = fixtureUuid(`chain-${tag}`);
  await world.ports.decision.repo.save({
    consentId,
    tenantId: TENANT_ID,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid(`subject-${tag}`),
    decisionMakerRef: "dm:page-state-seed",
    invitationRef: "inv-page-state-seed",
    verificationRef: "ver-page-state-seed",
    chainRef,
    state,
    purposes: LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const })),
    priorStepsComplete: true,
    stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
    receiptRef: `receipt-${consentId}`,
  });
  (world.revocationPorts.tenantHandle as InMemoryTenantHandleAdapter).issue({ handle: mgmtToken, tenantId: TENANT_ID, chainRef, revokedDecisionRef: consentId });
  return { consentId };
}

/** GET /m/{token} -> GET /manage: la sesión (entry, sin OTP MANAGE) que fija el servidor. */
export async function manageEntrySession(world: World, mgmtToken: string): Promise<{ readonly session: string; readonly handleCookie: string }> {
  const redeemed = await fetch(`${world.baseUrl}/m/${mgmtToken}`, { redirect: "manual" });
  const handleCookie = parseSetCookies(redeemed)[MANAGE_ENTRY_HANDLE_COOKIE_NAME];
  if (!handleCookie) throw new Error("manageEntrySession: GET /m/{token} no fijó el handle");
  const manage = await fetch(`${world.baseUrl}/manage`, { headers: { cookie: `${MANAGE_ENTRY_HANDLE_COOKIE_NAME}=${handleCookie}` } });
  const session = parseSetCookies(manage)[SESSION_COOKIE_NAME];
  if (!session) throw new Error("manageEntrySession: GET /manage no fijó sesión");
  return { session, handleCookie };
}

/** entry -> V1 MANAGE -> V3 MANAGE. Devuelve la sesión con manageDecisionMakerRef (variante `status`). */
export async function verifiedManageSession(world: World, mgmtToken: string): Promise<{ readonly session: string; readonly handleCookie: string }> {
  const entry = await manageEntrySession(world, mgmtToken);
  const requested = await post(world.baseUrl, "/otp/request", entry.session);
  const afterRequest = parseSetCookies(requested)[SESSION_COOKIE_NAME] ?? entry.session;
  const sink = world.ports.otp.channel as InMemoryOtpChannelSink;
  const submitted = await post(world.baseUrl, "/otp/submit", afterRequest, { code: sink.sent[sink.sent.length - 1]?.code ?? "" });
  const verified = parseSetCookies(submitted)[SESSION_COOKIE_NAME];
  if (!verified) throw new Error("verifiedManageSession: V3 MANAGE no fijó la sesión");
  return { session: verified, handleCookie: entry.handleCookie };
}
