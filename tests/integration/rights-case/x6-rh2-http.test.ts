// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-136 (POST /platform/rights-cases/{caseRef}/verification-proposals,
// caseSession) y API-CNS-137 (.../{proposalRef}/approval, platformSession; en IT0 el roster los modela como APPROVER, OPEN-TC-06),
// revocation.spec RH2, GRD-RV-09 (ERR-RV-07), GRD-CM-01/07/10; CA-128 X6. Camino HTTP real (node:http, puerto efímero):
// /__dev/staff-login (LOCAL-only) -> propone el RIGHTS_OPERATOR -> aprueba el APPROVER -> RH3 record + cosign hasta APPLIED.
// El step-up/aserción del IdP es un stub LOCAL-only (APR-IDP PENDING). TEST-CNS-984, TEST-CNS-985.

import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "../../../src/server/entrypoints/http/revocation-flow.handler.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { StaffIdentityPort, StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import type { Environment } from "../../../src/server/modules/common/types.ts";
import { validateApiPayload, validateCommon, type ValidationResult } from "../../contract/schema-lite.ts";
import { TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET, TEST_SESSION_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CASE_SESSION_COOKIE_NAME = "__Host-cns-case";
const CASE_CSRF_COOKIE_NAME = "__Host-cns-case-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const TENANT_ID = "7cfbfb16-4c4d-4966-892b-0794cbd57199";

const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY = { ttlMs: 60_000 };

/** LOCAL + CI / SYNTHETIC DATA ONLY — APR-IDP PENDING (Carlos, 2026-09-28 opción (ii)): 4
 * personas ficticias distintas, sin reutilización entre roles (NF-19, GRD-RC-15). */
const FULL_ROSTER: readonly StaffPrincipal[] = [
  { principalRef: fixtureUuid("staff-synthetic-01"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-02"), role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("staff-synthetic-03"), role: "APPROVER" },
  { principalRef: fixtureUuid("staff-synthetic-04"), role: "APPROVER" },
];

function assertValid(result: ValidationResult): void {
  assert.ok(result.ok, `violaciones de esquema:\n${result.errors.join("\n")}`);
}

/** RightsProblem (contracts/openapi: allOf [Problem, required rightsPathsAvailable]) no es un
 * $def independiente de common.schema.json (solo un allOf inline del OpenAPI, que schema-lite
 * no implementa); valida contra Problem y además exige rightsPathsAvailable con las tres vías
 * (RightsPaths). */
function assertRightsProblem(body: unknown): void {
  assertValid(validateCommon("Problem", body));
  assert.deepEqual((body as { rightsPathsAvailable?: unknown }).rightsPathsAvailable, ["OTP", "RECOVERY_LINK", "HUMAN_CASE"]);
}

function getAllSetCookies(res: Response): string[] {
  const withGetter = res.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof withGetter.getSetCookie === "function") return withGetter.getSetCookie();
  const raw = res.headers.get("set-cookie");
  return raw ? [raw] : [];
}

function parseSetCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of getAllSetCookies(res)) {
    const firstAttr = line.split(";", 1)[0] ?? "";
    const eq = firstAttr.indexOf("=");
    if (eq === -1) continue;
    out[firstAttr.slice(0, eq).trim()] = firstAttr.slice(eq + 1).trim();
  }
  return out;
}

interface Fixture {
  readonly baseUrl: string;
  readonly revocationPorts: RevocationFlowPorts;
  readonly staffIdentity: StaffIdentityPort;
  readonly caseRef: string;
  readonly revocationRef: string;
  close(): Promise<void>;
}

async function setUp(
  opts: { chainRef: string; caseRef: string; revocationRef: string; environment?: Environment; roster?: readonly StaffPrincipal[] },
): Promise<Fixture> {
  const consentId = fixtureUuid(`consent-${opts.chainRef}`);
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG, TEST_CHAIN_REF_KEY, TEST_DECISION_MAKER_REF_KEY, TEST_OTP_SECRET);
  await ports.decision.repo.save({
    consentId,
    tenantId: TENANT_ID,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid("subject-rh3"),
    decisionMakerRef: "dm:rh3-seed",
    invitationRef: fixtureUuid("inv-rh3-seed"),
    verificationRef: fixtureUuid("ver-rh3-seed"),
    chainRef: opts.chainRef,
    state: "GRANTED",
    purposes: LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const })),
    priorStepsComplete: true,
    stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
    receiptRef: `receipt-${consentId}`,
  });

  const revocationPorts = createDefaultRevocationFlowPorts(LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY, ports.decision.ledger, ports.decision.repo);

  // RC1 (rights-case.ts openRightsCase, sin HTTP en este slice: el caso ya OPEN de partida).
  await revocationPorts.rightsCase.rightsCaseRepo.save({
    caseRef: opts.caseRef,
    tenantId: TENANT_ID,
    chainRef: opts.chainRef,
    revokedDecisionRef: consentId,
    status: "OPEN",
  });

  // Revocation REQUESTED -> RH2 (attestHumanAssistedVerification, VERIFIED + attestedVerification).
  await revocationPorts.revocation.revocationRepo.save({
    revocationRef: opts.revocationRef,
    tenantId: TENANT_ID,
    chainRef: opts.chainRef,
    caseRef: opts.caseRef,
    revokedDecisionRef: consentId,
    status: "REQUESTED",
  });

  // RC3 (liga la Revocation al caso, mismo efecto que expressRevocationIntentInCase sin repetir
  // el handle HTTP en este slice): el handler resuelve el revocationRef desde el caso.
  await revocationPorts.rightsCase.rightsCaseRepo.save({
    caseRef: opts.caseRef,
    tenantId: TENANT_ID,
    chainRef: opts.chainRef,
    revokedDecisionRef: consentId,
    status: "IN_VERIFICATION",
    revocationRef: opts.revocationRef,
  });

  const staffIdentity = createInMemoryStaffIdentityAdapter(opts.roster ?? FULL_ROSTER);

  const server = createConsentFlowHttpServer({ sessionSecret: TEST_SESSION_SECRET, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
    config: { allowedOrigin: ALLOWED_ORIGIN },
    ports,
    revocationPorts,
    environment: opts.environment ?? "LOCAL",
    staffIdentity,
  });
  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
  return {
    baseUrl,
    revocationPorts,
    staffIdentity,
    caseRef: opts.caseRef,
    revocationRef: opts.revocationRef,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

async function devStaffLogin(baseUrl: string, body: { tenantId: string; caseRef: string; principalRef: string }): Promise<{ res: Response; caseSessionCookie?: string; caseCsrfCookie?: string }> {
  const res = await fetch(`${baseUrl}/__dev/staff-login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const cookies = parseSetCookies(res);
  return { res, caseSessionCookie: cookies[CASE_SESSION_COOKIE_NAME], caseCsrfCookie: cookies[CASE_CSRF_COOKIE_NAME] };
}


interface Sess { readonly session: string; readonly csrf: string }

async function login(baseUrl: string, caseRef: string, principalRef: string): Promise<Sess> {
  const { res, caseSessionCookie, caseCsrfCookie } = await devStaffLogin(baseUrl, { tenantId: TENANT_ID, caseRef, principalRef });
  assert.equal(res.status, 200);
  return { session: caseSessionCookie!, csrf: caseCsrfCookie! };
}

function post(baseUrl: string, path: string, s: Sess | undefined, body: unknown): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json", origin: ALLOWED_ORIGIN };
  const csrf = s?.csrf ?? "csrf-token-abcdefgh";
  headers[CSRF_HEADER_NAME] = csrf;
  headers.cookie = [s ? `${CASE_SESSION_COOKIE_NAME}=${s.session}` : "", `${CASE_CSRF_COOKIE_NAME}=${csrf}`].filter(Boolean).join("; ");
  return fetch(`${baseUrl}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
}

const STEP_UP = { stepUpAssertion: "aserc-sintetica-local-only" };
const OP1 = fixtureUuid("staff-synthetic-01");
const OP2 = fixtureUuid("staff-synthetic-02");
const APPROVER1 = fixtureUuid("staff-synthetic-03");

test("TEST-CNS-984: RH2 HTTP: propone RIGHTS_OPERATOR (201 PENDING), aprueba APPROVER (200 ATTESTED/VERIFIED), luego RH3 record+cosign llega a APPLIED con REVOCATION_VERIFIED verifiedByRef/secondApproverRef de la sesión", async () => {
  const fx = await setUp({ chainRef: fixtureUuid("chain-984"), caseRef: fixtureUuid("case-984"), revocationRef: fixtureUuid("rv-984") });
  try {
    const op1 = await login(fx.baseUrl, fx.caseRef, OP1);
    const proposed = await post(fx.baseUrl, `/platform/rights-cases/${fx.caseRef}/verification-proposals`, op1, { verificationScriptVersion: "guion-1", ...STEP_UP });
    assert.equal(proposed.status, 201);
    const pBody = (await proposed.json()) as { proposalRef: string; attestation: string };
    assertValid(validateApiPayload("ProposalAck", pBody));
    assert.equal(pBody.attestation, "PENDING");
    assert.equal((await fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, fx.revocationRef))?.status, "REQUESTED");

    const approver = await login(fx.baseUrl, fx.caseRef, APPROVER1);
    const approved = await post(fx.baseUrl, `/platform/rights-cases/${fx.caseRef}/verification-proposals/${pBody.proposalRef}/approval`, approver, STEP_UP);
    assert.equal(approved.status, 200, JSON.stringify(await approved.clone().json()));
    const aBody = await approved.json();
    assertValid(validateApiPayload("ApprovalAck", aBody));
    assert.deepEqual(aBody, { attestation: "ATTESTED", revocationState: "VERIFIED" });
    const events = await fx.revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", fx.revocationRef);
    const verified = events.find((e) => e.eventType === "REVOCATION_VERIFIED")!.payload as Record<string, unknown>;
    assert.equal(verified.verifiedByRef, OP1, "verifiedByRef = principal de la sesión CASE del proponente");
    assert.equal(verified.secondApproverRef, APPROVER1, "secondApproverRef = principal de la sesión del aprobador");

    // RH3 con dos RIGHTS_OPERATOR (el proponente puede ser uno de ellos, AUDIT-H01-rev4 M-04) hasta APPLIED.
    const rec = await post(fx.baseUrl, `/platform/rights-cases/${fx.caseRef}/confirmation`, op1, { confirmationGivenOnCasePage: true });
    assert.equal(rec.status, 200, JSON.stringify(await rec.clone().json()));
    const op2 = await login(fx.baseUrl, fx.caseRef, OP2);
    const cos = await post(fx.baseUrl, `/platform/rights-cases/${fx.caseRef}/confirmation/cosign`, op2, {});
    assert.equal(cos.status, 200, JSON.stringify(await cos.clone().json()));
    assert.equal((await fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, fx.revocationRef))?.status, "APPLIED");
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-985: RH2 HTTP guards: rol que no corresponde 403 ACTOR_NOT_ALLOWED; sin sesión o caso ajeno 404; body inválido (campo extra, sin aserción, guion mal formado) 422; actor nunca del body", async () => {
  const fx = await setUp({ chainRef: fixtureUuid("chain-985"), caseRef: fixtureUuid("case-985"), revocationRef: fixtureUuid("rv-985") });
  try {
    const propose = `/platform/rights-cases/${fx.caseRef}/verification-proposals`;
    assert.equal((await post(fx.baseUrl, propose, undefined, { verificationScriptVersion: "g", ...STEP_UP })).status, 404, "sin sesión CASE");
    const approverSession = await login(fx.baseUrl, fx.caseRef, APPROVER1);
    const denied = await post(fx.baseUrl, propose, approverSession, { verificationScriptVersion: "g", ...STEP_UP });
    assert.equal(denied.status, 403, "un APPROVER no propone");
    assert.equal(((await denied.json()) as { code: string }).code, "ACTOR_NOT_ALLOWED");
    const op1 = await login(fx.baseUrl, fx.caseRef, OP1);
    assert.equal((await post(fx.baseUrl, `/platform/rights-cases/${fixtureUuid("otro-caso")}/verification-proposals`, op1, { verificationScriptVersion: "g", ...STEP_UP })).status, 404, "caseRef distinto del de la sesión");
    for (const bad of [
      { verificationScriptVersion: "g", ...STEP_UP, verifiedByRef: fixtureUuid("suplanta") },
      { verificationScriptVersion: "g" },
      { verificationScriptVersion: "guion con espacios", ...STEP_UP },
      { ...STEP_UP },
    ]) {
      assert.equal((await post(fx.baseUrl, propose, op1, bad)).status, 422, JSON.stringify(Object.keys(bad)));
    }
    const ok = await post(fx.baseUrl, propose, op1, { verificationScriptVersion: "g", ...STEP_UP });
    const { proposalRef } = (await ok.json()) as { proposalRef: string };
    const approve = `/platform/rights-cases/${fx.caseRef}/verification-proposals/${proposalRef}/approval`;
    assert.equal((await post(fx.baseUrl, approve, op1, STEP_UP)).status, 403, "un RIGHTS_OPERATOR (incluido el proponente) no aprueba");
    assert.equal((await post(fx.baseUrl, approve, approverSession, { ...STEP_UP, secondApproverRef: fixtureUuid("suplanta") })).status, 422);
    assert.equal((await post(fx.baseUrl, `/platform/rights-cases/${fx.caseRef}/verification-proposals/${fixtureUuid("inexistente")}/approval`, approverSession, STEP_UP)).status, 404, "propuesta inexistente");
    assert.equal((await fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, fx.revocationRef))?.status, "REQUESTED", "sin efecto hasta la aprobación válida");
  } finally {
    await fx.close();
  }
});
