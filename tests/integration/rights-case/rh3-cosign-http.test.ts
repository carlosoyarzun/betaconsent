// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-139 (POST /platform/rights-cases/{caseRef}/confirmation/cosign, CosignCaseConfirmationRequest) y API-CNS-138 (POST
// /platform/rights-cases/{caseRef}/confirmation, securitySchemes.caseSession);
// specs/state-machines/revocation.spec.yaml RH3 paso 1 (GRD-RV-10/ERR-RV-20);
// specs/state-machines/rights-case.spec.yaml GRD-RC-15/ERR-RC-10; CA-128. Recorre el camino
// HTTP real (node:http en un puerto efímero de localhost): RC1 abierto -> RH2 (atestado
// directo, sin HTTP en este slice) -> /__dev/staff-login (LOCAL-only, Carlos 2026-09-28 opción
// (ii)) -> RH3 paso 1 registrado. Cubre además los guards técnicos citados en la tarea CA-128
// (GRD-CM-01/06/07/10, GRD-RC-15, GRD-RV-20) y la validación de la respuesta contra el
// contrato (schema-lite).
// TEST-CNS-667..675 (cosign, RH3 paso 2; el paso 1 vive en rh3-case-confirmation-http.test.ts).

import test from "node:test";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { assertRevocationEvidence } from "../../contract/revocation-evidence.ts";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import type { ConsentFlowPorts } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "../../../src/server/entrypoints/http/revocation-flow.handler.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { attestHumanAssistedVerification } from "../../../src/server/modules/revocation/revocation.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import type { StaffIdentityPort, StaffPrincipal } from "../../../src/server/ports/staff-identity.port.ts";
import type { Environment } from "../../../src/server/modules/common/types.ts";
import { validateApiPayload, validateCommon, validateLedgerEventPayload, type ValidationResult } from "../../contract/schema-lite.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CASE_SESSION_COOKIE_NAME = "__Host-cns-case";
const CASE_CSRF_COOKIE_NAME = "__Host-cns-case-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const TENANT_ID = "tenant-rh3";

const LOCAL_ONLY_TEST_OTP_POLICY = { codeLength: 6, maxAttempts: 3, ttlMs: 60_000, maxResends: 3 };
const LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG = { allowedRelationshipRefs: ["SYNTHETIC_GUARDIAN"] };
const LOCAL_ONLY_TEST_RECOVERY_TOKEN_POLICY = { ttlMs: 60_000 };

/** LOCAL + CI / SYNTHETIC DATA ONLY — APR-IDP PENDING (Carlos, 2026-09-28 opción (ii)): 4
 * personas ficticias distintas, sin reutilización entre roles (NF-19, GRD-RC-15). */
const FULL_ROSTER: readonly StaffPrincipal[] = [
  { principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR" },
  { principalRef: "staff-synthetic-03", role: "APPROVER" },
  { principalRef: "staff-synthetic-04", role: "APPROVER" },
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
  opts: { chainRef: string; caseRef: string; revocationRef: string; consentId?: string; environment?: Environment; roster?: readonly StaffPrincipal[] },
): Promise<Fixture> {
  const consentId = opts.consentId ?? `consent-${opts.chainRef}`;
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  await ports.decision.repo.save({
    consentId,
    tenantId: TENANT_ID,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: "subject-rh3@example.invalid",
    decisionMakerRef: "dm:rh3-seed",
    invitationRef: "inv-rh3-seed",
    verificationRef: "ver-rh3-seed",
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
  await attestHumanAssistedVerification(revocationPorts.revocation, TENANT_ID, opts.revocationRef, opts.caseRef);

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

  const server = createConsentFlowHttpServer({
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

interface ConfirmOpts {
  readonly caseRef: string;
  readonly caseSessionCookie?: string;
  readonly caseCsrfCookie?: string;
  readonly origin?: string;
  readonly csrfHeader?: string;
  readonly body?: unknown;
}

function postConfirmation(baseUrl: string, opts: ConfirmOpts): Promise<Response> {
  const cookieParts: string[] = [];
  if (opts.caseSessionCookie !== undefined) cookieParts.push(`${CASE_SESSION_COOKIE_NAME}=${opts.caseSessionCookie}`);
  if (opts.caseCsrfCookie !== undefined) cookieParts.push(`${CASE_CSRF_COOKIE_NAME}=${opts.caseCsrfCookie}`);

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.csrfHeader !== undefined) headers[CSRF_HEADER_NAME] = opts.csrfHeader;
  if (cookieParts.length > 0) headers.cookie = cookieParts.join("; ");

  return fetch(`${baseUrl}/platform/rights-cases/${opts.caseRef}/confirmation`, {
    method: "POST",
    headers,
    body: JSON.stringify(opts.body ?? { confirmationGivenOnCasePage: true }),
  });
}


function postCosign(baseUrl: string, opts: ConfirmOpts): Promise<Response> {
  const cookieParts: string[] = [];
  if (opts.caseSessionCookie !== undefined) cookieParts.push(`${CASE_SESSION_COOKIE_NAME}=${opts.caseSessionCookie}`);
  if (opts.caseCsrfCookie !== undefined) cookieParts.push(`${CASE_CSRF_COOKIE_NAME}=${opts.caseCsrfCookie}`);
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.csrfHeader !== undefined) headers[CSRF_HEADER_NAME] = opts.csrfHeader;
  if (cookieParts.length > 0) headers.cookie = cookieParts.join("; ");
  return fetch(`${baseUrl}/platform/rights-cases/${opts.caseRef}/confirmation/cosign`, {
    method: "POST",
    headers,
    body: JSON.stringify(opts.body ?? {}),
  });
}

interface Session {
  readonly caseSessionCookie?: string;
  readonly caseCsrfCookie?: string;
}

function authed(fx: Fixture, s: Session, extra: Partial<ConfirmOpts> = {}): ConfirmOpts {
  return { caseRef: fx.caseRef, caseSessionCookie: s.caseSessionCookie, caseCsrfCookie: s.caseCsrfCookie, origin: ALLOWED_ORIGIN, csrfHeader: s.caseCsrfCookie, ...extra };
}

async function login(fx: Fixture, principalRef: string): Promise<Session> {
  const res = await devStaffLogin(fx.baseUrl, { tenantId: TENANT_ID, caseRef: fx.caseRef, principalRef });
  assert.equal(res.res.status, 200);
  return { caseSessionCookie: res.caseSessionCookie, caseCsrfCookie: res.caseCsrfCookie };
}

/** Registra la confirmación (paso 1) con el operador dado. */
async function record(fx: Fixture, principalRef: string): Promise<Session> {
  const s = await login(fx, principalRef);
  const res = await postConfirmation(fx.baseUrl, authed(fx, s, { body: { confirmationGivenOnCasePage: true } }));
  assert.equal(res.status, 200);
  return s;
}

async function confirmedEvents(fx: Fixture) {
  return (await fx.revocationPorts.revocation.ledger
    .listByAggregate(TENANT_ID, "Revocation", fx.revocationRef))
    .filter((e) => e.eventType === "REVOCATION_CONFIRMED");
}

test("TEST-CNS-667: cosign con sesión APPROVER (rol no permitido) -> 403 ACTOR_NOT_ALLOWED (GRD-CM-07, LD-03), sin efecto", async () => {
  const fx = await setUp({ chainRef: "chain-667", caseRef: fixtureUuid("case-667"), revocationRef: fixtureUuid("rv-667") });
  try {
    await record(fx, "staff-synthetic-01");
    const approver = await login(fx, "staff-synthetic-03");
    const res = await postCosign(fx.baseUrl, authed(fx, approver));
    assert.equal(res.status, 403);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "ACTOR_NOT_ALLOWED");
    assertRightsProblem(body);
    assert.equal((await fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, fx.revocationRef))?.status, "VERIFIED");
    assert.equal((await confirmedEvents(fx)).length, 0);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-668: cosignedByRef en el body viola additionalProperties:false de CosignCaseConfirmationRequest -> 422, sin efecto (GRD-CM-07)", async () => {
  const fx = await setUp({ chainRef: "chain-668", caseRef: fixtureUuid("case-668"), revocationRef: fixtureUuid("rv-668") });
  try {
    await record(fx, "staff-synthetic-01");
    const op2 = await login(fx, "staff-synthetic-02");
    const res = await postCosign(fx.baseUrl, authed(fx, op2, { body: { cosignedByRef: "staff-synthetic-02" } }));
    assert.equal(res.status, 422);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "INVALID_TRANSITION");
    assertRightsProblem(body);
    const stored = await fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, fx.revocationRef);
    assert.equal(stored?.status, "VERIFIED");
    assert.equal(stored?.cosignedByRef, undefined);
    assert.equal((await confirmedEvents(fx)).length, 0);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-669: cosign por la misma persona que registró -> 409 RH3_FOUR_EYES_REQUIRED (ERR-RV-18), sin efecto", async () => {
  const fx = await setUp({ chainRef: "chain-669", caseRef: fixtureUuid("case-669"), revocationRef: fixtureUuid("rv-669") });
  try {
    const op1 = await record(fx, "staff-synthetic-01");
    const res = await postCosign(fx.baseUrl, authed(fx, op1));
    assert.equal(res.status, 409);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "RH3_FOUR_EYES_REQUIRED");
    assertRightsProblem(body);
    assert.equal((await fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, fx.revocationRef))?.status, "VERIFIED");
    assert.equal((await confirmedEvents(fx)).length, 0);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-670: cosign sin confirmación previa (sin AWAITING_COSIGN) -> 409 RH3_FOUR_EYES_REQUIRED, sin efecto", async () => {
  const fx = await setUp({ chainRef: "chain-670", caseRef: fixtureUuid("case-670"), revocationRef: fixtureUuid("rv-670") });
  try {
    const op2 = await login(fx, "staff-synthetic-02");
    const res = await postCosign(fx.baseUrl, authed(fx, op2));
    assert.equal(res.status, 409);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "RH3_FOUR_EYES_REQUIRED");
    assertRightsProblem(body);
    assert.equal((await fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, fx.revocationRef))?.status, "VERIFIED");
    assert.equal((await confirmedEvents(fx)).length, 0);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-671: sesión de otro caso (path distinto) o sin sesión -> 404 uniforme (GRD-CM-01)", async () => {
  const fx = await setUp({ chainRef: "chain-671", caseRef: fixtureUuid("case-671"), revocationRef: fixtureUuid("rv-671") });
  try {
    await record(fx, "staff-synthetic-01");
    const op2 = await login(fx, "staff-synthetic-02");
    const otherCase = await postCosign(fx.baseUrl, authed(fx, op2, { caseRef: "case-otro-distinto" }));
    assert.equal(otherCase.status, 404);
    const csrf = "csrf-token-abcdefgh";
    const noSession = await postCosign(fx.baseUrl, { caseRef: fx.caseRef, caseCsrfCookie: csrf, origin: ALLOWED_ORIGIN, csrfHeader: csrf });
    assert.equal(noSession.status, 404);
    assert.equal((await confirmedEvents(fx)).length, 0);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-672: CSRF/Origin incorrecto en cosign -> 403 CSRF_REJECTED (GRD-CM-10)", async () => {
  const fx = await setUp({ chainRef: "chain-672", caseRef: fixtureUuid("case-672"), revocationRef: fixtureUuid("rv-672") });
  try {
    await record(fx, "staff-synthetic-01");
    const op2 = await login(fx, "staff-synthetic-02");
    const res = await postCosign(fx.baseUrl, authed(fx, op2, { origin: "http://otro-origen.test.localhost" }));
    assert.equal(res.status, 403);
    assert.equal(((await res.json()) as { code: string }).code, "CSRF_REJECTED");
    assert.equal((await confirmedEvents(fx)).length, 0);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-673: dotación insuficiente en cosign -> 409 ROSTER_INSUFFICIENT (GRD-RC-15), fail-closed", async () => {
  const shortRoster: readonly StaffPrincipal[] = [
    { principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" },
    { principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR" },
    { principalRef: "staff-synthetic-03", role: "APPROVER" },
  ];
  const fx = await setUp({ chainRef: "chain-673", caseRef: fixtureUuid("case-673"), revocationRef: fixtureUuid("rv-673"), roster: shortRoster });
  try {
    const op2 = await login(fx, "staff-synthetic-02");
    const res = await postCosign(fx.baseUrl, authed(fx, op2));
    assert.equal(res.status, 409);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "ROSTER_INSUFFICIENT");
    assertRightsProblem(body);
    assert.equal((await confirmedEvents(fx)).length, 0);
  } finally {
    await fx.close();
  }
});

const CONSENT_674 = "674a3c52-8d4e-4a7b-9c21-0e5a7d3b9f74";
const CONSENT_675 = "675a3c52-8d4e-4a7b-9c21-0e5a7d3b9f75";
const REVOCATION_675 = "675b3c52-8d4e-4a7b-9c21-0e5a7d3b9f75";

test("TEST-CNS-674: camino feliz HTTP completo — login 01 -> confirmación -> login 02 -> cosign; ack válido y REVOCATION_CONFIRMED válido contra el schema", async () => {
  const opA = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
  const opB = "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e";
  const uuidRoster: readonly StaffPrincipal[] = [
    { principalRef: opA, role: "RIGHTS_OPERATOR" },
    { principalRef: opB, role: "RIGHTS_OPERATOR" },
    { principalRef: "c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f", role: "APPROVER" },
    { principalRef: "d4e5f6a7-b8c9-4d0e-9f2a-3b4c5d6e7f80", role: "APPROVER" },
  ];
  const revocationRef = "6f1b3c52-8d4e-4a7b-9c21-0e5a7d3b9f10";
  const fx = await setUp({ chainRef: "chain-674", caseRef: fixtureUuid("case-674"), revocationRef, consentId: CONSENT_674, roster: uuidRoster });
  try {
    await record(fx, opA);
    const op2 = await login(fx, opB);
    const res = await postCosign(fx.baseUrl, authed(fx, op2));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.deepEqual(body, { cosign: "COSIGNED", revocationState: "APPLIED" }); // Carlos 2026-09-28 (a): R4 síncrono -> APPLIED
    assertValid(validateApiPayload("CaseConfirmationAck", body));

    const stored = await fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, revocationRef);
    assert.equal(stored?.status, "APPLIED"); // R4 síncrono en IT0 (Carlos 2026-09-28); la ack devuelve APPLIED (contrato enmendado)
    assert.equal(stored?.recordedByRef, opA);
    assert.equal(stored?.cosignedByRef, opB); // de la sesión CASE del co-firmante, nunca del body

    const events = await confirmedEvents(fx);
    assert.equal(events.length, 1);
    assert.equal(events[0]?.recordedByRef, opA);
    assert.equal(events[0]?.cosignedByRef, opB);
    assert.notEqual(events[0]?.recordedByRef, events[0]?.cosignedByRef);
    assertValid(validateLedgerEventPayload("REVOCATION_CONFIRMED", events[0]?.payload));
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-675: cosign repetido es idempotente — 200 con el mismo ack y un único REVOCATION_CONFIRMED", async () => {
  const fx = await setUp({ chainRef: "chain-675", caseRef: fixtureUuid("case-675"), revocationRef: REVOCATION_675, consentId: CONSENT_675 });
  try {
    await record(fx, "staff-synthetic-01");
    const op2 = await login(fx, "staff-synthetic-02");
    const first = await postCosign(fx.baseUrl, authed(fx, op2));
    const second = await postCosign(fx.baseUrl, authed(fx, op2));
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    const secondBody = await second.json();
    assert.deepEqual(secondBody, { cosign: "COSIGNED", revocationState: "APPLIED" });
    assertValid(validateApiPayload("CaseConfirmationAck", secondBody));
    assert.equal((await confirmedEvents(fx)).length, 1);
    const events = await fx.revocationPorts.revocation.ledger.listByAggregate(TENANT_ID, "Revocation", fx.revocationRef);
    // CA-127: un solo CONSENT_REVOKED y un solo RECEIPT_CREATED, ambos válidos contra el schema.
    assertRevocationEvidence(events, { revocationRef: REVOCATION_675, authPath: "RECOVERY", recoveryMethod: "HUMAN_ASSISTED", revokedDecisionRef: CONSENT_675 });
  } finally {
    await fx.close();
  }
});
