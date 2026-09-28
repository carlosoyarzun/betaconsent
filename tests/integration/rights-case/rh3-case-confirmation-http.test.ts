// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-138 (POST
// /platform/rights-cases/{caseRef}/confirmation, securitySchemes.caseSession);
// specs/state-machines/revocation.spec.yaml RH3 paso 1 (GRD-RV-10/ERR-RV-20);
// specs/state-machines/rights-case.spec.yaml GRD-RC-15/ERR-RC-10; CA-128. Recorre el camino
// HTTP real (node:http en un puerto efímero de localhost): RC1 abierto -> RH2 (atestado
// directo, sin HTTP en este slice) -> /__dev/staff-login (LOCAL-only, Carlos 2026-09-28 opción
// (ii)) -> RH3 paso 1 registrado. Cubre además los guards técnicos citados en la tarea CA-128
// (GRD-CM-01/06/07/10, GRD-RC-15, GRD-RV-20) y la validación de la respuesta contra el
// contrato (schema-lite).
// TEST-CNS-637..644.

import test from "node:test";
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
import { validateApiPayload, type ValidationResult } from "../../contract/schema-lite.ts";

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
  const consentId = `consent-${opts.chainRef}`;
  const ports: ConsentFlowPorts = createDefaultConsentFlowPorts(LOCAL_ONLY_TEST_OTP_POLICY, LOCAL_ONLY_TEST_RELATIONSHIP_CONFIG);
  ports.decision.repo.save({
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
  revocationPorts.rightsCase.rightsCaseRepo.save({
    caseRef: opts.caseRef,
    tenantId: TENANT_ID,
    chainRef: opts.chainRef,
    revokedDecisionRef: consentId,
    status: "OPEN",
  });

  // Revocation REQUESTED -> RH2 (attestHumanAssistedVerification, VERIFIED + attestedVerification).
  revocationPorts.revocation.revocationRepo.save({
    revocationRef: opts.revocationRef,
    tenantId: TENANT_ID,
    chainRef: opts.chainRef,
    caseRef: opts.caseRef,
    status: "REQUESTED",
  });
  attestHumanAssistedVerification(revocationPorts.revocation, TENANT_ID, opts.revocationRef, opts.caseRef);

  // RC3 (liga la Revocation al caso, mismo efecto que expressRevocationIntentInCase sin repetir
  // el handle HTTP en este slice): el handler resuelve el revocationRef desde el caso.
  revocationPorts.rightsCase.rightsCaseRepo.save({
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

test("TEST-CNS-637: sin sesión CASE (cookie ausente, CSRF válido) -> 404 uniforme (GRD-CM-01)", async () => {
  const fx = await setUp({ chainRef: "chain-637", caseRef: "case-637", revocationRef: "rv-637" });
  try {
    // CSRF double-submit válido (cookie == header) pero SIN __Host-cns-case: GRD-CM-10 pasa,
    // GRD-CM-01 (sin sesión CASE) es lo que se está probando aquí.
    const csrf = "csrf-token-abcdefgh";
    const res = await postConfirmation(fx.baseUrl, { caseRef: fx.caseRef, caseCsrfCookie: csrf, origin: ALLOWED_ORIGIN, csrfHeader: csrf });
    assert.equal(res.status, 404);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-638: sesión CASE con rol APPROVER (no RIGHTS_OPERATOR) -> ERR-CM-10 (GRD-CM-07)", async () => {
  const fx = await setUp({ chainRef: "chain-638", caseRef: "case-638", revocationRef: "rv-638" });
  try {
    const login = await devStaffLogin(fx.baseUrl, { tenantId: TENANT_ID, caseRef: fx.caseRef, principalRef: "staff-synthetic-03" });
    assert.equal(login.res.status, 200);
    const res = await postConfirmation(fx.baseUrl, {
      caseRef: fx.caseRef,
      caseSessionCookie: login.caseSessionCookie,
      caseCsrfCookie: login.caseCsrfCookie,
      origin: ALLOWED_ORIGIN,
      csrfHeader: login.caseCsrfCookie,
    });
    assert.equal(res.status, 403);
    assert.equal((await res.json() as { code: string }).code, "ERR-CM-10");
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-639: /__dev/staff-login ausente fuera de LOCAL -> 404 (GRD-CM-13)", async () => {
  const fx = await setUp({ chainRef: "chain-639", caseRef: "case-639", revocationRef: "rv-639", environment: "DEV" });
  try {
    const login = await devStaffLogin(fx.baseUrl, { tenantId: TENANT_ID, caseRef: fx.caseRef, principalRef: "staff-synthetic-01" });
    assert.equal(login.res.status, 404);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-640: recordedByRef enviado en el body se ignora — el ledger/proyección usa siempre el de la sesión (GRD-CM-07)", async () => {
  const fx = await setUp({ chainRef: "chain-640", caseRef: "case-640", revocationRef: "rv-640" });
  try {
    const login = await devStaffLogin(fx.baseUrl, { tenantId: TENANT_ID, caseRef: fx.caseRef, principalRef: "staff-synthetic-01" });
    const res = await postConfirmation(fx.baseUrl, {
      caseRef: fx.caseRef,
      caseSessionCookie: login.caseSessionCookie,
      caseCsrfCookie: login.caseCsrfCookie,
      origin: ALLOWED_ORIGIN,
      csrfHeader: login.caseCsrfCookie,
      body: { confirmationGivenOnCasePage: true, recordedByRef: "attacker-claims-someone-else" },
    });
    assert.equal(res.status, 200);
    const stored = fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, fx.revocationRef);
    assert.equal(stored?.recordedByRef, "staff-synthetic-01");
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-641: CSRF/Origin incorrecto -> 403 CSRF_REJECTED (GRD-CM-10)", async () => {
  const fx = await setUp({ chainRef: "chain-641", caseRef: "case-641", revocationRef: "rv-641" });
  try {
    const login = await devStaffLogin(fx.baseUrl, { tenantId: TENANT_ID, caseRef: fx.caseRef, principalRef: "staff-synthetic-01" });
    const res = await postConfirmation(fx.baseUrl, {
      caseRef: fx.caseRef,
      caseSessionCookie: login.caseSessionCookie,
      caseCsrfCookie: login.caseCsrfCookie,
      origin: "http://otro-origen.test.localhost",
      csrfHeader: login.caseCsrfCookie,
    });
    assert.equal(res.status, 403);
    assert.equal((await res.json() as { code: string }).code, "CSRF_REJECTED");
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-642: caseRef del path que no coincide con la sesión CASE -> 404 uniforme (contracts/openapi CaseRef)", async () => {
  const fx = await setUp({ chainRef: "chain-642", caseRef: "case-642", revocationRef: "rv-642" });
  try {
    const login = await devStaffLogin(fx.baseUrl, { tenantId: TENANT_ID, caseRef: fx.caseRef, principalRef: "staff-synthetic-01" });
    const res = await postConfirmation(fx.baseUrl, {
      caseRef: "case-otro-distinto",
      caseSessionCookie: login.caseSessionCookie,
      caseCsrfCookie: login.caseCsrfCookie,
      origin: ALLOWED_ORIGIN,
      csrfHeader: login.caseCsrfCookie,
    });
    assert.equal(res.status, 404);
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-643: dotación insuficiente (<4 personas) -> ERR-RC-10 (GRD-RC-15), 409, caso sigue abierto", async () => {
  const shortRoster: readonly StaffPrincipal[] = [
    { principalRef: "staff-synthetic-01", role: "RIGHTS_OPERATOR" },
    { principalRef: "staff-synthetic-03", role: "APPROVER" },
  ];
  const fx = await setUp({ chainRef: "chain-643", caseRef: "case-643", revocationRef: "rv-643", roster: shortRoster });
  try {
    const login = await devStaffLogin(fx.baseUrl, { tenantId: TENANT_ID, caseRef: fx.caseRef, principalRef: "staff-synthetic-01" });
    const res = await postConfirmation(fx.baseUrl, {
      caseRef: fx.caseRef,
      caseSessionCookie: login.caseSessionCookie,
      caseCsrfCookie: login.caseCsrfCookie,
      origin: ALLOWED_ORIGIN,
      csrfHeader: login.caseCsrfCookie,
    });
    assert.equal(res.status, 409);
    assert.equal((await res.json() as { code: string }).code, "ERR-RC-10");
  } finally {
    await fx.close();
  }
});

test("TEST-CNS-644: camino feliz — RC1 abierto -> RH2 atestado -> RH3 paso 1 registrado por HTTP; respuesta válida contra CaseConfirmationAck", async () => {
  const fx = await setUp({ chainRef: "chain-644", caseRef: "case-644", revocationRef: "rv-644" });
  try {
    const login = await devStaffLogin(fx.baseUrl, { tenantId: TENANT_ID, caseRef: fx.caseRef, principalRef: "staff-synthetic-02" });
    assert.equal(login.res.status, 200);
    assert.deepEqual(await login.res.json(), { principalRef: "staff-synthetic-02", role: "RIGHTS_OPERATOR" });

    const res = await postConfirmation(fx.baseUrl, {
      caseRef: fx.caseRef,
      caseSessionCookie: login.caseSessionCookie,
      caseCsrfCookie: login.caseCsrfCookie,
      origin: ALLOWED_ORIGIN,
      csrfHeader: login.caseCsrfCookie,
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.deepEqual(body, { cosign: "AWAITING_COSIGN", revocationState: "VERIFIED" });
    assertValid(validateApiPayload("CaseConfirmationAck", body));

    // Sin efecto sobre la Revocation (RH3 paso 1: effect none) — el caso "sigue abierto".
    const stored = fx.revocationPorts.revocation.revocationRepo.findByRef(TENANT_ID, fx.revocationRef);
    assert.equal(stored?.status, "VERIFIED");
    assert.equal(stored?.recordedByRef, "staff-synthetic-02");
    assert.equal(stored?.cosignedByRef, undefined);

    // Idempotente (x-idempotency: revocationRef): un segundo POST no falla ni cambia el estado.
    const again = await postConfirmation(fx.baseUrl, {
      caseRef: fx.caseRef,
      caseSessionCookie: login.caseSessionCookie,
      caseCsrfCookie: login.caseCsrfCookie,
      origin: ALLOWED_ORIGIN,
      csrfHeader: login.caseCsrfCookie,
    });
    assert.equal(again.status, 200);
    assert.deepEqual(await again.json(), { cosign: "AWAITING_COSIGN", revocationState: "VERIFIED" });
  } finally {
    await fx.close();
  }
});
