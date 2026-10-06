// Gobierna: CA-140, contracts/openapi/consent-it0.openapi.yaml API-CNS-192 (POST /staff/logout) y API-CNS-193 (POST /platform/case-session/logout),
// contracts/schemas/api-payloads.schema.json (EmptyCommand) y common.schema.json (Problem), specs/session.spec.yaml GRD-SE-09.
// Levanta el servidor HTTP real y valida la RESPUESTA (estado, cuerpo, cabeceras, cookies) contra el esquema declarado en el contrato.
// Solo datos sinteticos.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createInMemoryCaseSessionStore } from "../../../src/infra/adapters/in-memory-case-session-store.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import { createInMemoryStaffSessionStore } from "../../../src/infra/adapters/in-memory-staff-session-store.adapter.ts";
import { LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG, LOCAL_ONLY_DEV_TENANT_ID } from "../../../src/server/entrypoints/dev-local-config.ts";
import { createConsentFlowHttpServer, createDefaultConsentFlowPorts, createDefaultRevocationFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import { caseCsrfTokenFor, deriveCaseSessionKey, issueCaseSession } from "../../../src/server/entrypoints/http/case-session.ts";
import { deriveStaffSessionKey, issueStaffSession, staffCsrfTokenFor } from "../../../src/server/entrypoints/http/staff-session.ts";
import { parseYaml, type YamlValue } from "../../../tools/spec-checks/yaml-lite.ts";
import { validateCommon } from "../schema-lite.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
type Rec = Record<string, YamlValue>;
const api = parseYaml(readFileSync(resolve(ROOT, "contracts", "openapi", "consent-it0.openapi.yaml"), "utf-8")) as Rec;
const operation = (path: string): Rec => ((api.paths as Rec)[path] as Rec).post as Rec;

const ORIGIN = "http://consola-logout-contract.test.localhost";
const SECRET = Buffer.alloc(32, 3);
const TENANT = LOCAL_ONLY_DEV_TENANT_ID;
const ADMIN = fixtureUuid("logout-contract-admin");
const OPERATOR = fixtureUuid("logout-contract-operator");
const CASE_REF = fixtureUuid("logout-contract-case");

async function start(): Promise<{ baseUrl: string; staffSessions: ReturnType<typeof createInMemoryStaffSessionStore>; caseSessions: ReturnType<typeof createInMemoryCaseSessionStore>; close(): Promise<void> }> {
  const ports = createDefaultConsentFlowPorts(LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG);
  const revocationPorts = createDefaultRevocationFlowPorts({ ttlMs: 60_000 }, ports.decision.ledger, ports.decision.repo);
  const staffIdentity = createInMemoryStaffIdentityAdapter([
    { principalRef: ADMIN, role: "TENANT_ADMIN", tenantId: TENANT },
    { principalRef: OPERATOR, role: "RIGHTS_OPERATOR" },
  ]);
  const staffSessions = createInMemoryStaffSessionStore();
  const caseSessions = createInMemoryCaseSessionStore();
  const staffConsole = { sessions: staffSessions } as unknown as NonNullable<NonNullable<Parameters<typeof createConsentFlowHttpServer>[0]>["staffConsole"]>;
  const server: Server = createConsentFlowHttpServer({
    config: { allowedOrigin: ORIGIN }, ports, revocationPorts, sessionSecret: SECRET, environment: "LOCAL", staffIdentity, staffConsole, caseSessions,
  });
  const baseUrl = await new Promise<string>((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
  return { baseUrl, staffSessions, caseSessions, close: () => new Promise((r) => server.close(() => r())) };
}

test("TEST-CNS-1185 contrato API-CNS-192: POST /staff/logout declara 200 {} y 403 CsrfRejected; la respuesta real cumple el esquema, no-store y borra cookies", async () => {
  const op = operation("/staff/logout");
  assert.equal(op["x-api-id"], "API-CNS-192");
  const ok = ((op.responses as Rec)["200"] as Rec).content as Rec;
  const schema = (ok["application/json"] as Rec).schema as Rec;
  assert.deepEqual([schema.type, schema.additionalProperties], ["object", false]);
  assert.deepEqual(((op.responses as Rec)["403"] as Rec).$ref, "#/components/responses/CsrfRejected");
  const h = await start();
  try {
    const key = deriveStaffSessionKey(SECRET);
    const s = await issueStaffSession({ sessions: h.staffSessions, staffSessionKey: key }, { tenantId: TENANT, principalRef: ADMIN, role: "TENANT_ADMIN" });
    const cookie = `__Host-cns-staff=${s.cookieValue}; __Host-cns-staff-csrf=${s.csrfToken}`;
    const call = (csrf: string, ck: string): Promise<Response> => fetch(`${h.baseUrl}/staff/logout`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": csrf, cookie: ck }, body: "{}" });
    const bad = await call("otro", `__Host-cns-staff=${s.cookieValue}; __Host-cns-staff-csrf=otro`);
    assert.equal(bad.status, 403);
    assert.match(bad.headers.get("content-type") ?? "", /application\/problem\+json/);
    const problem = await bad.json();
    const verdict = validateCommon("Problem", problem);
    assert.ok(verdict.ok, verdict.errors.join("\n"));
    assert.equal(staffCsrfTokenFor(key, s.sid) === s.csrfToken, true);
    const res = await call(s.csrfToken, cookie);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /application\/json/);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.deepEqual(await res.json(), {});
    const cleared = res.headers.getSetCookie();
    for (const name of ["__Host-cns-staff", "__Host-cns-staff-csrf", "__Host-cns-staff-flash"]) assert.ok(cleared.some((c) => c.startsWith(`${name}=;`) && c.includes("Max-Age=0")), name);
  } finally {
    await h.close();
  }
});

test("TEST-CNS-1186 contrato API-CNS-193: POST /platform/case-session/logout declara 200 {} y 403 CsrfRejected; la respuesta real cumple el esquema, no-store y borra cookies", async () => {
  const op = operation("/platform/case-session/logout");
  assert.equal(op["x-api-id"], "API-CNS-193");
  const ok = ((op.responses as Rec)["200"] as Rec).content as Rec;
  const schema = (ok["application/json"] as Rec).schema as Rec;
  assert.deepEqual([schema.type, schema.additionalProperties], ["object", false]);
  assert.deepEqual(((op.responses as Rec)["403"] as Rec).$ref, "#/components/responses/CsrfRejected");
  const h = await start();
  try {
    const key = deriveCaseSessionKey(SECRET);
    const s = await issueCaseSession({ sessions: h.caseSessions, caseSessionKey: key }, { tenantId: TENANT, caseRef: CASE_REF, principalRef: OPERATOR, role: "RIGHTS_OPERATOR" });
    const call = (csrf: string, ck: string): Promise<Response> => fetch(`${h.baseUrl}/platform/case-session/logout`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": csrf, cookie: ck }, body: "{}" });
    const bad = await call("otro", `__Host-cns-case=${s.cookieValue}; __Host-cns-case-csrf=otro`);
    assert.equal(bad.status, 403);
    assert.match(bad.headers.get("content-type") ?? "", /application\/problem\+json/);
    const verdict = validateCommon("Problem", await bad.json());
    assert.ok(verdict.ok, verdict.errors.join("\n"));
    assert.equal(caseCsrfTokenFor(key, s.sid) === s.csrfToken, true);
    const res = await call(s.csrfToken, `__Host-cns-case=${s.cookieValue}; __Host-cns-case-csrf=${s.csrfToken}`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /application\/json/);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.deepEqual(await res.json(), {});
    const cleared = res.headers.getSetCookie();
    for (const name of ["__Host-cns-case", "__Host-cns-case-csrf"]) assert.ok(cleared.some((c) => c.startsWith(`${name}=;`) && c.includes("Max-Age=0")), name);
  } finally {
    await h.close();
  }
});
