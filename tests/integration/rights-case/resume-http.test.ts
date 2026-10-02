// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-149 (POST /rights-case/resume),
// specs/state-machines/rights-case.spec.yaml RC2u, specs/state-machines/common.spec.yaml
// GRD-CM-10, ERR-CM-09, ERR-CM-01.
// TEST-CNS-468, TEST-CNS-469, TEST-CNS-470 (traceability/test-matrix.csv).
//
// Levanta el servidor HTTP real (node:http) en un puerto efímero de localhost, con los
// adapters in-memory de src/infra/adapters/**, y hace requests HTTP de verdad (fetch de
// Node) contra él. Cero PII, todo localhost.

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  createRightsCaseHttpServer,
  createDefaultInMemoryPorts,
  type RightsCaseInMemoryPorts,
} from "../../../src/server/entrypoints/http/server.ts";

const ALLOWED_ORIGIN = "http://consola-consent.test.localhost";
const CSRF_COOKIE_NAME = "__Host-cns-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const MANAGE_COOKIE_NAME = "__Host-cns-manage";

interface Harness {
  readonly baseUrl: string;
  readonly ports: RightsCaseInMemoryPorts;
  close(): Promise<void>;
}

function startServer(): Promise<Harness> {
  const ports = createDefaultInMemoryPorts();
  const server: Server = createRightsCaseHttpServer({
    config: { allowedOrigin: ALLOWED_ORIGIN },
    ports,
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        ports,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

async function seedOpenChannelUnreachableCase(ports: Harness["ports"], handle: string): Promise<void> {
  ports.tenantHandle.issue({
    handle,
    tenantId: "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73",
    chainRef: fixtureUuid("chain-1"),
    revokedDecisionRef: fixtureUuid("decision-1"),
  });
  await ports.rightsCaseRepo.save({
    caseRef: fixtureUuid("case-1"),
    tenantId: "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73",
    chainRef: fixtureUuid("chain-1"),
    revokedDecisionRef: fixtureUuid("decision-1"),
    status: "OPEN",
    origin: "CHANNEL_UNREACHABLE",
  });
}

async function postResume(
  baseUrl: string,
  opts: { origin?: string; csrfHeader?: string; csrfCookie?: string; manageHandle?: string },
): Promise<Response> {
  const cookieParts: string[] = [];
  if (opts.manageHandle !== undefined) cookieParts.push(`${MANAGE_COOKIE_NAME}=${opts.manageHandle}`);
  if (opts.csrfCookie !== undefined) cookieParts.push(`${CSRF_COOKIE_NAME}=${opts.csrfCookie}`);

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.csrfHeader !== undefined) headers[CSRF_HEADER_NAME] = opts.csrfHeader;
  if (cookieParts.length > 0) headers.cookie = cookieParts.join("; ");

  return fetch(`${baseUrl}/rights-case/resume`, { method: "POST", headers, body: "{}" });
}

test("TEST-CNS-468: RC2u sin CSRF (Origin ausente) -> ERR-CM-09 (403), sin transición", async () => {
  const harness = await startServer();
  try {
    await seedOpenChannelUnreachableCase(harness.ports, "handle-A");

    const res = await postResume(harness.baseUrl, { manageHandle: "handle-A" });
    assert.equal(res.status, 403);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "CSRF_REJECTED");

    const stored = await harness.ports.rightsCaseRepo.findByRef("0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", fixtureUuid("case-1"));
    assert.equal(stored?.status, "OPEN");
    assert.equal((await harness.ports.ledger.listByAggregate("0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", "RightsCase", fixtureUuid("case-1"))).length, 0);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-468b: RC2u con Origin correcto pero sin token CSRF -> ERR-CM-09 (403), sin transición", async () => {
  const harness = await startServer();
  try {
    await seedOpenChannelUnreachableCase(harness.ports, "handle-A");

    const res = await postResume(harness.baseUrl, { origin: ALLOWED_ORIGIN, manageHandle: "handle-A" });
    assert.equal(res.status, 403);

    const stored = await harness.ports.rightsCaseRepo.findByRef("0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", fixtureUuid("case-1"));
    assert.equal(stored?.status, "OPEN");
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-469: RC2u con Origin de otra consola o sufijo parecido -> ERR-CM-09 uniforme (403), sin transición", async () => {
  const harness = await startServer();
  try {
    await seedOpenChannelUnreachableCase(harness.ports, "handle-A");

    // Origen de otra consola.
    const otherConsole = await postResume(harness.baseUrl, {
      origin: "http://otra-consola.test.localhost",
      csrfHeader: "token-123",
      csrfCookie: "token-123",
      manageHandle: "handle-A",
    });
    assert.equal(otherConsole.status, 403);

    // Sufijo parecido: el origen permitido como substring de un dominio ajeno nunca compara
    // igual (GRD-CM-10 exige igualdad EXACTA, no prefijo/sufijo).
    const lookalike = await postResume(harness.baseUrl, {
      origin: `${ALLOWED_ORIGIN}.evil.test`,
      csrfHeader: "token-123",
      csrfCookie: "token-123",
      manageHandle: "handle-A",
    });
    assert.equal(lookalike.status, 403);

    const stored = await harness.ports.rightsCaseRepo.findByRef("0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", fixtureUuid("case-1"));
    assert.equal(stored?.status, "OPEN");
    assert.equal((await harness.ports.ledger.listByAggregate("0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", "RightsCase", fixtureUuid("case-1"))).length, 0);
  } finally {
    await harness.close();
  }
});

test("TEST-CNS-470: RC2u no consume el handle de /m/; un reintento no duplica RIGHTS_CASE_CONTACTING", async () => {
  const harness = await startServer();
  try {
    await seedOpenChannelUnreachableCase(harness.ports, "handle-A");

    const requestOpts = {
      origin: ALLOWED_ORIGIN,
      csrfHeader: "token-123",
      csrfCookie: "token-123",
      manageHandle: "handle-A",
    };

    const first = await postResume(harness.baseUrl, requestOpts);
    assert.equal(first.status, 200);
    const firstBody = (await first.json()) as { result: string };
    assert.equal(firstBody.result, "IN_REVIEW");

    const afterFirst = await harness.ports.rightsCaseRepo.findByRef("0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", fixtureUuid("case-1"));
    assert.equal(afterFirst?.status, "CONTACTING");
    assert.equal((await harness.ports.ledger.listByAggregate("0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", "RightsCase", fixtureUuid("case-1"))).length, 1);

    // El handle sigue resolviendo: RC2u no lo consume ni lo rota.
    assert.ok(await harness.ports.tenantHandle.resolve("handle-A"));

    // Reintento con el mismo handle (idempotencyKey: caseRef): mismo ack, sin duplicar evento.
    const second = await postResume(harness.baseUrl, requestOpts);
    assert.equal(second.status, 200);
    const secondBody = (await second.json()) as { result: string };
    assert.equal(secondBody.result, "IN_REVIEW");

    const afterSecond = await harness.ports.rightsCaseRepo.findByRef("0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", fixtureUuid("case-1"));
    assert.equal(afterSecond?.status, "CONTACTING");
    assert.equal((await harness.ports.ledger.listByAggregate("0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", "RightsCase", fixtureUuid("case-1"))).length, 1);
  } finally {
    await harness.close();
  }
});
