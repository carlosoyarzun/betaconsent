// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-128 (POST /decision/subject-mismatch: solo 200/403/404), invitation.spec I9,
// ERR-IV-09, specs/db-roles.spec.yaml Q-18-I9. Un conflicto de secuencia del ledger que agota los reintentos del UoW (RV409 ->
// LedgerSequenceConflictError) o un rechazo de guard (ERR-IV-09) responden 404 uniforme, nunca 500. TEST-CNS-1445.

import test from "node:test";
import assert from "node:assert/strict";

import { handleReportSubjectMismatch } from "../../../src/server/entrypoints/http/consent-flow.handler.ts";
import { encodeSession } from "../../../src/server/entrypoints/http/consent-session.ts";
import { loadRightsCaseHttpConfig } from "../../../src/server/entrypoints/http/config.ts";
import { DomainError } from "../../../src/server/modules/common/errors.ts";
import { LedgerSequenceConflictError } from "../../../src/server/ports/ledger.port.ts";

const SECRET = Buffer.alloc(32, 5);
const ORIGIN = "http://consola-consent.test.localhost";
const config = loadRightsCaseHttpConfig({ allowedOrigin: ORIGIN });

function request() {
  const session = encodeSession(SECRET, { tenantId: "0a96abb3-3b07-4f0e-8f48-bcc4893e0e73", invitationRef: "inv", verificationRef: "ver", decisionMakerRef: "dm" } as never);
  return {
    originHeader: ORIGIN,
    csrfHeaderToken: "csrf-token-abcdefgh",
    cookieHeader: `${config.csrfCookieName}=csrf-token-abcdefgh; ${config.sessionCookieName}=${session}`,
    body: {},
  };
}

const portsThrowing = (error: unknown) => ({ invitation: { uow: { inTenant: async () => { throw error; } } } }) as never;

test("TEST-CNS-1445: subject-mismatch responde 404 uniforme (no 500) ante LedgerSequenceConflictError (RV409 agotado) y ante ERR-IV-09; un error inesperado sigue propagándose", async () => {
  const conflict = await handleReportSubjectMismatch(request(), portsThrowing(new LedgerSequenceConflictError(0, 1)), config, SECRET);
  assert.equal(conflict.status, 404);
  assert.deepEqual(conflict.body, { status: 404 });
  const guard = await handleReportSubjectMismatch(request(), portsThrowing(new DomainError("ERR-IV-09")), config, SECRET);
  assert.equal(guard.status, 404);
  await assert.rejects(() => handleReportSubjectMismatch(request(), portsThrowing(new Error("boom")), config, SECRET), /boom/);
});
