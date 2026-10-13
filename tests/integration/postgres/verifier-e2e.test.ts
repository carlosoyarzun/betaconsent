// Gobierna: ADR-010 rev. 4 §4.3 (nonce, canje en el verifier, aserciones, step-up), §7 fila PR-4 (DF-4, F-X8-15); F-A10-12 (sub_hmac <-> principal_ref); F-A10-13 (COMMIT ante un DENY y
// error generico); specs/db-roles.spec.yaml; db/migrations/0036_adr010_verifier_assertions.sql.
// TEST-CNS-1372: extremo a extremo con los adaptadores reales: IdP SINTETICO (sin egress) + modulo verifier + adaptadores Postgres como platform_rw e integrity_verifier.
//   Camino feliz (ATTESTED habilita el step-up), sub de otra persona (la base degrada), DENY con evidencia confirmada y error uniforme, y cero secretos/PII persistidos.
// Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos.

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createPgOidcExchangeQueue, createPgOidcExchangeStore, nonceBinding } from "../../../src/infra/adapters/postgres/oidc-exchange.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { withPlatformTransaction } from "../../../src/infra/adapters/postgres/platform-call.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";
import { computeSubHmac } from "../../../src/server/modules/step-up/id-token.ts";
import { runVerifierCycle } from "../../../src/server/modules/step-up/verifier.ts";
import type { VerifierConfig } from "../../../src/server/modules/step-up/verifier.ts";
import { PlatformDeniedError } from "../../../src/server/ports/oidc-exchange.port.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const ISSUER = "https://idp.synthetic.invalid";
const AUDIENCE = "consent-app-synthetic";
const K_SUB = randomBytes(32);
const SEED_REQ = fixtureUuid("e2e-seed-requester");
const SEED_APR = fixtureUuid("e2e-seed-approver");
const config: VerifierConfig = { issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, environment: "LOCAL", subHmacKey: K_SUB };

pgTest("TEST-CNS-1372 pg: e2e con IdP sintetico: el verifier atesta el step-up y la accion se autoriza; sub ajeno => REJECTED; DENY confirma la evidencia y responde un error uniforme; sin secretos ni PII persistidos", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platformPool = createPool({ connectionString: ctx.urlFor("platform_rw"), max: 2 });
  const verifierPool = createPool({ connectionString: ctx.urlFor("integrity_verifier"), max: 2 });
  try {
    const A = fixtureUuid("e2e-platform-a");
    const TARGET = fixtureUuid("e2e-target");
    const SUB = "sub-synthetic-e2e-a";
    await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, 'PLATFORM', 'PENDING', $2)", [A, SEED_REQ]);
    await admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = $2, approved_at = now() WHERE principal_ref = $1", [A, SEED_APR]);
    await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [A, computeSubHmac(K_SUB, ISSUER, SUB)]);

    const idp = new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE });
    const queue = createPgOidcExchangeQueue(platformPool);
    const store = createPgOidcExchangeStore(verifierPool);
    const resource = `${TARGET}:RIGHTS_OPERATOR`;
    const issue = async (): Promise<string> => {
      const rows = await withPlatformTransaction(platformPool, A, async (tx) =>
        (await tx.query<{ n: string | null }>("SELECT platform.issue_action_nonce('REQUEST_ROLE_ASSIGNMENT', ARRAY[$1]::text[], NULL, 300) AS n", [resource])).rows);
      const n = rows[0]?.n;
      assert.ok(typeof n === "string");
      return n;
    };
    const request = async (): Promise<string | null> =>
      (await withPlatformTransaction(platformPool, A, async (tx) => (await tx.query<{ r: string | null }>("SELECT platform.request_role_assignment($1, 'RIGHTS_OPERATOR', NULL) AS r", [TARGET])).rows))[0]?.r ?? null;

    // 0. Sin el verifier, la accion falla cerrada (F-X8-15: la sola presencia de stepUpAssertion ya no cuenta).
    assert.equal(await request(), null);
    assert.equal(await runVerifierCycle({ store, idp, config }), "IDLE");

    // 1. Camino feliz: nonce -> el navegador autentica en el IdP con ese nonce -> platform encola code + PKCE -> el verifier canjea y atesta -> la accion se autoriza.
    const nonce = await issue();
    const { code, pkceVerifier } = idp.simulateAuthorization({ sub: SUB, nonce, acr: "urn:synthetic:mfa", amr: ["pwd", "otp"], email: "persona@example.invalid" });
    const exchangeRef = await queue.enqueue({ principalRef: A, actionNonce: nonce, code, pkceVerifier, ttlSeconds: 60 });
    assert.match(exchangeRef, /^[0-9a-f-]{36}$/);
    assert.equal(await runVerifierCycle({ store, idp, config }), "ATTESTED");
    assert.equal(await runVerifierCycle({ store, idp, config }), "IDLE", "la solicitud se consumio");
    const reqRef = await request();
    assert.ok(typeof reqRef === "string", "con el nonce ATTESTED la accion se autoriza");
    assert.equal(await request(), null, "el nonce era de un solo uso");

    // 2. Otra persona (sub distinto) se autentica con el nonce de A: la base degrada a REJECTED/SUB_MISMATCH y el nonce NO queda atestado.
    const nonce2 = await issue();
    const intruder = idp.simulateAuthorization({ sub: "sub-synthetic-e2e-intruso", nonce: nonce2 });
    await queue.enqueue({ principalRef: A, actionNonce: nonce2, code: intruder.code, pkceVerifier: intruder.pkceVerifier, ttlSeconds: 60 });
    assert.equal(await runVerifierCycle({ store, idp, config }), "REJECTED");
    assert.equal((await admin.query("SELECT 1 FROM platform.action_nonce WHERE nonce_hash = $1 AND attested_at IS NOT NULL", [nonceBinding(nonce2)])).rowCount, 0);
    assert.deepEqual((await admin.query("SELECT decision, reason_code FROM platform.grant_assertion WHERE binding = $1", [nonceBinding(nonce2)])).rows, [{ decision: "REJECTED", reason_code: "SUB_MISMATCH" }]);

    // 3. Canje fallido en el IdP (PKCE equivocado): REJECTED/EXCHANGE_FAILED.
    const nonce3 = await issue();
    const t3 = idp.simulateAuthorization({ sub: SUB, nonce: nonce3 });
    await queue.enqueue({ principalRef: A, actionNonce: nonce3, code: t3.code, pkceVerifier: "otro-verifier-".padEnd(43, "q"), ttlSeconds: 60 });
    assert.equal(await runVerifierCycle({ store, idp, config }), "REJECTED");
    assert.deepEqual((await admin.query("SELECT decision, reason_code FROM platform.grant_assertion WHERE binding = $1", [nonceBinding(nonce3)])).rows, [{ decision: "REJECTED", reason_code: "EXCHANGE_FAILED" }]);

    // 4. F-A10-13: un DENY de la base (nonce que no es del principal) se confirma como evidencia y el adaptador responde un error UNIFORME, sin motivo.
    const before = (await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.authorization_check WHERE principal_ref = $1 AND check_kind = 'ENQUEUE_EXCHANGE' AND decision = 'DENY'", [A])).rows[0]!.n;
    await assert.rejects(
      () => queue.enqueue({ principalRef: A, actionNonce: "nonce-que-nadie-emitio", code: "code-x", pkceVerifier: "p".repeat(43), ttlSeconds: 60 }),
      (e) => e instanceof PlatformDeniedError && e.message === "platform: operacion no autorizada",
    );
    const after = (await admin.query<{ n: string }>("SELECT count(*)::text AS n FROM platform.authorization_check WHERE principal_ref = $1 AND check_kind = 'ENQUEUE_EXCHANGE' AND decision = 'DENY'", [A])).rows[0]!.n;
    assert.equal(Number(after), Number(before) + 1, "la evidencia del DENY se confirmo (COMMIT)");
    // Principal con forma invalida (la forma vieja): ni llega a la base.
    await assert.rejects(() => queue.enqueue({ principalRef: "staff-synthetic-01", actionNonce: nonce, code: "c", pkceVerifier: "p".repeat(43), ttlSeconds: 60 }), PlatformDeniedError);

    // 5. Cero secretos y cero PII persistidos: ni code, ni PKCE, ni sub en claro, ni email, ni el nonce en claro en ninguna tabla de platform.
    const needles = [code, pkceVerifier, intruder.code, SUB, "sub-synthetic-e2e-intruso", "example.invalid", nonce, nonce2, nonce3, "@"];
    for (const t of ["oidc_exchange", "grant_assertion", "authorization_check", "action_nonce", "principal_identity", "platform_role_assignment", "tenant_membership"]) {
      for (const needle of needles) {
        assert.equal((await admin.query(`SELECT 1 FROM platform.${t} x WHERE strpos(x::text, $1) > 0`, [needle])).rowCount, 0, `${t} contiene ${needle.slice(0, 6)}`);
      }
    }
    assert.equal((await admin.query("SELECT 1 FROM platform.oidc_exchange WHERE status <> 'PENDING' AND (code IS NOT NULL OR pkce_verifier IS NOT NULL)")).rowCount, 0);
    // El hash del token (assertion_hash) es de 64 hex y no el token.
    const hash = (await admin.query<{ assertion_hash: string }>("SELECT assertion_hash FROM platform.grant_assertion WHERE exchange_ref = $1", [exchangeRef])).rows[0]?.assertion_hash;
    assert.ok(typeof hash === "string" && /^[0-9a-f]{64}$/.test(hash) && hash !== createHash("sha256").update(nonce).digest("hex"));
  } finally {
    await platformPool.end();
    await verifierPool.end();
  }
});
