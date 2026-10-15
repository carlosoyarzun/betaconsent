// Gobierna: ADR-010 rev. 5 §5.2 (login PLATFORM sin principal previo de punta a punta), G-5, G-7, G-8; PR-6b.
// TEST-CNS-1509: extremo a extremo con adaptadores reales (platform_rw e integrity_verifier) + IdP SINTETICO: begin (state) -> callback (state) -> verifier canjea y entrega sub_hmac -> la BASE
//   resuelve el principal -> consume_login_assertion (state correcto, un solo uso). Un sub desconocido queda REJECTED sin persistir el sub_hmac. Cero secretos/PII persistidos.
// Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createPgOidcAuthorization, createPgOidcExchangeStore, nonceBinding } from "../../../src/infra/adapters/postgres/oidc-exchange.adapter.ts";
import { createPool } from "../../../src/infra/adapters/postgres/pool.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";
import { computeSubHmac } from "../../../src/server/modules/step-up/id-token.ts";
import { runVerifierCycle } from "../../../src/server/modules/step-up/verifier.ts";
import type { VerifierConfig } from "../../../src/server/modules/step-up/verifier.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { pgTest } from "./harness.ts";

const ISSUER = "https://idp.synthetic.invalid";
const AUDIENCE = "consent-app-synthetic";
const K_SUB = randomBytes(32);
const config: VerifierConfig = { issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, environment: "LOCAL", subHmacKey: K_SUB };

pgTest("TEST-CNS-1509 pg e2e login PLATFORM: state -> callback -> verifier (IdP sintetico) -> la base resuelve el principal -> consumo de un solo uso con state; sub desconocido REJECTED sin persistir el sub_hmac", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  const platformPool = createPool({ connectionString: ctx.urlFor("platform_rw"), max: 2 });
  const verifierPool = createPool({ connectionString: ctx.urlFor("integrity_verifier"), max: 2 });
  try {
    const A = fixtureUuid("pr6b-e2e-a");
    const SUB = "sub-synthetic-pr6b-a";
    await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, 'PLATFORM', 'PENDING', $2)", [A, fixtureUuid("pr6b-e2e-req")]);
    await admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = $2, approved_at = now() WHERE principal_ref = $1", [A, fixtureUuid("pr6b-e2e-apr")]);
    await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [A, computeSubHmac(K_SUB, ISSUER, SUB)]);
    const idp = new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE });
    const authz = createPgOidcAuthorization(platformPool);
    const store = createPgOidcExchangeStore(verifierPool);

    const flow = async (sub: string): Promise<{ ref: string; state: string }> => {
      const state = randomBytes(24).toString("base64url");
      const nonce = randomBytes(24).toString("base64url");
      const { code, pkceVerifier } = idp.simulateAuthorization({ sub, nonce, acr: "urn:synthetic:mfa", amr: ["pwd", "otp"], email: "persona@example.invalid" });
      const ref = await authz.begin({ kind: "LOGIN_PLATFORM", state, bindingHex: nonceBinding(nonce), pkceVerifier, ttlSeconds: 300, maxAwaiting: null });
      assert.equal(await authz.status({ exchangeRef: ref, state }), "AWAITING_CALLBACK");
      assert.equal(await runVerifierCycle({ store, idp, config }), "IDLE", "AWAITING_CALLBACK todavia no es canjeable");
      assert.equal(await authz.complete({ state: randomBytes(24).toString("base64url"), code }), null, "state ajeno");
      assert.equal(await authz.complete({ state, code }), ref);
      assert.equal(await authz.status({ exchangeRef: ref, state }), "PENDING");
      return { ref, state };
    };

    // Camino feliz.
    const f = await flow(SUB);
    assert.equal(await runVerifierCycle({ store, idp, config }), "ATTESTED");
    assert.equal(await authz.status({ exchangeRef: f.ref, state: f.state }), "ATTESTED");
    const consume = async (ref: string, state: string): Promise<string | null> =>
      (await admin.query<{ p: string | null }>("SELECT platform.consume_login_assertion($1::uuid, $2, 'LOGIN_PLATFORM', NULL) AS p", [ref, state])).rows[0]?.p ?? null;
    assert.equal(await consume(f.ref, randomBytes(24).toString("base64url")), null, "state ajeno no consume");
    assert.equal(await consume(f.ref, f.state), A, "la base entrega el principal que ELLA resolvio");
    assert.equal(await consume(f.ref, f.state), null, "un solo uso");

    // Sub desconocido: REJECTED; el sub_hmac no se persiste; no se crea ningun principal.
    const unknownSub = "sub-synthetic-pr6b-desconocido";
    const g = await flow(unknownSub);
    assert.equal(await runVerifierCycle({ store, idp, config }), "REJECTED");
    assert.equal(await authz.status({ exchangeRef: g.ref, state: g.state }), "REJECTED");
    assert.deepEqual((await admin.query("SELECT decision, reason_code, principal_ref FROM platform.login_assertion WHERE exchange_ref = $1", [g.ref])).rows, [{ decision: "REJECTED", reason_code: "NO_MAPPING", principal_ref: null }]);
    assert.equal(await consume(g.ref, g.state), null);

    // Cero secretos y cero PII persistidos en las tablas de platform.
    const needles = [SUB, unknownSub, computeSubHmac(K_SUB, ISSUER, unknownSub), "example.invalid", f.state, g.state, "@"];
    for (const t of ["oidc_exchange", "login_assertion", "session_event", "grant_assertion", "authorization_check"]) {
      for (const needle of needles) assert.equal((await admin.query(`SELECT 1 FROM platform.${t} x WHERE strpos(x::text, $1) > 0`, [needle])).rowCount, 0, `${t} contiene ${needle.slice(0, 8)}`);
    }
    assert.equal((await admin.query("SELECT 1 FROM platform.oidc_exchange WHERE status IN ('ATTESTED', 'REJECTED') AND (code IS NOT NULL OR pkce_verifier IS NOT NULL)")).rowCount, 0);
  } finally {
    await platformPool.end();
    await verifierPool.end();
  }
});
