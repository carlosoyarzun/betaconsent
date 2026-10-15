// Gobierna: ADR-010 rev. 5 §5.2 pasos 1-7 (login PLATFORM, sesion PLATFORM, login CASE con esa sesion, sesion CASE, logout) con adaptadores reales (platform_rw e integrity_verifier) + IdP SINTETICO; PR-6c.
// TEST-CNS-1560: extremo a extremo: begin -> callback -> verifier -> open_platform_session -> validate -> begin LOGIN_CASE (sessionSid) -> verifier -> open_case_session (grant sembrado) -> logout en cascada.
//   Cero sid/state/PII persistidos en claro. Requiere Postgres real (harness.ts); skip sin entorno. Solo sinteticos.

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createPgOidcAuthorization, createPgOidcExchangeStore, nonceBinding } from "../../../src/infra/adapters/postgres/oidc-exchange.adapter.ts";
import { createPgPlatformSessionStore } from "../../../src/infra/adapters/postgres/platform-session.adapter.ts";
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
const LIFE = { absoluteSeconds: 3600, idleSeconds: 600 };

pgTest("TEST-CNS-1560 pg e2e: login PLATFORM -> sesion PLATFORM -> login CASE con esa sesion -> sesion CASE (grant) -> logout en cascada; sin sid ni state en claro", async (ctx) => {
  const admin = await ctx.fixtureAdmin();
  const platformPool = createPool({ connectionString: ctx.urlFor("platform_rw"), max: 2 });
  const verifierPool = createPool({ connectionString: ctx.urlFor("integrity_verifier"), max: 2 });
  try {
    const A = fixtureUuid("pr6c-e2e-a");
    const SUB = "sub-synthetic-pr6c-a";
    const CASE = fixtureUuid("pr6c-e2e-case");
    await admin.query("INSERT INTO platform.platform_role_assignment (principal_ref, platform_role, status, requested_by_ref) VALUES ($1, 'RIGHTS_OPERATOR', 'PENDING', $2)", [A, fixtureUuid("pr6c-e2e-req")]);
    await admin.query("UPDATE platform.platform_role_assignment SET status = 'ACTIVE', approved_by_ref = $2, approved_at = now() WHERE principal_ref = $1", [A, fixtureUuid("pr6c-e2e-apr")]);
    await admin.query("INSERT INTO platform.principal_identity (principal_ref, sub_hmac) VALUES ($1, $2)", [A, computeSubHmac(K_SUB, ISSUER, SUB)]);
    await admin.query("INSERT INTO platform.rights_case_grant (tenant_id, case_ref, operator_principal_ref, expires_at) VALUES ($1, $2, $3, now() + interval '1 hour')", [fixtureUuid("pr6c-e2e-tenant"), CASE, A]);
    const idp = new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE });
    const authz = createPgOidcAuthorization(platformPool);
    const store = createPgOidcExchangeStore(verifierPool);
    const sessions = createPgPlatformSessionStore(platformPool);

    const login = async (input: { kind: "LOGIN_PLATFORM" | "LOGIN_CASE"; sessionSid?: string; targetRefHash?: string }): Promise<{ ref: string; state: string }> => {
      const state = randomBytes(24).toString("base64url");
      const nonce = randomBytes(24).toString("base64url");
      const { code, pkceVerifier } = idp.simulateAuthorization({ sub: SUB, nonce, acr: "urn:synthetic:mfa", amr: ["pwd", "otp"], email: "persona@example.invalid" });
      const ref = await authz.begin({ ...input, state, bindingHex: nonceBinding(nonce), pkceVerifier, ttlSeconds: 300, maxAwaiting: null });
      assert.equal(await authz.complete({ state, code }), ref);
      assert.equal(await runVerifierCycle({ store, idp, config }), "ATTESTED");
      return { ref, state };
    };

    const f1 = await login({ kind: "LOGIN_PLATFORM" });
    // El state ajeno no abre; el correcto abre y la sesion valida con el principal que resolvio la base.
    assert.equal(await sessions.openPlatformSession({ exchangeRef: f1.ref, state: randomBytes(24).toString("base64url"), lifetime: LIFE }), null);
    const platformSid = (await sessions.openPlatformSession({ exchangeRef: f1.ref, state: f1.state, lifetime: LIFE }))!;
    assert.match(platformSid, /^[0-9a-f]{64}$/);
    assert.equal(await sessions.openPlatformSession({ exchangeRef: f1.ref, state: f1.state, lifetime: LIFE }), null, "un solo uso");
    const v = (await sessions.validate({ sid: platformSid, kind: "PLATFORM" }))!;
    assert.deepEqual({ k: v.kind, p: v.principalRef, c: v.caseRef }, { k: "PLATFORM", p: A, c: null });
    assert.equal(await sessions.validate({ sid: platformSid, kind: "CASE" }), null);

    // LOGIN_CASE: la base valida la sesion (sid); el principal NO se declara.
    await assert.rejects(authz.begin({ kind: "LOGIN_CASE", principalRef: A, state: "x".repeat(32), bindingHex: nonceBinding("n"), pkceVerifier: "p".repeat(64), targetRefHash: createHash("sha256").update(CASE).digest("hex"), ttlSeconds: 300, maxAwaiting: null }));
    await assert.rejects(authz.begin({ kind: "LOGIN_CASE", sessionSid: "a".repeat(64), state: randomBytes(24).toString("base64url"), bindingHex: nonceBinding("n2"), pkceVerifier: "p".repeat(64), targetRefHash: createHash("sha256").update(CASE).digest("hex"), ttlSeconds: 300, maxAwaiting: null }), "sid ajeno");
    const target = createHash("sha256").update(CASE).digest("hex");
    const f2 = await login({ kind: "LOGIN_CASE", sessionSid: platformSid, targetRefHash: target });
    assert.equal(await sessions.openCaseSession({ exchangeRef: f2.ref, state: f2.state, caseRef: fixtureUuid("pr6c-e2e-otro-caso"), platformSid, lifetime: LIFE }), null, "la asercion no sirve para otro caso");
    const caseSid = (await sessions.openCaseSession({ exchangeRef: f2.ref, state: f2.state, caseRef: CASE, platformSid, lifetime: LIFE }))!;
    assert.match(caseSid, /^[0-9a-f]{64}$/);
    const vc = (await sessions.validate({ sid: caseSid, kind: "CASE" }))!;
    assert.deepEqual({ k: vc.kind, p: vc.principalRef, c: vc.caseRef }, { k: "CASE", p: A, c: CASE });

    // Logout PLATFORM: cae tambien la sesion CASE.
    assert.equal(await sessions.revoke({ sid: platformSid, kind: "PLATFORM" }), true);
    assert.equal(await sessions.validate({ sid: platformSid, kind: "PLATFORM" }), null);
    assert.equal(await sessions.validate({ sid: caseSid, kind: "CASE" }), null);
    assert.equal(await sessions.revoke({ sid: platformSid, kind: "PLATFORM" }), false);

    // Cero secretos/PII en claro.
    for (const t of ["platform_session", "session_event", "login_assertion", "oidc_exchange"]) {
      for (const needle of [platformSid, caseSid, f1.state, f2.state, SUB, "example.invalid", CASE.replace(/-/g, "").slice(0, 0) + "persona@"]) {
        assert.equal((await admin.query(`SELECT 1 FROM platform.${t} x WHERE strpos(x::text, $1) > 0`, [needle])).rowCount, 0, `${t} contiene ${needle.slice(0, 8)}`);
      }
    }
    assert.equal((await admin.query("SELECT 1 FROM platform.oidc_exchange x WHERE strpos(x::text, $1) > 0", [CASE])).rowCount, 0, "el case_ref en claro no esta en oidc_exchange (solo su hash)");
  } finally {
    await platformPool.end();
    await verifierPool.end();
  }
});
