// Gobierna: ADR-010 rev. 4, decision de Carlos del 2026-10-12 (registrada bajo PR-4 #87): "(2) MFA/acr obligatorio fuera de LOCAL (requiredAcrAnyOf no vacio)"; plan PR-6-0; F-A10-21, F-PR6-03.
// TEST-CNS-1392: fuera de LOCAL, requiredAcrAnyOf vacio/ausente => VerifierConfigError al validar (validateVerifierConfig, runVerifierCycle y verifyIdToken) y NO se toma nada de la cola;
//   environment vacio tambien falla cerrado; en LOCAL el comportamiento sintetico se mantiene (lista vacia admitida).
// TEST-CNS-1393: con la lista no vacia, el acr del id_token fuera de la lista (o ausente) se rechaza con motivo "acr no exigido"; dentro de la lista se acepta.
// Los valores de acr usados son SINTETICOS de prueba: los reales dependen de APR-IDP (PENDING). Sin Postgres.

import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { IdTokenRejected, VerifierConfigError, verifyIdToken } from "../../../src/server/modules/step-up/id-token.ts";
import type { IdTokenPolicy } from "../../../src/server/modules/step-up/id-token.ts";
import { runVerifierCycle, validateVerifierConfig } from "../../../src/server/modules/step-up/verifier.ts";
import type { VerifierConfig } from "../../../src/server/modules/step-up/verifier.ts";
import type { AssertionRecord, ClaimedExchange, LoginAssertionRecord, OidcExchangeStorePort } from "../../../src/server/ports/oidc-exchange.port.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";

const ISSUER = "https://idp.synthetic.invalid";
const AUDIENCE = "consent-app-synthetic";
const NOW_MS = Date.UTC(2026, 9, 13, 12, 0, 0);
const NOW_S = Math.floor(NOW_MS / 1000);
const NONCE = "m".repeat(64);
const NONCE_HASH = createHash("sha256").update(NONCE, "utf8").digest("hex");
const ACR_OK = "urn:synthetic:test-mfa";
const K_SUB = randomBytes(32);
const idp = (): SyntheticIdpAdapter => new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE, now: () => NOW_MS });

/** acr: null = clave ausente (no vacia); el resto se pasa tal cual. */
function policy(environment: string, acr: readonly string[] | null = [ACR_OK]): IdTokenPolicy {
  const base: IdTokenPolicy = { issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, environment, nowSeconds: NOW_S };
  return acr === null ? base : { ...base, requiredAcrAnyOf: acr };
}
function config(environment: string, acr: readonly string[] | null = [ACR_OK]): VerifierConfig {
  // PR-6b: fuera de LOCAL P-48/P-52 son obligatorios (G-6/G-7); este test es de MFA, asi que los aporta con los valores iniciales aprobados.
  const base: VerifierConfig = { issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, environment, subHmacKey: K_SUB, login: { p48MaxFailures: 5, p48WindowSeconds: 900, p52AssertionSeconds: 300 } };
  return acr === null ? base : { ...base, requiredAcrAnyOf: acr };
}
const configError = (fn: () => unknown, label: string): void => assert.throws(fn, (e) => e instanceof VerifierConfigError && /requiredAcrAnyOf|environment/.test(e.message), label);

class CountingStore implements OidcExchangeStorePort {
  claims = 0;
  records: AssertionRecord[] = [];
  next: ClaimedExchange | null = null;
  async claim(): Promise<ClaimedExchange | null> {
    this.claims += 1;
    return this.next;
  }
  async recordAssertion(record: AssertionRecord): Promise<boolean> {
    this.records.push(record);
    return false;
  }
  async recordLoginAssertion(): Promise<boolean> {
    return false;
  }
}

async function tokenWith(p: SyntheticIdpAdapter, acr?: string): Promise<string> {
  const { code, pkceVerifier } = p.simulateAuthorization({ sub: "sub-synthetic-1", nonce: NONCE, authTime: NOW_S - 5, ...(acr === undefined ? {} : { acr }) });
  return (await p.exchangeCode({ code, pkceVerifier })).idToken;
}

test("TEST-CNS-1392 MFA obligatorio fuera de LOCAL: requiredAcrAnyOf vacio o ausente falla cerrado (config, ciclo del verifier y verifyIdToken); en LOCAL se mantiene el modo sintetico", async () => {
  const p = idp();
  const jwks = await p.getJwks();
  const token = await tokenWith(p, ACR_OK);

  for (const env of ["STAGING", "DEV", "PRODUCTION", "local", "desconocido"]) {
    for (const acr of [null, []] as const) {
      const label = `${env}/${acr === null ? "ausente" : "vacio"}`;
      configError(() => validateVerifierConfig(config(env, acr), NOW_S), `${label}: validateVerifierConfig`);
      configError(() => verifyIdToken(token, jwks, NONCE_HASH, policy(env, acr)), `${label}: verifyIdToken`);
      const store = new CountingStore();
      await assert.rejects(runVerifierCycle({ store, idp: p, config: config(env, acr), now: () => NOW_MS }), (e) => e instanceof VerifierConfigError, `${label}: runVerifierCycle`);
      assert.equal(store.claims, 0, `${label}: una config rota aborta antes de tomar nada de la cola`);
      assert.equal(store.records.length, 0, `${label}: y no registra REJECTED`);
    }
  }
  configError(() => validateVerifierConfig(config("", [ACR_OK]), NOW_S), "environment vacio");

  // Fuera de LOCAL con lista no vacia: valido. En LOCAL: lista vacia o ausente sigue admitida (IdP sintetico).
  validateVerifierConfig(config("STAGING"), NOW_S);
  validateVerifierConfig(config("LOCAL", []), NOW_S);
  validateVerifierConfig(config("LOCAL", null), NOW_S);
  const store = new CountingStore();
  assert.equal(await runVerifierCycle({ store, idp: p, config: config("LOCAL", []), now: () => NOW_MS }), "IDLE");
  assert.equal(store.claims, 1);
  assert.equal(verifyIdToken(token, jwks, NONCE_HASH, policy("LOCAL", [])).sub, "sub-synthetic-1");
});

test("TEST-CNS-1393 acr del id_token contra la lista: fuera de la lista o ausente => IdTokenRejected('acr no exigido'); dentro de la lista => aceptado", async () => {
  const p = idp();
  const jwks = await p.getJwks();
  const rejectedAcr = (token: string, label: string): void =>
    assert.throws(() => verifyIdToken(token, jwks, NONCE_HASH, policy("STAGING")), (e) => e instanceof IdTokenRejected && e.reason === "acr no exigido", label);

  assert.equal(verifyIdToken(await tokenWith(p, ACR_OK), jwks, NONCE_HASH, policy("STAGING")).acr, ACR_OK);
  assert.equal(verifyIdToken(await tokenWith(p, "urn:synthetic:otro"), jwks, NONCE_HASH, policy("STAGING", ["urn:synthetic:a", "urn:synthetic:otro"])).acr, "urn:synthetic:otro");
  rejectedAcr(await tokenWith(p, "urn:synthetic:pwd-only"), "acr fuera de la lista");
  rejectedAcr(await tokenWith(p, ACR_OK.toUpperCase()), "comparacion exacta (sensible a mayusculas)");
  rejectedAcr(await tokenWith(p), "acr ausente en el token");

  // El ciclo del verifier registra REJECTED/INVALID_CLAIMS (no ATTESTED) cuando el acr no esta en la lista.
  const { code, pkceVerifier } = p.simulateAuthorization({ sub: "sub-synthetic-1", nonce: NONCE, authTime: NOW_S - 5, acr: "urn:synthetic:pwd-only" });
  const store = new CountingStore();
  store.next = { exchangeRef: "0f1e2d3c-4b5a-4968-8776-655443322110", kind: "STEP_UP", nonceHash: NONCE_HASH, principalRef: "5b0c1d2e-3f40-4a51-8b62-73849a0b1c2d", code, pkceVerifier };
  assert.equal(await runVerifierCycle({ store, idp: p, config: config("STAGING"), now: () => NOW_MS }), "REJECTED");
  assert.deepEqual(store.records.map((r) => (r.decision === "REJECTED" ? r.reason : r.decision)), ["INVALID_CLAIMS"]);
});
