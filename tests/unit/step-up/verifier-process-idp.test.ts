// Gobierna: ADR-010 rev. 4 §4.3.3 ("en LOCAL un JWKS sintetico fijo, sin egress"), §7 fila PR-6 (6a: proceso verifier), registers/findings-register-IT0.md F-A10-23 (el IdP sintetico
// se niega en el proceso verifier fuera de LOCAL, ademas del constructor) y F-PR6-08 (environment de fuente confiable); PR-6-0 (environment obligatorio, MFA fuera de LOCAL).
// TEST-CNS-1397: el proceso verifier NO arranca con el IdP sintetico fuera de LOCAL (marca estructural, instancia, fabrica y arranque completo), sin Postgres.

import test from "node:test";
import assert from "node:assert/strict";

import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";
import { VerifierConfigError } from "../../../src/server/modules/step-up/id-token.ts";
import { assertIdpAllowedForEnvironment, createVerifierIdp, loadVerifierSettings, startVerifierProcess } from "../../../src/server/entrypoints/verifier/verifier-process.ts";
import type { IdpClientPort } from "../../../src/server/ports/idp-client.port.ts";

const BASE = { issuer: "https://idp.synthetic.invalid", audience: "consent-app-synthetic" };
const baseEnv = (environment: string, extra: Record<string, string> = {}) => ({
  CNS_ENVIRONMENT: environment,
  CNS_DATABASE_URL: "postgresql://integrity_verifier:pw@127.0.0.1:1/db",
  CNS_VERIFIER_ISSUER: BASE.issuer,
  CNS_VERIFIER_AUDIENCE: BASE.audience,
  CNS_VERIFIER_MAX_AUTH_AGE_SECONDS: "300",
  CNS_VERIFIER_SUB_HMAC_KEY_HEX: "cd".repeat(32),
  ...extra,
});

test("TEST-CNS-1397 F-A10-23: assertIdpAllowedForEnvironment niega el IdP sintetico fuera de LOCAL (instancia y marca estructural) y lo admite en LOCAL", () => {
  const synthetic = new SyntheticIdpAdapter({ environment: "LOCAL", ...BASE });
  assert.equal(synthetic.synthetic, true);
  assertIdpAllowedForEnvironment(synthetic, "LOCAL");
  for (const env of ["DEV", "STAGING", "PRODUCTION", "local", ""]) {
    assert.throws(() => assertIdpAllowedForEnvironment(synthetic, env), VerifierConfigError, env);
  }
  // Un envoltorio que solo conserva la marca (sin ser instancia) tambien se niega.
  const marked: IdpClientPort = { synthetic: true, exchangeCode: synthetic.exchangeCode.bind(synthetic), getJwks: synthetic.getJwks.bind(synthetic) };
  assert.throws(() => assertIdpAllowedForEnvironment(marked, "STAGING"), VerifierConfigError);
  // Un adaptador sin la marca (real) no se bloquea por esta regla.
  const real: IdpClientPort = { exchangeCode: synthetic.exchangeCode.bind(synthetic), getJwks: synthetic.getJwks.bind(synthetic) };
  assertIdpAllowedForEnvironment(real, "STAGING");
  // El constructor tambien se niega fuera de LOCAL (defensa en profundidad).
  assert.throws(() => new SyntheticIdpAdapter({ environment: "DEV", ...BASE }), /solo existe en LOCAL/);
});

// PR-6b: fuera de LOCAL P-48/P-52 son obligatorios (G-6/G-7); estos casos prueban F-A10-23 / IdP, asi que los aportan (valores iniciales aprobados).
const LOGIN_ENV = { CNS_VERIFIER_P48_MAX_FAILURES: "5", CNS_VERIFIER_P48_WINDOW_SECONDS: "900", CNS_VERIFIER_P52_ASSERTION_SECONDS: "300" };

test("TEST-CNS-1397 createVerifierIdp: LOCAL devuelve el sintetico; DEV/STAGING no tienen IdP activable (APR-IDP y P-45 PENDING) y lanzan", () => {
  assert.equal(createVerifierIdp("LOCAL", BASE).synthetic, true);
  for (const env of ["DEV", "STAGING"] as const) assert.throws(() => createVerifierIdp(env, BASE), VerifierConfigError, env);
});

test("TEST-CNS-1397 startVerifierProcess fuera de LOCAL no arranca: con IdP sintetico inyectado, sin IdP, y sin MFA (requiredAcrAnyOf) antes de tocar la base", async () => {
  const synthetic = new SyntheticIdpAdapter({ environment: "LOCAL", ...BASE });
  // DEV con acr configurado y el IdP sintetico inyectado -> F-A10-23 (antes de abrir ningun pool: la URL apunta a un puerto cerrado).
  await assert.rejects(() => startVerifierProcess({ env: baseEnv("DEV", { CNS_VERIFIER_REQUIRED_ACR_ANY_OF: "urn:synthetic:mfa", ...LOGIN_ENV }), idp: synthetic }), (e: unknown) => e instanceof VerifierConfigError && /sintetico/.test(e.message));
  // DEV con acr y sin IdP inyectado -> no hay IdP activable.
  await assert.rejects(() => startVerifierProcess({ env: baseEnv("DEV", { CNS_VERIFIER_REQUIRED_ACR_ANY_OF: "urn:synthetic:mfa", ...LOGIN_ENV }) }), (e: unknown) => e instanceof VerifierConfigError && /IdP/.test(e.message));
  // STAGING sin requiredAcrAnyOf -> MFA obligatorio fuera de LOCAL (PR-6-0).
  await assert.rejects(() => startVerifierProcess({ env: baseEnv("STAGING"), idp: synthetic }), (e: unknown) => e instanceof VerifierConfigError && /requiredAcrAnyOf/.test(e.message));
  // environment fuera del enum cerrado -> no arranca.
  await assert.rejects(() => startVerifierProcess({ env: baseEnv("PRODUCTION"), idp: synthetic }));
});

test("TEST-CNS-1397 loadVerifierSettings: sin defaults para parametros PENDING (P-36, K_sub, issuer, audience); K_sub >= 32 bytes hex", () => {
  const ok = loadVerifierSettings(baseEnv("LOCAL"));
  assert.equal(ok.maxAuthAgeSeconds, 300);
  assert.equal(ok.subHmacKey.length, 32);
  assert.deepEqual(ok.requiredAcrAnyOf, []);
  for (const missing of ["CNS_VERIFIER_ISSUER", "CNS_VERIFIER_AUDIENCE", "CNS_VERIFIER_MAX_AUTH_AGE_SECONDS", "CNS_VERIFIER_SUB_HMAC_KEY_HEX"]) {
    const env: Record<string, string | undefined> = { ...baseEnv("LOCAL") };
    delete env[missing];
    assert.throws(() => loadVerifierSettings(env), VerifierConfigError, missing);
  }
  assert.throws(() => loadVerifierSettings(baseEnv("LOCAL", { CNS_VERIFIER_SUB_HMAC_KEY_HEX: "ab".repeat(8) })), VerifierConfigError);
  assert.throws(() => loadVerifierSettings(baseEnv("LOCAL", { CNS_VERIFIER_SUB_HMAC_KEY_HEX: "zz".repeat(32) })), VerifierConfigError);
});
