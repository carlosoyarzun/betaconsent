// Gobierna: ADR-010 rev. 4 §4.3 (puntos 2-4), §7 fila PR-4 (DF-4, F-X8-15); F-A10-13 (error uniforme y COMMIT ante DENY en platform-call.ts).
// TEST-CNS-1370: ciclo del verifier con IdP sintetico y almacen falso: IDLE, ATTESTED, REJECTED (canje fallido, claims invalidos, la base degrada), sin fuga de secretos,
//   token, email ni sub en lo registrado; el IdP sintetico se niega fuera de LOCAL; el code es de un solo uso.
// TEST-CNS-1371: withPlatformTransaction: principal solo por set_config(..., true), COMMIT aun cuando el resultado es un DENY, ROLLBACK + error uniforme ante fallo de base.
// Sin Postgres. Solo sinteticos.

import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { runVerifierCycle } from "../../../src/server/modules/step-up/verifier.ts";
import type { VerifierConfig } from "../../../src/server/modules/step-up/verifier.ts";
import { computeSubHmac, VerifierConfigError } from "../../../src/server/modules/step-up/id-token.ts";
import { PlatformDeniedError } from "../../../src/server/ports/oidc-exchange.port.ts";
import type { AssertionRecord, ClaimedExchange, OidcExchangeStorePort } from "../../../src/server/ports/oidc-exchange.port.ts";
import { SyntheticIdpAdapter } from "../../../src/infra/adapters/synthetic-idp.adapter.ts";
import { withPlatformTransaction } from "../../../src/infra/adapters/postgres/platform-call.ts";
import { FakeClient, fakePool, sqlError } from "../postgres/fakes.ts";

const ISSUER = "https://idp.synthetic.invalid";
const AUDIENCE = "consent-app-synthetic";
const NOW_MS = Date.UTC(2026, 9, 11, 12, 0, 0);
const NONCE = "nonce-sintetico-".padEnd(64, "x");
const NONCE_HASH = createHash("sha256").update(NONCE, "utf8").digest("hex");
const K_SUB = randomBytes(32);
const PRINCIPAL = "5b0c1d2e-3f40-4a51-8b62-73849a0b1c2d";
const config = (over: Partial<VerifierConfig> = {}): VerifierConfig => ({
  issuer: ISSUER, audience: AUDIENCE, allowedAlgs: ["EdDSA"], maxAuthAgeSeconds: 300, environment: "LOCAL", subHmacKey: K_SUB, ...over,
});
const idp = (): SyntheticIdpAdapter => new SyntheticIdpAdapter({ environment: "LOCAL", issuer: ISSUER, audience: AUDIENCE, now: () => NOW_MS });

class FakeStore implements OidcExchangeStorePort {
  readonly records: AssertionRecord[] = [];
  private readonly queue: ClaimedExchange[];
  private readonly attestedResult: boolean;
  constructor(queue: ClaimedExchange[], attestedResult = true) {
    this.queue = queue;
    this.attestedResult = attestedResult;
  }
  async claim(): Promise<ClaimedExchange | null> {
    return this.queue.shift() ?? null;
  }
  async recordAssertion(record: AssertionRecord): Promise<boolean> {
    this.records.push(record);
    return record.decision === "ATTESTED" && this.attestedResult;
  }
}

function claimed(p: SyntheticIdpAdapter, auth: Parameters<SyntheticIdpAdapter["simulateAuthorization"]>[0]): ClaimedExchange {
  const { code, pkceVerifier } = p.simulateAuthorization(auth);
  return { exchangeRef: "0f1e2d3c-4b5a-4968-8776-655443322110", nonceHash: NONCE_HASH, principalRef: PRINCIPAL, code, pkceVerifier };
}

test("TEST-CNS-1370 verifier: sin solicitudes devuelve IDLE; con una valida registra ATTESTED con solo claims minimos (sub como HMAC, sin email ni token ni code)", async () => {
  const p = idp();
  assert.equal(await runVerifierCycle({ store: new FakeStore([]), idp: p, config: config(), now: () => NOW_MS }), "IDLE");

  const c = claimed(p, { sub: "sub-synthetic-uno", nonce: NONCE, authTime: Math.floor(NOW_MS / 1000) - 5, acr: "urn:synthetic:mfa", amr: ["pwd"], email: "persona@example.invalid" });
  const store = new FakeStore([c]);
  assert.equal(await runVerifierCycle({ store, idp: p, config: config(), now: () => NOW_MS }), "ATTESTED");
  assert.equal(store.records.length, 1);
  const r = store.records[0]!;
  assert.equal(r.decision, "ATTESTED");
  if (r.decision !== "ATTESTED") return;
  assert.equal(r.subHmac, computeSubHmac(K_SUB, ISSUER, "sub-synthetic-uno"));
  assert.match(r.assertionHash, /^[0-9a-f]{64}$/);
  assert.equal(r.authTime.getTime(), (Math.floor(NOW_MS / 1000) - 5) * 1000);
  assert.equal(r.acr, "urn:synthetic:mfa");
  assert.deepEqual(r.amr, ["pwd"]);
  const dump = JSON.stringify(store.records);
  for (const secret of ["sub-synthetic-uno", "example.invalid", c.code, c.pkceVerifier]) assert.ok(!dump.includes(secret), `no debe registrarse: ${secret.slice(0, 8)}`);
});

test("TEST-CNS-1370 verifier: canje fallido, PKCE equivocado, code reutilizado, nonce ajeno o token viejo => REJECTED con motivo cerrado y sin detalle", async () => {
  const p = idp();
  const run = async (c: ClaimedExchange): Promise<AssertionRecord> => {
    const store = new FakeStore([c]);
    assert.equal(await runVerifierCycle({ store, idp: p, config: config(), now: () => NOW_MS }), "REJECTED");
    assert.equal(store.records.length, 1);
    return store.records[0]!;
  };
  const nowS = Math.floor(NOW_MS / 1000);
  // PKCE equivocado: el IdP rechaza el canje.
  const bad = claimed(p, { sub: "s", nonce: NONCE });
  assert.deepEqual(await run({ ...bad, pkceVerifier: "otro-verifier-".padEnd(43, "z") }), { decision: "REJECTED", exchangeRef: bad.exchangeRef, reason: "EXCHANGE_FAILED" });
  // El code de un solo uso ya se consumio (aun con canje fallido).
  assert.deepEqual(await run(bad), { decision: "REJECTED", exchangeRef: bad.exchangeRef, reason: "EXCHANGE_FAILED" });
  // Code inexistente.
  assert.equal((await run({ ...claimed(p, { sub: "s", nonce: NONCE }), code: "no-existe" })).decision, "REJECTED");
  // Nonce distinto del binding (token de otra solicitud).
  assert.deepEqual(await run(claimed(p, { sub: "s", nonce: "otro-nonce" })), { decision: "REJECTED", exchangeRef: "0f1e2d3c-4b5a-4968-8776-655443322110", reason: "INVALID_CLAIMS" });
  // auth_time demasiado viejo (step-up exige autenticacion reciente).
  assert.equal(((await run(claimed(p, { sub: "s", nonce: NONCE, authTime: nowS - 7200 }))) as { reason: string }).reason, "INVALID_CLAIMS");
  // Issuer/audiencia distintos en la configuracion del verifier.
  const store = new FakeStore([claimed(p, { sub: "s", nonce: NONCE })]);
  assert.equal(await runVerifierCycle({ store, idp: p, config: config({ audience: "otra" }), now: () => NOW_MS }), "REJECTED");
  assert.equal((store.records[0] as { reason: string }).reason, "INVALID_CLAIMS");
  // Ningun registro contiene secretos ni mensajes del IdP.
  for (const rec of [store.records[0]!]) assert.deepEqual(Object.keys(rec).sort(), ["decision", "exchangeRef", "reason"]);
});

test("TEST-CNS-1370 verifier: si la base degrada la asercion (sub_hmac no mapeado, nonce vencido) el ciclo devuelve REJECTED; el IdP sintetico solo existe en LOCAL y el JWKS no trae material privado", async () => {
  const p = idp();
  const store = new FakeStore([claimed(p, { sub: "s", nonce: NONCE })], false);
  assert.equal(await runVerifierCycle({ store, idp: p, config: config(), now: () => NOW_MS }), "REJECTED");
  assert.equal(store.records.length, 1, "no se registra un REJECTED adicional: la base ya decidio");
  for (const env of ["DEV", "STAGING", "PRODUCTION", ""]) {
    assert.throws(() => new SyntheticIdpAdapter({ environment: env, issuer: ISSUER, audience: AUDIENCE }), /solo existe en LOCAL/);
  }
  const jwks = await p.getJwks();
  assert.equal(jwks.keys.length, 1);
  assert.ok(!("d" in jwks.keys[0]!));
  // Un error al registrar la asercion no se traga como exito.
  const failing: OidcExchangeStorePort = { claim: async () => claimed(p, { sub: "s", nonce: NONCE }), recordAssertion: async () => { throw new PlatformDeniedError(); } };
  await assert.rejects(() => runVerifierCycle({ store: failing, idp: p, config: config(), now: () => NOW_MS }), PlatformDeniedError);
});

test("TEST-CNS-1371 platform-call: principal solo por set_config('app.principal_ref', $1, true); COMMIT aun si el resultado es un DENY (NULL); ROLLBACK + error uniforme ante fallo de base", async () => {
  // DENY (la funcion devuelve NULL): se confirma la transaccion para que la evidencia persista; el llamador traduce despues.
  const c1 = new FakeClient((text) => (text.startsWith("SELECT platform.") ? { rows: [{ r: null }], rowCount: 1 } : undefined));
  const rows = await withPlatformTransaction(fakePool([c1]), PRINCIPAL, async (tx) => (await tx.query<{ r: string | null }>("SELECT platform.enqueue_oidc_exchange($1)", ["x"])).rows);
  assert.deepEqual(rows, [{ r: null }]);
  const texts1 = c1.queries.map((q) => q.text);
  const iBegin = texts1.indexOf("BEGIN");
  assert.ok(iBegin >= 0 && texts1.indexOf("COMMIT") > iBegin && !texts1.includes("ROLLBACK"));
  const setCfg = c1.queries.find((q) => q.text.includes("set_config('app.principal_ref'"));
  assert.equal(setCfg?.text, "SELECT set_config('app.principal_ref', $1, true)");
  assert.deepEqual(setCfg?.values, [PRINCIPAL]);
  assert.deepEqual(c1.releases, [false]);

  // Sin principal (verifier): no se fija ninguna GUC.
  const c2 = new FakeClient();
  await withPlatformTransaction(fakePool([c2]), null, async () => 1);
  assert.ok(!c2.queries.some((q) => q.text.includes("app.principal_ref")));

  // Fallo de base: ROLLBACK y error uniforme sin el mensaje ni el SQLSTATE originales.
  const c3 = new FakeClient((text) => (text.startsWith("SELECT platform.") ? sqlError("23514", "violates check constraint tenant_membership_principal_shape") : undefined));
  await assert.rejects(
    () => withPlatformTransaction(fakePool([c3]), PRINCIPAL, async (tx) => tx.query("SELECT platform.x()")),
    (e) => e instanceof PlatformDeniedError && e.message === "platform: operacion no autorizada" && !/constraint|23514/.test(String(e.message)),
  );
  assert.ok(c3.queries.some((q) => q.text === "ROLLBACK") && !c3.queries.some((q) => q.text === "COMMIT"));
  // Si ni el ROLLBACK se puede hacer, la conexion se destruye.
  const c4 = new FakeClient((text) => (text === "ROLLBACK" || text.startsWith("SELECT platform.") ? sqlError("08006") : undefined));
  await assert.rejects(() => withPlatformTransaction(fakePool([c4]), PRINCIPAL, async (tx) => tx.query("SELECT platform.x()")), PlatformDeniedError);
  assert.deepEqual(c4.releases, [true]);

  // Principal con forma invalida (p. ej. la forma vieja staff-synthetic-): ni se conecta.
  const pool = fakePool([new FakeClient()]);
  for (const bad of ["staff-synthetic-01", "", "x@example.invalid", PRINCIPAL.toUpperCase(), "12345678-1234-1234-1234-123456789012"]) {
    await assert.rejects(() => withPlatformTransaction(pool, bad, async () => 1), PlatformDeniedError, bad);
  }
  assert.equal(pool.connects, 0);
});

test("TEST-CNS-1370 verifier: una configuracion invalida (NaN, Infinity, negativo, enorme, vacio, K_sub corta) ABORTA con VerifierConfigError antes de tomar la cola y nunca registra REJECTED", async () => {
  const p = idp();
  const bad: Array<[string, Partial<VerifierConfig>]> = [
    ["skew NaN", { clockSkewSeconds: Number.NaN }], ["skew Infinity", { clockSkewSeconds: Number.POSITIVE_INFINITY }], ["skew negativo", { clockSkewSeconds: -1 }], ["skew enorme", { clockSkewSeconds: 1e9 }],
    ["maxAuth NaN", { maxAuthAgeSeconds: Number.NaN }], ["maxAuth Infinity", { maxAuthAgeSeconds: Number.POSITIVE_INFINITY }], ["maxAuth negativo", { maxAuthAgeSeconds: -1 }],
    ["maxAuth enorme", { maxAuthAgeSeconds: 1e12 }], ["maxAuth 0", { maxAuthAgeSeconds: 0 }],
    ["allowedAlgs vacio", { allowedAlgs: [] }], ["issuer vacio", { issuer: "" }], ["audience vacia", { audience: "" }],
    ["lease NaN", { leaseSeconds: Number.NaN }], ["lease 0", { leaseSeconds: 0 }], ["lease 121", { leaseSeconds: 121 }], ["lease negativo", { leaseSeconds: -3 }],
    ["K_sub corta", { subHmacKey: randomBytes(16) }],
  ];
  for (const [label, over] of bad) {
    let claims = 0;
    const store = new FakeStore([claimed(p, { sub: "s", nonce: NONCE })]);
    const counting: OidcExchangeStorePort = { claim: async () => { claims += 1; return store.claim(); }, recordAssertion: (r) => store.recordAssertion(r) };
    await assert.rejects(() => runVerifierCycle({ store: counting, idp: p, config: config(over), now: () => NOW_MS }), (e) => e instanceof VerifierConfigError, label);
    assert.equal(claims, 0, `${label}: no toca la cola`);
    assert.equal(store.records.length, 0, `${label}: no registra REJECTED`);
  }
  // Un token vencido hace 100.000 s con skew NaN (el P1): aborta; no se atesta ni se rechaza silenciosamente.
  const old = p.signRaw({ iss: ISSUER, aud: AUDIENCE, sub: "s", iat: 1, exp: Math.floor(NOW_MS / 1000) - 100_000, nonce: NONCE, auth_time: Math.floor(NOW_MS / 1000) });
  const idpOld = { exchangeCode: async () => ({ idToken: old }), getJwks: () => p.getJwks() };
  const store = new FakeStore([{ exchangeRef: "0f1e2d3c-4b5a-4968-8776-655443322110", nonceHash: NONCE_HASH, principalRef: PRINCIPAL, code: "c", pkceVerifier: "p" }]);
  await assert.rejects(() => runVerifierCycle({ store, idp: idpOld, config: config({ clockSkewSeconds: Number.NaN }), now: () => NOW_MS }), VerifierConfigError);
  assert.equal(store.records.length, 0);
});
