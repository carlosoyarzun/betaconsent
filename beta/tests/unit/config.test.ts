// Gobierna: plan v2 H1-01. loadConfig aborta con mensaje claro si falta una variable; los errores nunca incluyen valores.
import assert from "node:assert/strict";
import test from "node:test";

import { ConfigError, loadConfig, REQUIRED_VARIABLES } from "../../src/config.ts";

const S1 = Buffer.alloc(32, 1).toString("base64");
const S2 = Buffer.alloc(32, 2).toString("base64");
const S3 = Buffer.alloc(32, 3).toString("base64");
const GOOD: Record<string, string> = {
  CNS_ENVIRONMENT: "LOCAL",
  CNS_DATABASE_URL: "postgresql://consent_app:x@127.0.0.1:5432/consent",
  CNS_MAILER_DATABASE_URL: "postgresql://consent_mailer:y@127.0.0.1:5432/consent",
  CNS_SESSION_SECRET: S1,
  CNS_PUBLIC_ORIGIN: "http://localhost:8080",
  CNS_SMTP_URL: "smtp://127.0.0.1:1025",
  CNS_SMTP_FROM: "consent@example.test",
  CNS_MAIL_ALLOWLIST: "Alguien@Example.test, @example.org",
  CNS_API_KEYS: `k1:${S3}`,
  PORT: "8080",
  BIND: "127.0.0.1",
};

test("loadConfig acepta una configuración completa y normaliza la allowlist", () => {
  const c = loadConfig(GOOD);
  assert.equal(c.environment, "LOCAL");
  assert.deepEqual(c.mailAllowlist, ["alguien@example.test", "@example.org"]);
  assert.equal(c.apiKeys.length, 1);
  assert.equal(c.port, 8080);
});

test("loadConfig aborta nombrando cada variable faltante", () => {
  for (const name of REQUIRED_VARIABLES) {
    const env = { ...GOOD };
    delete env[name];
    assert.throws(() => loadConfig(env), (e: unknown) => e instanceof ConfigError && e.message.includes(name), name);
  }
});

test("loadConfig rechaza entorno inválido, secretos cortos, origen no exacto y más de 2 claves", () => {
  assert.throws(() => loadConfig({ ...GOOD, CNS_ENVIRONMENT: "STAGING" }), /LOCAL o REAL/);
  assert.equal("otpSecret" in loadConfig(GOOD), false); // CNS_OTP_SECRET ya no existe (F-SB-01)
  assert.throws(() => loadConfig({ ...GOOD, CNS_SESSION_SECRET: "corto" }), /base64/);
  assert.throws(() => loadConfig({ ...GOOD, CNS_PUBLIC_ORIGIN: "http://localhost:8080/" }), /origen exacto/);
  assert.throws(() => loadConfig({ ...GOOD, CNS_ENVIRONMENT: "REAL" }), /https en REAL/);
  assert.throws(() => loadConfig({ ...GOOD, CNS_API_KEYS: `a:${S1},b:${S2},c:${S3}` }), /1 o 2 claves/);
  assert.throws(() => loadConfig({ ...GOOD, PORT: "0" }), /PORT/);
  // SEC-CNS-024-V1: el pool del mailer es OTRO rol; no puede apuntar a la misma URL que el de la app.
  assert.throws(() => loadConfig({ ...GOOD, CNS_MAILER_DATABASE_URL: GOOD.CNS_DATABASE_URL }), /distinta de CNS_DATABASE_URL/);
  assert.throws(() => loadConfig({ ...GOOD, CNS_MAILER_DATABASE_URL: "mysql://x" }), /CNS_MAILER_DATABASE_URL/);
});

test("los mensajes de error no filtran valores de secretos", () => {
  try {
    loadConfig({ ...GOOD, CNS_SESSION_SECRET: "valor-secreto-corto" });
    assert.fail("debía abortar");
  } catch (e) {
    assert.ok(!(e as Error).message.includes("valor-secreto-corto"));
  }
});
