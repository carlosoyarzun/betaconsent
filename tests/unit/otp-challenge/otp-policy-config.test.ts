// Gobierna: SEC-CNS-006 rev. 5 §1 P-01/P-02/P-03 (aprobados por Carlos; D3 de SEC-CNS-021, 2026-10-08).

import test from "node:test";
import assert from "node:assert/strict";

import { loadOtpPolicyConfig } from "../../../src/server/modules/otp-challenge/otp-policy.config.ts";

const VARS = ["CNS_OTP_CODE_LENGTH", "CNS_OTP_TTL_MS", "CNS_OTP_MAX_ATTEMPTS", "CNS_OTP_MAX_RESENDS"];

function withCleanEnv(fn: () => void): void {
  const saved = VARS.map((v) => [v, process.env[v]] as const);
  for (const v of VARS) delete process.env[v];
  try {
    fn();
  } finally {
    for (const v of VARS) delete process.env[v];
    for (const [v, val] of saved) if (val !== undefined) process.env[v] = val;
  }
}

test("OTP P-01/P-02/P-03 aprobados son el default en cualquier entorno (6 digitos, 10 min, 5 intentos)", () => {
  withCleanEnv(() => {
    for (const env of ["LOCAL", "STAGING", "PRODUCTION", undefined]) {
      assert.deepEqual(loadOtpPolicyConfig({ maxResends: 3 }, env), { codeLength: 6, ttlMs: 600_000, maxAttempts: 5, maxResends: 3 });
    }
  });
});

test("OTP: override distinto del aprobado solo en LOCAL; en STAGING/PRODUCTION/sin entorno lanza", () => {
  withCleanEnv(() => {
    assert.deepEqual(loadOtpPolicyConfig({ codeLength: 8, ttlMs: 30, maxAttempts: 1, maxResends: 3 }, "LOCAL"), { codeLength: 8, ttlMs: 30, maxAttempts: 1, maxResends: 3 });
    for (const env of ["STAGING", "PRODUCTION", undefined]) {
      assert.throws(() => loadOtpPolicyConfig({ ttlMs: 30, maxResends: 3 }, env), /P-02/);
      assert.throws(() => loadOtpPolicyConfig({ maxAttempts: 3, maxResends: 3 }, env), /P-03/);
      assert.throws(() => loadOtpPolicyConfig({ codeLength: 8, maxResends: 3 }, env), /P-01/);
    }
    assert.doesNotThrow(() => loadOtpPolicyConfig({ ttlMs: 600_000, maxResends: 3 }, "STAGING"));
  });
});

test("OTP: override por env distinto del aprobado tambien falla fuera de LOCAL; valor invalido lanza", () => {
  withCleanEnv(() => {
    process.env.CNS_OTP_MAX_ATTEMPTS = "3";
    assert.throws(() => loadOtpPolicyConfig({ maxResends: 3 }, "STAGING"), /P-03/);
    assert.equal(loadOtpPolicyConfig({ maxResends: 3 }, "LOCAL").maxAttempts, 3);
    process.env.CNS_OTP_MAX_ATTEMPTS = "abc";
    assert.throws(() => loadOtpPolicyConfig({ maxResends: 3 }, "LOCAL"), /entero positivo/);
  });
});

test("OTP P-06: maxResends sigue fail-closed sin default (el valor aprobado aun no es modelable)", () => {
  withCleanEnv(() => {
    assert.throws(() => loadOtpPolicyConfig({}, "LOCAL"), /P-06/);
  });
});
