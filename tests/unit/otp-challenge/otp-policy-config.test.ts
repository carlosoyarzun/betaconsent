// Gobierna: SEC-CNS-006 rev. 5 §1 P-01/P-02/P-03 (aprobados por Carlos; D3 de SEC-CNS-021, 2026-10-08) y, desde SEC-CNS-021 PR-4, P-04/P-06/P-07.
// TEST-CNS-1320: P-04..P-07 vienen de approved-parameters.ts en cualquier entorno; los overrides solo valen en LOCAL; `maxResends` se retiro (F-5).

import test from "node:test";
import assert from "node:assert/strict";

import {
  APPROVED_P04_OTP_BUDGET_MAX_FAILURES,
  APPROVED_P04_OTP_BUDGET_WINDOW_MS,
  APPROVED_P06_OTP_MAX_SENDS_PER_HOUR,
  APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS,
  APPROVED_P07_OTP_DECISION_MAX_LOCKED_CHALLENGES,
  P07_RIGHTS_DAYS_30_CAP_ENFORCED,
} from "../../../src/server/modules/common/approved-parameters.ts";
import { loadOtpPolicyConfig } from "../../../src/server/modules/otp-challenge/otp-policy.config.ts";

const VARS = [
  "CNS_OTP_CODE_LENGTH", "CNS_OTP_TTL_MS", "CNS_OTP_MAX_ATTEMPTS", "CNS_OTP_MAX_RESENDS", "CNS_OTP_BUDGET_MAX_FAILURES", "CNS_OTP_BUDGET_WINDOW_MS",
  "CNS_OTP_MAX_LOCKED_CHALLENGES", "CNS_OTP_MIN_RESEND_INTERVAL_MS", "CNS_OTP_MAX_SENDS_PER_HOUR",
];

const APPROVED = {
  codeLength: 6, ttlMs: 600_000, maxAttempts: 5,
  budgetMaxFailures: 10, budgetWindowMs: 86_400_000, maxLockedChallenges: 3, minResendIntervalMs: 60_000, maxSendsPerHour: 3,
};

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

test("OTP P-01/P-02/P-03 y P-04/P-06/P-07 aprobados son el default en cualquier entorno (TEST-CNS-1320)", () => {
  withCleanEnv(() => {
    for (const env of ["LOCAL", "STAGING", "PRODUCTION", undefined]) {
      assert.deepEqual(loadOtpPolicyConfig({}, env), APPROVED);
    }
    // Las constantes aprobadas son exactamente las de SEC-CNS-006 rev. 5 (D3/D8).
    assert.equal(APPROVED_P04_OTP_BUDGET_MAX_FAILURES, 10);
    assert.equal(APPROVED_P04_OTP_BUDGET_WINDOW_MS, 24 * 60 * 60_000);
    assert.equal(APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS, 60_000);
    assert.equal(APPROVED_P06_OTP_MAX_SENDS_PER_HOUR, 3);
    assert.equal(APPROVED_P07_OTP_DECISION_MAX_LOCKED_CHALLENGES, 3);
  });
});

test("OTP: override distinto del aprobado solo en LOCAL; en STAGING/PRODUCTION/sin entorno lanza (P-01..P-07, TEST-CNS-1320)", () => {
  withCleanEnv(() => {
    assert.deepEqual(loadOtpPolicyConfig({ codeLength: 8, ttlMs: 30, maxAttempts: 1 }, "LOCAL"), { ...APPROVED, codeLength: 8, ttlMs: 30, maxAttempts: 1 });
    const overrides: Array<[Parameters<typeof loadOtpPolicyConfig>[0], RegExp]> = [
      [{ ttlMs: 30 }, /P-02/], [{ maxAttempts: 3 }, /P-03/], [{ codeLength: 8 }, /P-01/],
      [{ budgetMaxFailures: 1000 }, /P-04 \(budgetMaxFailures\)/], [{ budgetWindowMs: 1000 }, /P-04 \(budgetWindowMs\)/],
      [{ maxLockedChallenges: 5 }, /P-07/], [{ minResendIntervalMs: 0 }, /P-06 \(minResendIntervalMs\)/], [{ maxSendsPerHour: 10 }, /P-06 \(maxSendsPerHour\)/],
    ];
    for (const env of ["STAGING", "PRODUCTION", undefined]) {
      for (const [override, re] of overrides) assert.throws(() => loadOtpPolicyConfig(override, env), re, JSON.stringify(override));
    }
    for (const [override] of overrides) assert.doesNotThrow(() => loadOtpPolicyConfig(override, "LOCAL"));
    assert.doesNotThrow(() => loadOtpPolicyConfig({ ttlMs: 600_000, budgetMaxFailures: 10, minResendIntervalMs: 60_000 }, "STAGING"));
  });
});

test("OTP: override por env distinto del aprobado tambien falla fuera de LOCAL; valor invalido lanza", () => {
  withCleanEnv(() => {
    process.env.CNS_OTP_MAX_ATTEMPTS = "3";
    assert.throws(() => loadOtpPolicyConfig({}, "STAGING"), /P-03/);
    assert.equal(loadOtpPolicyConfig({}, "LOCAL").maxAttempts, 3);
    process.env.CNS_OTP_MAX_ATTEMPTS = "abc";
    assert.throws(() => loadOtpPolicyConfig({}, "LOCAL"), /entero positivo/);
    delete process.env.CNS_OTP_MAX_ATTEMPTS;
    process.env.CNS_OTP_BUDGET_MAX_FAILURES = "20";
    assert.throws(() => loadOtpPolicyConfig({}, "PRODUCTION"), /P-04/);
    assert.equal(loadOtpPolicyConfig({}, "LOCAL").budgetMaxFailures, 20);
    delete process.env.CNS_OTP_BUDGET_MAX_FAILURES;
    process.env.CNS_OTP_MIN_RESEND_INTERVAL_MS = "0";
    assert.equal(loadOtpPolicyConfig({}, "LOCAL").minResendIntervalMs, 0);
    assert.throws(() => loadOtpPolicyConfig({}, "STAGING"), /P-06/);
  });
});

test("OTP F-5: CNS_OTP_MAX_RESENDS se retiro (P-06 lo reemplaza): si sigue definida el arranque lanza en cualquier entorno", () => {
  withCleanEnv(() => {
    process.env.CNS_OTP_MAX_RESENDS = "3";
    for (const env of ["LOCAL", "STAGING", undefined]) assert.throws(() => loadOtpPolicyConfig({}, env), /CNS_OTP_MAX_RESENDS se retir/);
  });
});

test("OTP D6: el tope RIGHTS DAYS_30 (P-07, V6c) esta diferido y NO se aplica (TEST-CNS-1320)", () => {
  assert.equal(P07_RIGHTS_DAYS_30_CAP_ENFORCED, false);
});
