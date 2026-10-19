// Gobierna: plan v2 H1-03. Los parámetros OTP aprobados (P-01..P-06) coinciden con las constantes que aplica la base en 0003_functions.sql.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as P from "../../src/otp/approved-parameters.ts";

const sql = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "db", "migrations", "0003_functions.sql"), "utf8");

test("las constantes de issue_otp/verify_otp en SQL son las aprobadas", () => {
  assert.match(sql, new RegExp(`c_ttl constant interval := interval '${P.APPROVED_P02_OTP_TTL_MS / 60_000} minutes'`));
  assert.match(sql, new RegExp(`c_max_attempts constant integer := ${P.APPROVED_P03_OTP_MAX_ATTEMPTS};`));
  assert.match(sql, new RegExp(`c_budget_max constant integer := ${P.APPROVED_P04_OTP_BUDGET_MAX_FAILURES};`));
  assert.match(sql, new RegExp(`c_budget_window constant interval := interval '${P.APPROVED_P04_OTP_BUDGET_WINDOW_MS / 3_600_000} hours'`));
  assert.match(sql, new RegExp(`c_min_resend constant interval := interval '${P.APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS / 1000} seconds'`));
  assert.match(sql, new RegExp(`c_max_sends constant integer := ${P.APPROVED_P06_OTP_MAX_SENDS_PER_HOUR};`));
  assert.match(sql, new RegExp(`c_window constant interval := interval '${P.BETA_VERIFIED_SESSION_WINDOW_MS / 60_000} minutes'`));
  assert.equal(P.APPROVED_P01_OTP_CODE_LENGTH, 6);
});
