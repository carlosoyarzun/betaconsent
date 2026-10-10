// Gobierna: specs/state-machines/otp-challenge.spec.yaml (V1, V2, V2r, V4, V6; `used: [P-01 ... P-07, ...]` y `parametersRef`) y SEC-CNS-006 rev. 5 §1.
//
// Valores APROBADOS por Carlos (SEC-CNS-006 rev. 5 §1; confirmados 2026-10-08, D3/D6/D8 de SEC-CNS-021), en approved-parameters.ts y aplicables
// en cualquier entorno:
//   P-01 = 6 dígitos (crypto.randomInt sin sesgo)  P-02 = 10 min (hora de servidor)  P-03 = 5 intentos -> LOCKED
//   P-04 = 10 fallos por clave en ventana fija de 24 h  P-06 = >= 60 s entre envíos y <= 3 envíos/h por verificación (el inicial cuenta, D8)
//   P-07 (DECISION) = 3 challenges LOCKED por invitación -> V6a
// Son el DEFAULT. Cualquier override (argumento o CNS_OTP_CODE_LENGTH / CNS_OTP_TTL_MS / CNS_OTP_MAX_ATTEMPTS / CNS_OTP_BUDGET_MAX_FAILURES /
// CNS_OTP_BUDGET_WINDOW_MS / CNS_OTP_MAX_LOCKED_CHALLENGES / CNS_OTP_MIN_RESEND_INTERVAL_MS / CNS_OTP_MAX_SENDS_PER_HOUR) DISTINTO del aprobado
// solo se admite con CNS_ENVIRONMENT=LOCAL (marca LOCAL_ONLY); en cualquier otro entorno (incluido sin definir) lanza (fail-closed).
//
// `maxResends` / CNS_OTP_MAX_RESENDS se RETIRARON (SEC-CNS-021 PR-4, F-5): P-06 los reemplaza. Si la variable sigue definida, el arranque lanza
// (en cualquier entorno) para que nadie crea que aun rige. El tope RIGHTS DAYS_30 de P-07 (V6c) esta DIFERIDO (D6): no hay parametro que configurar.

import {
  APPROVED_P01_OTP_CODE_LENGTH,
  APPROVED_P02_OTP_TTL_MS,
  APPROVED_P03_OTP_MAX_ATTEMPTS,
  APPROVED_P04_OTP_BUDGET_MAX_FAILURES,
  APPROVED_P04_OTP_BUDGET_WINDOW_MS,
  APPROVED_P06_OTP_MAX_SENDS_PER_HOUR,
  APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS,
  APPROVED_P07_OTP_DECISION_MAX_LOCKED_CHALLENGES,
} from "../common/approved-parameters.ts";
import type { OtpPolicy } from "./otp-challenge.ts";

export interface OtpPolicyConfigOverrides {
  readonly codeLength?: number;
  readonly ttlMs?: number;
  readonly maxAttempts?: number;
  readonly budgetMaxFailures?: number;
  readonly budgetWindowMs?: number;
  readonly maxLockedChallenges?: number;
  /** 0 se admite (solo LOCAL): sin separación mínima entre envíos. */
  readonly minResendIntervalMs?: number;
  readonly maxSendsPerHour?: number;
}

function readIntEnv(name: string, allowZero = false): number | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value < 0 || (value === 0 && !allowZero)) {
    throw new Error(`${name} debe ser un entero ${allowZero ? "no negativo" : "positivo"} (SEC-CNS-006 P-01..P-07).`);
  }
  return value;
}

/**
 * Construye la política OTP: P-01/P-02/P-03/P-04/P-06/P-07 con el valor aprobado como default; un override distinto solo en LOCAL (LOCAL_ONLY).
 * El resultado lleva siempre los valores efectivos de los ocho parámetros.
 */
export function loadOtpPolicyConfig(
  overrides: OtpPolicyConfigOverrides = {},
  environment: string | undefined = process.env.CNS_ENVIRONMENT,
): OtpPolicy {
  if ((process.env.CNS_OTP_MAX_RESENDS ?? "") !== "") {
    throw new Error("CNS_OTP_MAX_RESENDS se retiró (SEC-CNS-021 PR-4): P-06 (>= 60 s entre envíos y <= 3/hora, el inicial incluido) lo reemplaza. Quítala del entorno.");
  }
  const codeLength = overrides.codeLength ?? readIntEnv("CNS_OTP_CODE_LENGTH") ?? APPROVED_P01_OTP_CODE_LENGTH;
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_OTP_TTL_MS") ?? APPROVED_P02_OTP_TTL_MS;
  const maxAttempts = overrides.maxAttempts ?? readIntEnv("CNS_OTP_MAX_ATTEMPTS") ?? APPROVED_P03_OTP_MAX_ATTEMPTS;
  const budgetMaxFailures = overrides.budgetMaxFailures ?? readIntEnv("CNS_OTP_BUDGET_MAX_FAILURES") ?? APPROVED_P04_OTP_BUDGET_MAX_FAILURES;
  const budgetWindowMs = overrides.budgetWindowMs ?? readIntEnv("CNS_OTP_BUDGET_WINDOW_MS") ?? APPROVED_P04_OTP_BUDGET_WINDOW_MS;
  const maxLockedChallenges = overrides.maxLockedChallenges ?? readIntEnv("CNS_OTP_MAX_LOCKED_CHALLENGES") ?? APPROVED_P07_OTP_DECISION_MAX_LOCKED_CHALLENGES;
  const minResendIntervalMs = overrides.minResendIntervalMs ?? readIntEnv("CNS_OTP_MIN_RESEND_INTERVAL_MS", true) ?? APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS;
  const maxSendsPerHour = overrides.maxSendsPerHour ?? readIntEnv("CNS_OTP_MAX_SENDS_PER_HOUR") ?? APPROVED_P06_OTP_MAX_SENDS_PER_HOUR;

  const deviations: string[] = [];
  if (codeLength !== APPROVED_P01_OTP_CODE_LENGTH) deviations.push("P-01 (codeLength)");
  if (ttlMs !== APPROVED_P02_OTP_TTL_MS) deviations.push("P-02 (ttlMs)");
  if (maxAttempts !== APPROVED_P03_OTP_MAX_ATTEMPTS) deviations.push("P-03 (maxAttempts)");
  if (budgetMaxFailures !== APPROVED_P04_OTP_BUDGET_MAX_FAILURES) deviations.push("P-04 (budgetMaxFailures)");
  if (budgetWindowMs !== APPROVED_P04_OTP_BUDGET_WINDOW_MS) deviations.push("P-04 (budgetWindowMs)");
  if (maxLockedChallenges !== APPROVED_P07_OTP_DECISION_MAX_LOCKED_CHALLENGES) deviations.push("P-07 (maxLockedChallenges)");
  if (minResendIntervalMs !== APPROVED_P06_OTP_MIN_RESEND_INTERVAL_MS) deviations.push("P-06 (minResendIntervalMs)");
  if (maxSendsPerHour !== APPROVED_P06_OTP_MAX_SENDS_PER_HOUR) deviations.push("P-06 (maxSendsPerHour)");
  if (deviations.length > 0 && environment !== "LOCAL") {
    throw new Error(
      `Valor distinto del aprobado en SEC-CNS-006 rev. 5 §1 para ${deviations.join(", ")}: solo se permite con ` +
        "CNS_ENVIRONMENT=LOCAL (LOCAL_ONLY). Fuera de LOCAL rige el valor aprobado (fail-closed).",
    );
  }

  return { codeLength, ttlMs, maxAttempts, budgetMaxFailures, budgetWindowMs, maxLockedChallenges, minResendIntervalMs, maxSendsPerHour };
}
