// Gobierna: specs/state-machines/otp-challenge.spec.yaml (V1, V2, V4; `used: [P-01, P-02, P-03, ...]`
// y `parametersRef`) y SEC-CNS-006 rev. 5 §1.
//
// Valores APROBADOS por Carlos (SEC-CNS-006 rev. 5 §1; confirmados 2026-10-08, D3 de SEC-CNS-021), en
// approved-parameters.ts y aplicables en cualquier entorno:
//   P-01 = 6 dígitos (crypto.randomInt sin sesgo)  P-02 = 10 min (hora de servidor)  P-03 = 5 intentos -> LOCKED
// Son el DEFAULT. Cualquier override (argumento o CNS_OTP_CODE_LENGTH / CNS_OTP_TTL_MS / CNS_OTP_MAX_ATTEMPTS)
// DISTINTO del aprobado solo se admite con CNS_ENVIRONMENT=LOCAL (marca LOCAL_ONLY); en cualquier otro
// entorno (incluido sin definir) lanza (fail-closed).
//
// P-06 (reenvíos): el valor aprobado es >=60 s entre envíos y <=3 envíos/hora por verificación, pero el
// modelo actual (`maxResends`, contador) no registra timestamps de envío, así que NO se puede aplicar sin
// una migración nueva + cambio en OtpVerificationRecord (FINDING reportado al Supervisor). Mientras
// tanto `maxResends` conserva el patrón D4: sin default, exigido por CNS_OTP_MAX_RESENDS u override.

import {
  APPROVED_P01_OTP_CODE_LENGTH,
  APPROVED_P02_OTP_TTL_MS,
  APPROVED_P03_OTP_MAX_ATTEMPTS,
} from "../common/approved-parameters.ts";
import type { OtpPolicy } from "./otp-challenge.ts";

export interface OtpPolicyConfigOverrides {
  readonly codeLength?: number;
  readonly ttlMs?: number;
  readonly maxAttempts?: number;
  readonly maxResends?: number;
}

function readIntEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} debe ser un entero positivo (P-01/P-02/P-03, SEC-CNS-006).`);
  }
  return value;
}

/**
 * Construye la política OTP: P-01/P-02/P-03 con el valor aprobado como default; un override distinto
 * solo en LOCAL (LOCAL_ONLY). `maxResends` (P-06) sigue sin default: lanza si falta.
 */
export function loadOtpPolicyConfig(
  overrides: OtpPolicyConfigOverrides = {},
  environment: string | undefined = process.env.CNS_ENVIRONMENT,
): OtpPolicy {
  const codeLength = overrides.codeLength ?? readIntEnv("CNS_OTP_CODE_LENGTH") ?? APPROVED_P01_OTP_CODE_LENGTH;
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_OTP_TTL_MS") ?? APPROVED_P02_OTP_TTL_MS;
  const maxAttempts = overrides.maxAttempts ?? readIntEnv("CNS_OTP_MAX_ATTEMPTS") ?? APPROVED_P03_OTP_MAX_ATTEMPTS;
  const maxResends = overrides.maxResends ?? readIntEnv("CNS_OTP_MAX_RESENDS");

  const deviations: string[] = [];
  if (codeLength !== APPROVED_P01_OTP_CODE_LENGTH) deviations.push("P-01 (codeLength)");
  if (ttlMs !== APPROVED_P02_OTP_TTL_MS) deviations.push("P-02 (ttlMs)");
  if (maxAttempts !== APPROVED_P03_OTP_MAX_ATTEMPTS) deviations.push("P-03 (maxAttempts)");
  if (deviations.length > 0 && environment !== "LOCAL") {
    throw new Error(
      `Valor distinto del aprobado en SEC-CNS-006 rev. 5 §1 para ${deviations.join(", ")}: solo se permite con ` +
        "CNS_ENVIRONMENT=LOCAL (LOCAL_ONLY). Fuera de LOCAL rige el valor aprobado (fail-closed).",
    );
  }

  if (maxResends === undefined) {
    throw new Error(
      "Política OTP incompleta: P-06 (CNS_OTP_MAX_RESENDS) no se puede aplicar como contador: el valor aprobado " +
        "(>=60 s entre envíos, <=3/hora por verificación) requiere timestamps de envío aún no modelados. " +
        "Sin default (fail-closed); dev.ts y los tests pasan override explícito LOCAL-only.",
    );
  }

  return { codeLength, ttlMs, maxAttempts, maxResends };
}
