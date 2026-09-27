// Gobierna: specs/state-machines/otp-challenge.spec.yaml (V1, V2, V4; ver `used: [P-01, P-02,
// P-03, ...]` en la cabecera de esa spec) y SEC-CNS-006 P-01 (longitud del código), P-02
// (TTL) y P-03 (intentos máximos). Ninguno de esos tres parámetros tiene un valor numérico
// fijado en el repo: se citan por nombre en otp-challenge.spec.yaml:26,65 y en
// contracts/openapi/consent-it0.openapi.yaml:597,631 pero ninguno de los dos archivos define
// el valor concreto (grep de "P-01"/"P-02"/"P-03" en specs/ y contracts/ el 2026-09-27 no
// encuentra un número aprobado por Carlos ni una entrada resuelta en SEC-CNS-006).
//
// D4 (decisión de Carlos, 2026-09-27): esta config NO fija un default de producción. El
// entrypoint HTTP exige los tres valores explícitos (env o override); si faltan, no arranca
// (fail-closed, mismo patrón que loadRightsCaseHttpConfig/CNS_ALLOWED_ORIGIN). Los únicos
// valores sintéticos permitidos viven en `dev.ts` y en tests, marcados LOCAL_ONLY_* y nunca
// reutilizados como default de esta función.

import type { OtpPolicy } from "./otp-challenge.ts";

export interface OtpPolicyConfigOverrides {
  readonly codeLength?: number;
  readonly ttlMs?: number;
  readonly maxAttempts?: number;
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
 * Construye la política OTP (P-01 longitud, P-02 TTL, P-03 intentos). Sin default de
 * producción: si ninguna fuente (override explícito o variable de entorno) provee un valor,
 * lanza (fail-closed). `overrides` es la única vía LOCAL-only para tests/dev.ts.
 */
export function loadOtpPolicyConfig(overrides: OtpPolicyConfigOverrides = {}): OtpPolicy {
  const codeLength = overrides.codeLength ?? readIntEnv("CNS_OTP_CODE_LENGTH");
  const ttlMs = overrides.ttlMs ?? readIntEnv("CNS_OTP_TTL_MS");
  const maxAttempts = overrides.maxAttempts ?? readIntEnv("CNS_OTP_MAX_ATTEMPTS");

  if (codeLength === undefined || ttlMs === undefined || maxAttempts === undefined) {
    throw new Error(
      "Política OTP incompleta: P-01 (CNS_OTP_CODE_LENGTH), P-02 (CNS_OTP_TTL_MS) y P-03 " +
        "(CNS_OTP_MAX_ATTEMPTS) no tienen un valor aprobado en specs/contracts (ver cabecera de " +
        "este archivo). No hay default de producción: PENDING — Carlos debe fijar P-01/P-02/P-03 " +
        "en SEC-CNS-006 antes de un entrypoint real. dev.ts y los tests pueden pasar overrides " +
        "explícitos marcados LOCAL-only.",
    );
  }

  return { codeLength, ttlMs, maxAttempts };
}
