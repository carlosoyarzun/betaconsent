// Gobierna: SEC-CNS-021 PR-3 (aceptada por Carlos 2026-10-08; §4.3, INV-21-10), P-34, LD-15 (LEGAL DECISION abierta: los 30 dias son un
// PLACEHOLDER, ver approved-parameters.ts PLACEHOLDER_P34_RETENTION_DAYS), SEC-CNS-006 rev. 5.
//
// Configuracion de retencion (SECURITY_EVENT_RETENTION y stores hermanos). Sin default en codigo:
//   CNS_RETENTION_SECURITY_EVENT_DAYS    ops.security_event
//   CNS_RETENTION_OTP_VERIFICATION_DAYS  app.otp_verification (por expires_at)
//   CNS_RETENTION_PURGE_RUN_DAYS         ops.purge_run
// (CNS_RETENTION_OTP_BUDGET_DAYS llega con SEC-CNS-021 PR-4, cuando exista ops.otp_budget.)
//  - STAGING / PRODUCTION / entorno desconocido: las tres son obligatorias; si falta o es invalida, lanza (el proceso no arranca).
//  - LOCAL / DEV: si no hay ninguna, la purga queda DESHABILITADA (DISABLED_LOCAL); si hay algunas pero no todas, o alguna es invalida, lanza.
// La coincidencia con ops.retention_policy la verifica startup-checks.ts (contra la base).

export interface RetentionConfig {
  readonly securityEventDays: number;
  readonly otpVerificationDays: number;
  readonly purgeRunDays: number;
}

export type RetentionConfigResult =
  | { readonly status: "CONFIGURED"; readonly config: RetentionConfig }
  | { readonly status: "DISABLED_LOCAL" };

export const RETENTION_ENV_VARS = {
  securityEventDays: "CNS_RETENTION_SECURITY_EVENT_DAYS",
  otpVerificationDays: "CNS_RETENTION_OTP_VERIFICATION_DAYS",
  purgeRunDays: "CNS_RETENTION_PURGE_RUN_DAYS",
} as const;

/** Tope defensivo (10 anos): un valor mayor casi seguro es un error de unidad. */
export const MAX_RETENTION_DAYS = 3650;
const LOCAL_ENVIRONMENTS: ReadonlySet<string> = new Set(["LOCAL", "DEV"]);

function parseDays(name: string, raw: string): number {
  const value = /^[1-9][0-9]{0,3}$/.test(raw.trim()) ? Number.parseInt(raw.trim(), 10) : Number.NaN;
  if (!Number.isInteger(value) || value > MAX_RETENTION_DAYS) {
    throw new Error(`${name} debe ser un entero de dias entre 1 y ${MAX_RETENTION_DAYS} (P-34, SEC-CNS-021).`);
  }
  return value;
}

export function loadRetentionConfig(
  env: NodeJS.ProcessEnv = process.env,
  environment: string | undefined = env.CNS_ENVIRONMENT,
): RetentionConfigResult {
  const keys = Object.keys(RETENTION_ENV_VARS) as Array<keyof typeof RETENTION_ENV_VARS>;
  const present = keys.filter((k) => (env[RETENTION_ENV_VARS[k]] ?? "") !== "");
  const isLocal = environment !== undefined && LOCAL_ENVIRONMENTS.has(environment);

  if (present.length === 0 && isLocal) return { status: "DISABLED_LOCAL" };
  const missing = keys.filter((k) => !present.includes(k)).map((k) => RETENTION_ENV_VARS[k]);
  if (missing.length > 0) {
    throw new Error(`Retencion P-34: falta configurar ${missing.join(", ")} (obligatorias fuera de LOCAL/DEV; en LOCAL/DEV se definen todas o ninguna).`);
  }
  return {
    status: "CONFIGURED",
    config: {
      securityEventDays: parseDays(RETENTION_ENV_VARS.securityEventDays, env[RETENTION_ENV_VARS.securityEventDays] as string),
      otpVerificationDays: parseDays(RETENTION_ENV_VARS.otpVerificationDays, env[RETENTION_ENV_VARS.otpVerificationDays] as string),
      purgeRunDays: parseDays(RETENTION_ENV_VARS.purgeRunDays, env[RETENTION_ENV_VARS.purgeRunDays] as string),
    },
  };
}
