// Gobierna: ADR-010 rev. 4 §4.1 (proceso verifier = integrity_verifier, unico con egress al IdP), §4.3 (puntos 2-4), §7 fila PR-6 ("Entrypoints ...; pools por rol"), INV-DBR-02;
// registers/findings-register-IT0.md F-A10-23 (el IdP sintetico se niega en el proceso verifier fuera de LOCAL, ademas del constructor), F-PR6-08 (environment de fuente confiable).
//
// Logica del proceso verifier (sin HTTP): un pool del rol integrity_verifier, chequeos de arranque con expectedRole, y un bucle de runVerifierCycle. Este archivo es un ENTRYPOINT
// (ADR-001 §11): puede importar adaptadores. El dominio (step-up/verifier.ts) no conoce Postgres ni el IdP concreto.
// IT0 sintetico: el unico IdP disponible es el sintetico (LOCAL). El adaptador real del IdP llega apagado en PR-6b (APR-IDP y P-45 PENDING): fuera de LOCAL este proceso NO arranca.
// Cero PII y cero secretos en logs: solo nombres de error / enums de resultado.

import { SyntheticIdpAdapter } from "../../../infra/adapters/synthetic-idp.adapter.ts";
import { createPgOidcExchangeStore } from "../../../infra/adapters/postgres/oidc-exchange.adapter.ts";
import { openProcessPool, parseRuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import type { RuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import { VerifierConfigError } from "../../modules/step-up/id-token.ts";
import { runVerifierCycle, validateVerifierConfig } from "../../modules/step-up/verifier.ts";
import type { VerifierConfig, VerifierCycleResult } from "../../modules/step-up/verifier.ts";
import type { IdpClientPort } from "../../ports/idp-client.port.ts";
import type { LoginLimits } from "../../ports/oidc-exchange.port.ts";

/** F-A10-23: el proceso verifier niega un IdP sintetico (marca estructural o instancia) fuera de LOCAL. Fail-closed. */
export function assertIdpAllowedForEnvironment(idp: IdpClientPort, environment: string): void {
  const synthetic = idp.synthetic === true || idp instanceof SyntheticIdpAdapter;
  if (synthetic && environment !== "LOCAL") {
    throw new VerifierConfigError("el IdP sintetico no puede cablearse fuera de LOCAL (F-A10-23)");
  }
}

export interface VerifierProcessSettings {
  readonly issuer: string;
  readonly audience: string;
  /** P-36 (PENDING): sin default; viene del entorno y se valida en validateVerifierConfig. */
  readonly maxAuthAgeSeconds: number;
  readonly requiredAcrAnyOf: readonly string[];
  readonly subHmacKey: Buffer;
  /** P-48/P-52 (G-6/G-7). undefined = no configurados: solo LOCAL arranca (valores iniciales aprobados); fuera de LOCAL validateVerifierConfig lanza. */
  readonly login?: LoginLimits;
  /** Version vigente de K_sub (F-PR6-16). Default 1. */
  readonly subKeyVersion?: number;
}

function requiredEnv(env: Readonly<Record<string, string | undefined>>, name: string): string {
  const value = env[name];
  if (value === undefined || value === "") throw new VerifierConfigError(`${name} es obligatoria (sin default)`);
  return value;
}

function optionalInt(env: Readonly<Record<string, string | undefined>>, name: string): number | undefined {
  const value = env[name];
  if (value === undefined || value === "") return undefined;
  if (!/^[0-9]{1,9}$/.test(value)) throw new VerifierConfigError(`${name} debe ser un entero positivo`);
  return Number(value);
}

/** P-48/P-52 por entorno: las tres variables juntas o ninguna (una configuracion parcial es un despliegue roto). */
function loadLoginLimits(env: Readonly<Record<string, string | undefined>>): LoginLimits | undefined {
  const max = optionalInt(env, "CNS_VERIFIER_P48_MAX_FAILURES");
  const window = optionalInt(env, "CNS_VERIFIER_P48_WINDOW_SECONDS");
  const life = optionalInt(env, "CNS_VERIFIER_P52_ASSERTION_SECONDS");
  const present = [max, window, life].filter((v) => v !== undefined).length;
  if (present === 0) return undefined;
  if (present !== 3 || max === undefined || window === undefined || life === undefined) {
    throw new VerifierConfigError("CNS_VERIFIER_P48_MAX_FAILURES, CNS_VERIFIER_P48_WINDOW_SECONDS y CNS_VERIFIER_P52_ASSERTION_SECONDS van juntas");
  }
  return { p48MaxFailures: max, p48WindowSeconds: window, p52AssertionSeconds: life };
}

/** Lee la configuracion del verifier del entorno. Sin defaults para parametros PENDING (P-36, APR-IDP): si falta alguno, el proceso no arranca. */
export function loadVerifierSettings(env: Readonly<Record<string, string | undefined>>): VerifierProcessSettings {
  const keyHex = requiredEnv(env, "CNS_VERIFIER_SUB_HMAC_KEY_HEX");
  if (!/^[0-9a-f]{64,}$/i.test(keyHex) || keyHex.length % 2 !== 0) throw new VerifierConfigError("CNS_VERIFIER_SUB_HMAC_KEY_HEX debe ser hex de al menos 32 bytes");
  const maxAuthAge = Number(requiredEnv(env, "CNS_VERIFIER_MAX_AUTH_AGE_SECONDS"));
  const acr = (env.CNS_VERIFIER_REQUIRED_ACR_ANY_OF ?? "").split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  return {
    issuer: requiredEnv(env, "CNS_VERIFIER_ISSUER"),
    audience: requiredEnv(env, "CNS_VERIFIER_AUDIENCE"),
    maxAuthAgeSeconds: maxAuthAge,
    requiredAcrAnyOf: acr,
    subHmacKey: Buffer.from(keyHex, "hex"),
    ...(loadLoginLimits(env) === undefined ? {} : { login: loadLoginLimits(env) as LoginLimits }),
    ...(optionalInt(env, "CNS_VERIFIER_SUB_KEY_VERSION") === undefined ? {} : { subKeyVersion: optionalInt(env, "CNS_VERIFIER_SUB_KEY_VERSION") as number }),
  };
}

/**
 * Fabrica del IdP del proceso. LOCAL: sintetico. Fuera de LOCAL no hay IdP activable (el adaptador real llega apagado en PR-6b; APR-IDP y P-45 PENDING): lanza.
 * Devuelve el IdP ya validado con assertIdpAllowedForEnvironment.
 */
export function createVerifierIdp(environment: RuntimeEnvironment, settings: Pick<VerifierProcessSettings, "issuer" | "audience">): IdpClientPort {
  if (environment !== "LOCAL") throw new VerifierConfigError("no hay IdP real activable fuera de LOCAL (APR-IDP y P-45 PENDING; adaptador real en PR-6b, apagado)");
  const idp = new SyntheticIdpAdapter({ environment, issuer: settings.issuer, audience: settings.audience });
  assertIdpAllowedForEnvironment(idp, environment);
  return idp;
}

export interface VerifierProcess {
  /** Ejecuta un ciclo (tomar UNA solicitud). Util para tests y para el bucle. */
  cycle(): Promise<VerifierCycleResult>;
  stop(): Promise<void>;
}

export interface StartVerifierProcessOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Solo tests: IdP inyectado. Se valida igual con assertIdpAllowedForEnvironment (F-A10-23). */
  readonly idp?: IdpClientPort;
  readonly now?: () => number;
}

/**
 * Arranque del proceso verifier. Orden fail-closed: (1) environment (enum cerrado, CNS_ENVIRONMENT); (2) configuracion completa; (3) IdP permitido para el entorno (F-A10-23);
 * (4) pool UNICO de integrity_verifier + chequeos de arranque (el environment debe coincidir con ops.db_catalog, F-PR6-08). Cualquier fallo lanza antes de tomar nada de la cola.
 */
export async function startVerifierProcess(options: StartVerifierProcessOptions = {}): Promise<VerifierProcess> {
  const env = options.env ?? process.env;
  const environment = parseRuntimeEnvironment(env.CNS_ENVIRONMENT);
  const settings = loadVerifierSettings(env);
  const config: VerifierConfig = {
    issuer: settings.issuer,
    audience: settings.audience,
    allowedAlgs: ["EdDSA"],
    maxAuthAgeSeconds: settings.maxAuthAgeSeconds,
    environment,
    requiredAcrAnyOf: settings.requiredAcrAnyOf,
    subHmacKey: settings.subHmacKey,
    ...(settings.login === undefined ? {} : { login: settings.login }),
    ...(settings.subKeyVersion === undefined ? {} : { subKeyVersion: settings.subKeyVersion }),
  };
  const now = options.now ?? Date.now;
  validateVerifierConfig(config, Math.floor(now() / 1000));
  const idp = options.idp ?? createVerifierIdp(environment, settings);
  assertIdpAllowedForEnvironment(idp, environment);
  const pool = await openProcessPool({ process: "verifier", environment, env, max: 2 });
  const store = createPgOidcExchangeStore(pool);
  return {
    cycle: () => runVerifierCycle({ store, idp, config, now }),
    stop: () => pool.end(),
  };
}

/** Bucle del proceso: un ciclo por tick; los resultados son enums. Un VerifierConfigError aborta (despliegue roto). */
export async function runVerifierLoop(proc: VerifierProcess, signal: AbortSignal, pollMs = 1000): Promise<void> {
  while (!signal.aborted) {
    let result: VerifierCycleResult;
    try {
      result = await proc.cycle();
    } catch (error) {
      if (error instanceof VerifierConfigError) throw error;
      console.error(`verifier_cycle_error name=${(error as Error).name}`);
      result = "IDLE";
    }
    if (result === "IDLE") await new Promise<void>((resolve) => {
      const t = setTimeout(resolve, pollMs);
      signal.addEventListener("abort", () => { clearTimeout(t); resolve(); }, { once: true });
    });
  }
}
