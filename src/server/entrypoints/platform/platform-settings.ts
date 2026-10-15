// Gobierna: ADR-010 rev. 5 §5.4 (P-49, P-50, P-51, P-53; G-6, Carlos 2026-10-15: "Valores iniciales configurables"), "Fallo cerrado: fuera de LOCAL, si falta la configuracion de P-48..P-52, el
// proceso no arranca (startup-checks)"; seccion "Red (G-6)": plataforma solo por red privada o VPN en staging. Esa restriccion es de INFRAESTRUCTURA (firewall/unidad del host, infra/README.md);
// aqui solo se exige que el arranque declare un bind explicito (no comodin) y una allowlist de origen fuera de LOCAL. NO se asume implementada a nivel de red.
// Sin defaults fuera de LOCAL. En LOCAL se usan los valores iniciales aprobados (approved-parameters.ts). P-53 no tiene valor aprobado: fuera de LOCAL es obligatorio y sin valor no arranca.

import { isIP } from "node:net";
import {
  APPROVED_P49_AUTH_MAX_PER_IP,
  APPROVED_P49_AUTH_WINDOW_SECONDS,
  APPROVED_P50_REQUESTS_MAX_PER_MINUTE,
  APPROVED_P50_WINDOW_SECONDS,
  APPROVED_P51_STEP_UP_MAX_ATTEMPTS,
  APPROVED_P51_STEP_UP_WINDOW_SECONDS,
} from "../../modules/common/approved-parameters.ts";
import type { IdpRedirectConfig } from "./auth-routes.ts";
import { parseCidr } from "./rate-limit.ts";
import type { Cidr } from "./rate-limit.ts";

export class PlatformConfigError extends Error {
  constructor(detail: string) {
    super(`configuracion del proceso platform invalida: ${detail}. Abortando (fail-closed).`);
    this.name = "PlatformConfigError";
  }
}

export interface PlatformSettings {
  readonly bindAddress: string;
  readonly allowedCidrs: readonly Cidr[];
  readonly p49: { readonly max: number; readonly windowSeconds: number; readonly ipv4Prefix: number };
  readonly p50: { readonly max: number; readonly windowSeconds: number };
  readonly p51: { readonly max: number; readonly windowSeconds: number };
  /** P-53: null = sin tope (solo LOCAL). */
  readonly maxAwaiting: number | null;
  readonly idp?: IdpRedirectConfig;
}

type Env = Readonly<Record<string, string | undefined>>;

function int(env: Env, name: string, min: number, max: number): number | undefined {
  const v = env[name];
  if (v === undefined || v === "") return undefined;
  if (!/^[0-9]{1,9}$/.test(v) || Number(v) < min || Number(v) > max) throw new PlatformConfigError(`${name} debe ser un entero entre ${min} y ${max}`);
  return Number(v);
}

export function loadPlatformSettings(env: Env, environment: string): PlatformSettings {
  const local = environment === "LOCAL";
  const need = (name: string, value: number | undefined, fallback: number | null): number => {
    if (value !== undefined) return value;
    if (local && fallback !== null) return fallback;
    throw new PlatformConfigError(`${name} es obligatoria fuera de LOCAL (sin default)`);
  };
  const bindRaw = env.CNS_PLATFORM_BIND_ADDRESS;
  if (!local && (bindRaw === undefined || bindRaw === "")) throw new PlatformConfigError("CNS_PLATFORM_BIND_ADDRESS es obligatoria fuera de LOCAL (red privada o VPN, G-6)");
  const bindAddress = bindRaw === undefined || bindRaw === "" ? "127.0.0.1" : bindRaw;
  if (isIP(bindAddress) === 0 || bindAddress === "0.0.0.0" || bindAddress === "::") throw new PlatformConfigError("CNS_PLATFORM_BIND_ADDRESS debe ser una IP concreta (no comodin)");
  const cidrText = (env.CNS_PLATFORM_ALLOWED_CIDRS ?? "").split(",").map((s) => s.trim()).filter((s) => s !== "");
  if (!local && cidrText.length === 0) throw new PlatformConfigError("CNS_PLATFORM_ALLOWED_CIDRS es obligatoria fuera de LOCAL (allowlist de origen)");
  let allowedCidrs: Cidr[];
  try {
    allowedCidrs = cidrText.map(parseCidr);
  } catch {
    throw new PlatformConfigError("CNS_PLATFORM_ALLOWED_CIDRS contiene un CIDR invalido");
  }
  const p53 = int(env, "CNS_PLATFORM_P53_MAX_AWAITING", 1, 1_000_000);
  if (!local && p53 === undefined) throw new PlatformConfigError("CNS_PLATFORM_P53_MAX_AWAITING (P-53, sin valor aprobado) es obligatoria fuera de LOCAL");
  const idpVars = [env.CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT, env.CNS_PLATFORM_IDP_CLIENT_ID, env.CNS_PLATFORM_REDIRECT_URI].map((v) => (v === undefined || v === "" ? undefined : v));
  const idpPresent = idpVars.filter((v) => v !== undefined).length;
  if (idpPresent !== 0 && idpPresent !== 3) throw new PlatformConfigError("CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT, CNS_PLATFORM_IDP_CLIENT_ID y CNS_PLATFORM_REDIRECT_URI van juntas");
  let idp: IdpRedirectConfig | undefined;
  if (idpPresent === 3) {
    const [endpoint, clientId, redirectUri] = idpVars as [string, string, string];
    let u: URL;
    try {
      u = new URL(endpoint);
    } catch {
      throw new PlatformConfigError("el endpoint del IdP no es una URL");
    }
    if (u.protocol !== "https:" && !(local && u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost"))) {
      throw new PlatformConfigError("el endpoint del IdP debe ser https (http solo en LOCAL contra 127.0.0.1)");
    }
    idp = { authorizationEndpoint: endpoint, clientId, redirectUri };
  }
  return {
    bindAddress,
    allowedCidrs,
    p49: {
      max: need("CNS_PLATFORM_P49_MAX", int(env, "CNS_PLATFORM_P49_MAX", 1, 100_000), APPROVED_P49_AUTH_MAX_PER_IP),
      windowSeconds: need("CNS_PLATFORM_P49_WINDOW_SECONDS", int(env, "CNS_PLATFORM_P49_WINDOW_SECONDS", 1, 86_400), APPROVED_P49_AUTH_WINDOW_SECONDS),
      ipv4Prefix: int(env, "CNS_PLATFORM_P49_IPV4_PREFIX", 8, 32) ?? 24,
    },
    p50: {
      max: need("CNS_PLATFORM_P50_MAX", int(env, "CNS_PLATFORM_P50_MAX", 1, 100_000), APPROVED_P50_REQUESTS_MAX_PER_MINUTE),
      windowSeconds: need("CNS_PLATFORM_P50_WINDOW_SECONDS", int(env, "CNS_PLATFORM_P50_WINDOW_SECONDS", 1, 3_600), APPROVED_P50_WINDOW_SECONDS),
    },
    p51: {
      max: need("CNS_PLATFORM_P51_MAX", int(env, "CNS_PLATFORM_P51_MAX", 1, 1000), APPROVED_P51_STEP_UP_MAX_ATTEMPTS),
      windowSeconds: need("CNS_PLATFORM_P51_WINDOW_SECONDS", int(env, "CNS_PLATFORM_P51_WINDOW_SECONDS", 60, 86_400), APPROVED_P51_STEP_UP_WINDOW_SECONDS),
    },
    maxAwaiting: p53 ?? null,
    ...(idp === undefined ? {} : { idp }),
  };
}
