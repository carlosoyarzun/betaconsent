// Gobierna: ADR-010 rev. 4 §4.3 (puntos 2-4), §4.1 (proceso verifier = integrity_verifier), §7 fila PR-4 (DF-4, F-X8-15).
// Modulo del proceso verifier (el entrypoint/unidad de servicio llega en PR-6): un ciclo = tomar UNA solicitud del canje, canjear el code en el IdP (el unico
// proceso con egress), verificar el ID token y registrar la asercion. platform NO canjea ni lee code/PKCE.
// Limites de IA (Master Plan §32): este codigo no decide si existe consentimiento ni la autoridad de nadie; solo atesta que la persona que inicio el step-up
// se autentico en el IdP. La decision de si el sub_hmac corresponde al principal_ref la toma la BASE (platform.record_assertion, N6), no este modulo.
// Cero PII y cero secretos en logs/errores: el resultado del ciclo es un enum; nunca se devuelve el token, el code ni los claims.

// ADR-010 rev. 5 PR-6b (§5.2 paso 3): ademas del step-up, el ciclo atiende LOGIN_PLATFORM / LOGIN_CASE. En un login el verifier entrega el sub_hmac (con su key_version) y la BASE resuelve el
// principal (record_login_assertion); este modulo nunca recibe ni conoce el principal. auth_time es obligatorio (id-token.ts) y su frescura frente a la creacion del flujo (G-5) la impone la base.

import { computeSubHmac, IdTokenRejected, validateIdTokenPolicy, VerifierConfigError, verifyIdToken } from "./id-token.ts";
import type { IdTokenPolicy } from "./id-token.ts";
import {
  APPROVED_P48_LOGIN_MAX_FAILURES,
  APPROVED_P48_LOGIN_WINDOW_SECONDS,
  APPROVED_P52_LOGIN_ASSERTION_SECONDS,
} from "../common/approved-parameters.ts";
import type { IdpClientPort } from "../../ports/idp-client.port.ts";
import type { LoginLimits, OidcExchangeStorePort, RejectionReason } from "../../ports/oidc-exchange.port.ts";

export interface VerifierConfig {
  issuer: string;
  audience: string;
  allowedAlgs: IdTokenPolicy["allowedAlgs"];
  /** P-36 (PENDING): se pasa explicito; no hay default. */
  maxAuthAgeSeconds: number;
  /** Entorno del proceso (sin default). Fuera de LOCAL, `requiredAcrAnyOf` no vacio es obligatorio (decision de Carlos 2026-10-12). */
  environment: string;
  /** APR-IDP (PENDING): los valores los fija Carlos/studio. Vacio/ausente solo se admite en LOCAL; fuera de LOCAL la configuracion falla cerrada. */
  requiredAcrAnyOf?: readonly string[];
  /** K_sub del SecretStore (F-X8-09 pendiente): >= 32 bytes. */
  subHmacKey: Buffer;
  /**
   * Lease del claim en segundos (entero 1..120, default 30). record_assertion exige un lease VIGENTE: el timeout HTTP del IdP (canje + JWKS) debe ser MENOR que el lease
   * (el adaptador real lo impone; el sintetico no tiene red) o la asercion se rechaza.
   */
  leaseSeconds?: number;
  clockSkewSeconds?: number;
  /**
   * P-48 / P-52 (G-6, G-7; Carlos 2026-10-15): limites del login, por configuracion. OBLIGATORIO fuera de LOCAL (sin el, validateVerifierConfig lanza y el proceso no arranca: fail-closed).
   * En LOCAL, si falta, se usan los valores iniciales aprobados (approved-parameters.ts).
   */
  login?: LoginLimits;
  /** Version vigente de K_sub (F-PR6-16; la rotacion con doble HMAC es PR-7). Entero 1..1000, default 1. */
  subKeyVersion?: number;
}

const isInt = (value: unknown, min: number, max: number): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;

/** Limites de login efectivos: la configuracion explicita o, SOLO en LOCAL, los valores iniciales aprobados. */
export function resolveLoginLimits(config: Pick<VerifierConfig, "login" | "environment">): LoginLimits {
  if (config.login !== undefined) return config.login;
  if (config.environment === "LOCAL") {
    return {
      p48MaxFailures: APPROVED_P48_LOGIN_MAX_FAILURES,
      p48WindowSeconds: APPROVED_P48_LOGIN_WINDOW_SECONDS,
      p52AssertionSeconds: APPROVED_P52_LOGIN_ASSERTION_SECONDS,
    };
  }
  throw new VerifierConfigError("los limites de login P-48/P-52 son obligatorios fuera de LOCAL");
}

export interface VerifierDeps {
  store: OidcExchangeStorePort;
  idp: IdpClientPort;
  config: VerifierConfig;
  /** Reloj inyectable (ms desde epoch). */
  now?: () => number;
}

/** Resultado de un ciclo: nunca incluye datos del token. */
export type VerifierCycleResult = "IDLE" | "ATTESTED" | "REJECTED";

/** Valida la configuracion COMPLETA antes de tomar nada de la cola. Lanza VerifierConfigError (el ciclo aborta; no se registra REJECTED). */
export function validateVerifierConfig(config: VerifierConfig, nowSeconds: number): void {
  validateIdTokenPolicy({
    issuer: config.issuer,
    audience: config.audience,
    allowedAlgs: config.allowedAlgs,
    maxAuthAgeSeconds: config.maxAuthAgeSeconds,
    environment: config.environment,
    ...(config.requiredAcrAnyOf === undefined ? {} : { requiredAcrAnyOf: config.requiredAcrAnyOf }),
    ...(config.clockSkewSeconds === undefined ? {} : { clockSkewSeconds: config.clockSkewSeconds }),
    nowSeconds,
  });
  const lease = config.leaseSeconds ?? 30;
  if (typeof lease !== "number" || !Number.isSafeInteger(lease) || lease < 1 || lease > 120) throw new VerifierConfigError("leaseSeconds debe ser un entero entre 1 y 120");
  if (!Buffer.isBuffer(config.subHmacKey) || config.subHmacKey.length < 32) throw new VerifierConfigError("K_sub debe tener al menos 32 bytes");
  const limits = resolveLoginLimits(config);
  // Rangos que la base tambien impone (0051): P-48 1..1000 intentos y ventana 60..86400 s; P-52 1..300 s (la base no admite mas de los 5 min aprobados).
  if (!isInt(limits.p48MaxFailures, 1, 1000) || !isInt(limits.p48WindowSeconds, 60, 86400) || !isInt(limits.p52AssertionSeconds, 1, 300)) {
    throw new VerifierConfigError("limites de login fuera de rango (P-48: 1..1000 y 60..86400 s; P-52: 1..300 s)");
  }
  if (config.subKeyVersion !== undefined && !isInt(config.subKeyVersion, 1, 1000)) throw new VerifierConfigError("subKeyVersion debe ser un entero entre 1 y 1000");
}

function rejectionFor(error: unknown): RejectionReason {
  return error instanceof IdTokenRejected ? "INVALID_CLAIMS" : "EXCHANGE_FAILED";
}

export async function runVerifierCycle(deps: VerifierDeps): Promise<VerifierCycleResult> {
  const { store, idp, config } = deps;
  const now = deps.now ?? Date.now;
  validateVerifierConfig(config, Math.floor(now() / 1000));
  const claimed = await store.claim(config.leaseSeconds ?? 30);
  if (claimed === null) return "IDLE";

  try {
    // El code y el verifier PKCE solo existen en este alcance; se anulan en la base al registrar la asercion.
    const { idToken } = (await idp.exchangeCode({ code: claimed.code, pkceVerifier: claimed.pkceVerifier }));
    const jwks = await idp.getJwks();
    const verified = verifyIdToken(idToken, jwks, claimed.nonceHash, {
      issuer: config.issuer,
      audience: config.audience,
      allowedAlgs: config.allowedAlgs,
      maxAuthAgeSeconds: config.maxAuthAgeSeconds,
      environment: config.environment,
      ...(config.requiredAcrAnyOf === undefined ? {} : { requiredAcrAnyOf: config.requiredAcrAnyOf }),
      ...(config.clockSkewSeconds === undefined ? {} : { clockSkewSeconds: config.clockSkewSeconds }),
      nowSeconds: Math.floor(now() / 1000),
    });
    const subHmac = computeSubHmac(config.subHmacKey, config.issuer, verified.sub);
    if (claimed.kind !== "STEP_UP") {
      // LOGIN_*: la base resuelve el principal por (key_version, sub_hmac) y no lo devuelve; aqui solo se sabe si quedo ATTESTED.
      const loginAttested = await store.recordLoginAssertion({
        decision: "ATTESTED",
        exchangeRef: claimed.exchangeRef,
        subHmac,
        keyVersion: config.subKeyVersion ?? 1,
        assertionHash: verified.assertionHash,
        authTime: verified.authTime,
        acr: verified.acr,
        amr: verified.amr,
        limits: resolveLoginLimits(config),
      });
      return loginAttested ? "ATTESTED" : "REJECTED";
    }
    const attested = await store.recordAssertion({
      decision: "ATTESTED",
      exchangeRef: claimed.exchangeRef,
      subHmac,
      assertionHash: verified.assertionHash,
      authTime: verified.authTime,
      acr: verified.acr,
      amr: verified.amr,
    });
    // La base puede degradar a REJECTED (sub_hmac no mapeado al principal, nonce vencido): el resultado refleja lo que quedo registrado.
    return attested ? "ATTESTED" : "REJECTED";
  } catch (error) {
    if (error instanceof VerifierConfigError) throw error; // despliegue roto: se aborta, no se "rechaza" al titular
    // Cualquier fallo del canje o de la verificacion cierra la solicitud como REJECTED (sin detalle). Si ni eso se puede registrar, la solicitud vence por TTL.
    if (claimed.kind !== "STEP_UP") {
      const identity = error instanceof IdTokenRejected && error.verifiedSub !== undefined
        ? { subHmac: computeSubHmac(config.subHmacKey, config.issuer, error.verifiedSub), keyVersion: config.subKeyVersion ?? 1 }
        : undefined;
      await store.recordLoginAssertion({
        decision: "REJECTED",
        exchangeRef: claimed.exchangeRef,
        reason: rejectionFor(error) === "INVALID_CLAIMS" ? "INVALID_CLAIMS" : "EXCHANGE_FAILED",
        ...(identity === undefined ? {} : { identity }),
      });
    } else {
      await store.recordAssertion({ decision: "REJECTED", exchangeRef: claimed.exchangeRef, reason: rejectionFor(error) });
    }
    return "REJECTED";
  }
  // El ID token crudo solo existio dentro del try: no se asigna fuera ni se devuelve.
}
