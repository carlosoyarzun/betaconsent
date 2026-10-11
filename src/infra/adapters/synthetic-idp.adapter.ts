// Gobierna: ADR-010 rev. 4 §4.3.3 ("en LOCAL un JWKS sintetico fijo, sin egress"), §7 fila PR-4; DEC-BR-014 §4 (solo datos sinteticos); ADR-001 §11.
// APR-IDP sigue PENDING: este adaptador NO es un IdP real, no abre sockets, no lee variables de entorno ni secretos y se niega a construirse fuera de LOCAL.
//
// IdP sintetico en memoria para LOCAL y tests: genera un par Ed25519 efimero por instancia (la clave privada nunca se escribe en el repo ni en disco), publica
// su JWKS y emite ID tokens firmados. simulateAuthorization reproduce el paso del navegador: entrega un code de un solo uso y el code_verifier PKCE cuya
// code_challenge (S256) el "token endpoint" exige en el canje. Los sub son sinteticos; email se puede incluir SOLO para probar que el verifier lo descarta.

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { IdpClientPort, Jwks } from "../../server/ports/idp-client.port.ts";

export interface SyntheticAuthorization {
  sub: string;
  /** `nonce` en claro que el RP envio en la solicitud de autorizacion (el action nonce de step-up). */
  nonce: string;
  /** Segundos desde epoch; default now. */
  authTime?: number;
  acr?: string;
  amr?: readonly string[];
  /** Solo para probar el descarte del claim (nunca se persiste). Debe ser un dominio reservado .invalid. */
  email?: string;
  /** Sobrescrituras para tests negativos. */
  overrides?: Record<string, unknown>;
}

export interface SyntheticIdpOptions {
  environment: string;
  issuer: string;
  audience: string;
  /** Reloj inyectable (ms). */
  now?: () => number;
  tokenLifetimeSeconds?: number;
}

export class SyntheticIdpAdapter implements IdpClientPort {
  readonly issuer: string;
  readonly audience: string;
  private readonly now: () => number;
  private readonly lifetime: number;
  private readonly privateKey: KeyObject;
  private readonly jwks: Jwks;
  private readonly kid: string;
  private readonly pending = new Map<string, { challenge: string; auth: SyntheticAuthorization }>();

  constructor(options: SyntheticIdpOptions) {
    if (options.environment !== "LOCAL") throw new Error("SyntheticIdpAdapter solo existe en LOCAL (APR-IDP pendiente; sin IdP real). Abortando (fail-closed).");
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.now = options.now ?? Date.now;
    this.lifetime = options.tokenLifetimeSeconds ?? 300;
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    this.privateKey = privateKey;
    this.kid = randomBytes(8).toString("hex");
    this.jwks = { keys: [{ ...(publicKey.export({ format: "jwk" }) as Record<string, string>), kty: "OKP", crv: "Ed25519", kid: this.kid, alg: "EdDSA", use: "sig" }] };
  }

  /** Paso del navegador: devuelve el code (un solo uso) y el code_verifier PKCE que el RP guarda. */
  simulateAuthorization(auth: SyntheticAuthorization): { code: string; pkceVerifier: string } {
    const pkceVerifier = randomBytes(48).toString("base64url");
    const code = randomBytes(24).toString("base64url");
    this.pending.set(code, { challenge: createHash("sha256").update(pkceVerifier, "utf8").digest("base64url"), auth });
    return { code, pkceVerifier };
  }

  async exchangeCode(input: { code: string; pkceVerifier: string }): Promise<{ idToken: string }> {
    const entry = this.pending.get(input.code);
    this.pending.delete(input.code); // un solo uso, aun si el canje falla
    if (entry === undefined) throw new Error("code invalido");
    if (createHash("sha256").update(input.pkceVerifier, "utf8").digest("base64url") !== entry.challenge) throw new Error("pkce invalido");
    return { idToken: this.sign(entry.auth) };
  }

  async getJwks(): Promise<Jwks> {
    return this.jwks;
  }

  /** Firma un token arbitrario con la clave del IdP (para tests: claims manipulados con firma valida). */
  signRaw(claims: Record<string, unknown>, header: Record<string, unknown> = {}): string {
    const h = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: this.kid, ...header })).toString("base64url");
    const p = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const s = sign(null, Buffer.from(`${h}.${p}`, "utf8"), this.privateKey).toString("base64url");
    return `${h}.${p}.${s}`;
  }

  private sign(auth: SyntheticAuthorization): string {
    const nowSeconds = Math.floor(this.now() / 1000);
    return this.signRaw({
      iss: this.issuer,
      aud: this.audience,
      sub: auth.sub,
      iat: nowSeconds,
      exp: nowSeconds + this.lifetime,
      nonce: auth.nonce,
      auth_time: auth.authTime ?? nowSeconds,
      ...(auth.acr === undefined ? {} : { acr: auth.acr }),
      ...(auth.amr === undefined ? {} : { amr: [...auth.amr] }),
      ...(auth.email === undefined ? {} : { email: auth.email }),
      ...(auth.overrides ?? {}),
    });
  }
}
