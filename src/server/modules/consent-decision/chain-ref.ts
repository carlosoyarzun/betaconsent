// Gobierna: ADR-002 §10 (chainRef opaco), consent-decision.spec.yaml (decisionChainKey = tenantRef,
// contextRef, subjectRef, decisionMakerRef), SEC-CNS-017 F2 (P1).
//
// chainRef = `chain:` + HMAC-SHA256(hex) con clave por entorno sobre la tupla decisionChainKey. Es
// determinista (misma tupla -> mismo chainRef: findActiveGrantByChain y la unicidad de grant activo
// por cadena no cambian) pero opaco y de largo fijo (70 caracteres): ya no expone tenantId,
// subjectRef ni el hash sin sal de decisionMakerRef. NO decide nada sobre decisionMakerRef en si
// (LEGAL DECISION de Carlos).

import { createHmac, hkdfSync } from "node:crypto";

/** `info` HKDF propio y separado del de las firmas de sesion, handles y OTP. */
export const CHAIN_REF_HKDF_INFO = "consent-app/chain-ref/v1";

export function deriveChainRefKey(secret: Buffer): Buffer {
  if (secret.length < 32) throw new Error("chainRef: el secreto raiz debe tener al menos 32 bytes (fail-closed).");
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), CHAIN_REF_HKDF_INFO, 32));
}

export function deriveChainRef(key: Buffer, tenantId: string, contextRef: string, subjectRef: string, decisionMakerRef: string): string {
  // Cada componente va con prefijo de longitud: la tupla es inambigua (sin colision por concatenacion).
  const message = [tenantId, contextRef, subjectRef, decisionMakerRef].map((p) => `${Buffer.byteLength(p)}:${p}`).join("|");
  return `chain:${createHmac("sha256", key).update(message).digest("hex")}`;
}

/** Secreto raiz del chainRef. `CNS_CHAIN_REF_SECRET` (base64, >=32 bytes). Fuera de LOCAL, sin el: aborta
 * (fail-closed). En LOCAL sin el: constante LOCAL_ONLY (datos sinteticos), estable entre reinicios para
 * que las cadenas persistidas en Postgres sigan resolviendose. */
export function loadChainRefSecret(env: Readonly<Record<string, string | undefined>>, environment: string): Buffer {
  const raw = env.CNS_CHAIN_REF_SECRET;
  if (raw === undefined || raw === "") {
    if (environment !== "LOCAL") {
      throw new Error("CNS_CHAIN_REF_SECRET es obligatorio fuera de LOCAL (chainRef opaco, ADR-002 §10). Abortando (fail-closed).");
    }
    return Buffer.from("LOCAL_ONLY_DEV_CHAIN_REF_SECRET_SYNTHETIC_DATA_ONLY");
  }
  const secret = Buffer.from(raw, "base64");
  if (secret.length < 32) throw new Error("CNS_CHAIN_REF_SECRET debe ser base64 de al menos 32 bytes. Abortando (fail-closed).");
  return secret;
}
