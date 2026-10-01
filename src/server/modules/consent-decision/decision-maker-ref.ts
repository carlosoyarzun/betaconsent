// Gobierna: LEGAL DECISION decisionMakerRef (Carlos, 2026-10-01, "confirmo el paquete con D6 segun
// DEC-BR-014"), CA-128. Patron: chain-ref.ts (HKDF con `info` propio + HMAC-SHA256 por entorno).
//
// decisionMakerRef = `dm:v1:` + HMAC-SHA256(hex, 64) del canal normalizado, con clave propia derivada
// por HKDF de un secreto de entorno separado (CNS_DECISION_MAKER_REF_SECRET), distinta de las claves de
// cookies/handles y de chainRef. Reemplaza `dm:` + SHA-256 sin sal (los correos plausibles eran
// enumerables offline). Determinista: mismo canal normalizado -> mismo ref (la cadena de consentimiento,
// chainRef y la unicidad de grant activo no cambian de semantica). Largo 70 <= 100 y sin '@'
// (CHECK consent_decision_dm_len / invitation_dm_len).
//
// ROTACION (futura, no implementada): el segmento `v1` identifica la version de la clave. Para rotar se
// agrega `v2` (nuevo secreto + nuevo `info` `.../v2`); los refs nuevos salen como `dm:v2:`; el ledger NO
// se re-escribe (es append-only): los `dm:v1:` ya persistidos siguen siendo validos y el verificador
// mantiene la clave v1 para recomputar y comparar refs historicos. Nunca se re-deriva un ref v1 con
// clave v2. NO decide nada sobre quien es el decisionMaker (LEGAL DECISION de Carlos).

import { createHmac, hkdfSync } from "node:crypto";

export const DECISION_MAKER_REF_VERSION = "v1";
/** `info` HKDF propio y separado del de chainRef, sesiones, handles y OTP. */
export const DECISION_MAKER_REF_HKDF_INFO = "consent-app/decision-maker-ref/v1";

export function deriveDecisionMakerRefKey(secret: Buffer): Buffer {
  if (secret.length < 32) throw new Error("decisionMakerRef: el secreto raiz debe tener al menos 32 bytes (fail-closed).");
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), DECISION_MAKER_REF_HKDF_INFO, 32));
}

/** Normaliza el canal (trim, NFC, minusculas) para que el mismo correo siempre produzca el mismo ref. */
export function normalizeChannelForRef(channel: string): string {
  return channel.trim().normalize("NFC").toLowerCase();
}

export function deriveDecisionMakerRef(key: Buffer, channel: string): string {
  const mac = createHmac("sha256", key).update(normalizeChannelForRef(channel)).digest("hex");
  return `dm:${DECISION_MAKER_REF_VERSION}:${mac}`;
}

/** Secreto raiz. `CNS_DECISION_MAKER_REF_SECRET` (base64, >=32 bytes). Fuera de LOCAL, sin el: aborta
 * (fail-closed). En LOCAL sin el: constante LOCAL_ONLY (datos sinteticos). */
export function loadDecisionMakerRefSecret(env: Readonly<Record<string, string | undefined>>, environment: string): Buffer {
  const raw = env.CNS_DECISION_MAKER_REF_SECRET;
  if (raw === undefined || raw === "") {
    if (environment !== "LOCAL") {
      throw new Error("CNS_DECISION_MAKER_REF_SECRET es obligatorio fuera de LOCAL (decisionMakerRef con clave). Abortando (fail-closed).");
    }
    return Buffer.from("LOCAL_ONLY_DEV_DECISION_MAKER_REF_SECRET_SYNTHETIC_DATA_ONLY");
  }
  const secret = Buffer.from(raw, "base64");
  if (secret.length < 32) throw new Error("CNS_DECISION_MAKER_REF_SECRET debe ser base64 de al menos 32 bytes. Abortando (fail-closed).");
  return secret;
}
