// Gobierna: LEGAL DECISION decisionMakerRef (Carlos, 2026-10-01, "confirmo el paquete con D6 segun
// DEC-BR-014"), CA-128. Patron: chain-ref.ts (HKDF con `info` propio + HMAC-SHA256 por entorno).
//
// decisionMakerRef = UUIDv4 derivado de HMAC-SHA256 del canal normalizado, con clave propia derivada por
// HKDF de un secreto de entorno separado (CNS_DECISION_MAKER_REF_SECRET), distinta de las claves de
// cookies/handles y de chainRef. El contrato exige `Ref` UUIDv4 (common.schema.json; ledger
// DECISION_MAKER_CHANNEL_VERIFIED.decisionMakerRef), asi que los primeros 128 bits del HMAC se mapean a
// UUIDv4 fijando version y variante (X6 P1-A). No queda ninguna derivacion sin clave. Determinista: mismo
// canal normalizado -> mismo ref (chainRef y unicidad de grant activo no cambian de semantica).
//
// ROTACION (futura, no implementada): la version de clave `DECISION_MAKER_REF_KEY_VERSION` entra en el `info` de
// HKDF y YA NO viaja en el valor. Rotar = subir la constante (nuevo secreto + nuevo `info`): los refs nuevos son
// distintos; el ledger NO se re-escribe (append-only) y los refs historicos siguen siendo validos (el verificador
// conserva la clave vieja para recomputarlos). Nunca se re-deriva un ref viejo con la clave nueva. NO decide nada
// sobre quien es el decisionMaker (LEGAL DECISION de Carlos).

import { createHmac, hkdfSync } from "node:crypto";

import { uuidV4FromDigest } from "../common/opaque-ref.ts";

/** Version de la clave: entra en el `info` de HKDF (rotar = subirla). */
export const DECISION_MAKER_REF_KEY_VERSION = 1;
/** `info` HKDF propio y separado del de chainRef, sesiones, handles y OTP. */
export const DECISION_MAKER_REF_HKDF_INFO = `consent-app/decision-maker-ref/v${DECISION_MAKER_REF_KEY_VERSION}`;

export function deriveDecisionMakerRefKey(secret: Buffer): Buffer {
  if (secret.length < 32) throw new Error("decisionMakerRef: el secreto raiz debe tener al menos 32 bytes (fail-closed).");
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), DECISION_MAKER_REF_HKDF_INFO, 32));
}

/** Normaliza el canal (trim, NFC, minusculas) para que el mismo correo siempre produzca el mismo ref. */
export function normalizeChannelForRef(channel: string): string {
  return channel.trim().normalize("NFC").toLowerCase();
}

export function deriveDecisionMakerRef(key: Buffer, channel: string): string {
  return uuidV4FromDigest(createHmac("sha256", key).update(normalizeChannelForRef(channel)).digest());
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
