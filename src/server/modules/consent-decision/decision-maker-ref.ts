// Gobierna: LEGAL DECISION decisionMakerRef (Carlos, 2026-10-01, "confirmo el paquete con D6 segun
// DEC-BR-014"), CA-128. Patron: chain-ref.ts (HKDF con `info` propio + HMAC-SHA256 por entorno).
//
// decisionMakerRef = UUIDv4 derivado de HMAC-SHA256 del canal normalizado, con clave propia derivada por
// HKDF de un secreto de entorno separado (CNS_DECISION_MAKER_REF_SECRET), distinta de las claves de
// cookies/handles y de chainRef. El contrato exige `Ref` UUIDv4 (common.schema.json; ledger
// DECISION_MAKER_CHANNEL_VERIFIED.decisionMakerRef), asi que los primeros 128 bits del HMAC se mapean a
// UUIDv4 fijando version y variante (X6 P1-A). No queda ninguna derivacion sin clave. Determinista: mismo
// canal normalizado EN EL MISMO TENANT -> mismo ref (chainRef y unicidad de grant activo no cambian de semantica).
//
// POR TENANT (LEGAL DECISION, Carlos 2026-10-01, opcion (a) por tenant/colegio; KEY_VERSION 2): el `tenantId` entra
// en el mensaje HMAC con prefijo de longitud fija (uint32 BE del largo en bytes UTF-8) y un separador de dominio:
//   HMAC(K, "dmref\0" || u32be(len(tenant)) || tenant || normalizedChannel)
// sin ambiguedad de concatenacion (el largo delimita el tenant). La misma persona en dos colegios obtiene refs
// distintos y no correlacionables sin la clave; en el mismo colegio, el mismo ref. El tenant sale SIEMPRE del
// contexto de sesion/invitacion, nunca de input del usuario. La v1 (sin tenant) queda reemplazada: los refs v1
// eran sinteticos y no se migran.
//
// ROTACION (futura, no implementada): la version de clave `DECISION_MAKER_REF_KEY_VERSION` entra en el `info` de
// HKDF y YA NO viaja en el valor. Rotar = subir la constante (nuevo secreto + nuevo `info`): los refs nuevos son
// distintos; el ledger NO se re-escribe (append-only) y los refs historicos siguen siendo validos (el verificador
// conserva la clave vieja para recomputarlos). Nunca se re-deriva un ref viejo con la clave nueva. NO decide nada
// sobre quien es el decisionMaker (LEGAL DECISION de Carlos).

import { createHmac, hkdfSync } from "node:crypto";

import type { TenantId } from "../common/types.ts";
import { uuidV4FromDigest } from "../common/opaque-ref.ts";

/** Version de la clave: entra en el `info` de HKDF (rotar = subirla). */
export const DECISION_MAKER_REF_KEY_VERSION = 2;
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

export function deriveDecisionMakerRef(key: Buffer, tenantId: TenantId, channel: string): string {
  if (typeof tenantId !== "string" || tenantId.length === 0) throw new Error("decisionMakerRef: tenantId es obligatorio (fail-closed).");
  const tenant = Buffer.from(tenantId, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(tenant.length);
  const mac = createHmac("sha256", key)
    .update("dmref\u0000", "utf8")
    .update(len)
    .update(tenant)
    .update(normalizeChannelForRef(channel), "utf8");
  return uuidV4FromDigest(mac.digest());
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
