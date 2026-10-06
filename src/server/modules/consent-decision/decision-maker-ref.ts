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
// ROTACION (OPEN-CM-09, Carlos 2026-10-06): la version de clave `DECISION_MAKER_REF_KEY_VERSION` entra en el `info`
// de HKDF y NO viaja en el valor (sigue UUIDv4 opaco). La clave viaja como `{ key, keyVersion }` y el evento de ledger
// emite `decisionMakerRefKeyVersion` desde ahi (INVITATION_VERIFIED, DECISION_MAKER_CHANNEL_VERIFIED; obligatorio en
// eventos nuevos). Un evento previo sin el campo se interpreta como v2 SOLO al leer (`resolveDecisionMakerRefKeyVersion`).
// Hoy hay UN solo secreto raiz (CNS_DECISION_MAKER_REF_SECRET): rotar la version cambia el `info` de HKDF, es decir,
// separacion de dominio entre versiones, NO recuperacion ante compromiso del secreto (quien tenga el secreto raiz
// deriva todas las versiones). Un keyring version->secreto, con fallo cerrado si falta el secreto de una version, queda
// como OPEN-CM-10 (common.spec.yaml), antes de la primera rotacion. El verificador falla cerrado si la version
// registrada es mayor que la conocida. El ledger NO se re-escribe (append-only). NO decide nada sobre quien es el
// decisionMaker (LEGAL DECISION de Carlos).

import { createHmac, hkdfSync } from "node:crypto";

import type { TenantId } from "../common/types.ts";
import { uuidV4FromDigest } from "../common/opaque-ref.ts";

/** Version de la clave: entra en el `info` de HKDF (rotar = subirla). */
export const DECISION_MAKER_REF_KEY_VERSION = 2;
/** `info` HKDF propio y separado del de chainRef, sesiones, handles y OTP. */
/** Version que se asume para eventos de ledger previos a OPEN-CM-09 (sin `decisionMakerRefKeyVersion`). La v1 (sin tenant) no se migra. */
export const LEGACY_DECISION_MAKER_REF_KEY_VERSION = 2;

function assertKeyVersion(version: unknown): asserts version is number {
  if (typeof version !== "number" || !Number.isInteger(version) || version < LEGACY_DECISION_MAKER_REF_KEY_VERSION || version > 1000) {
    throw new Error("decisionMakerRef: keyVersion invalida (entero >= 2, fail-closed).");
  }
}

export function decisionMakerRefHkdfInfo(keyVersion: number): string {
  assertKeyVersion(keyVersion);
  return `consent-app/decision-maker-ref/v${keyVersion}`;
}

export const DECISION_MAKER_REF_HKDF_INFO = decisionMakerRefHkdfInfo(DECISION_MAKER_REF_KEY_VERSION);

/** Clave derivada con su version: el evento de ledger toma `keyVersion` de aqui, no de la constante. */
export interface DecisionMakerRefKey {
  readonly key: Buffer;
  readonly keyVersion: number;
}

export function deriveDecisionMakerRefKey(secret: Buffer, keyVersion: number = DECISION_MAKER_REF_KEY_VERSION): DecisionMakerRefKey {
  if (secret.length < 32) throw new Error("decisionMakerRef: el secreto raiz debe tener al menos 32 bytes (fail-closed).");
  return { key: Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), decisionMakerRefHkdfInfo(keyVersion), 32)), keyVersion };
}

/** Version de clave de un ref historico a partir del payload del evento de ledger que lo registro (campo ausente = v2). */
export function resolveDecisionMakerRefKeyVersion(payload: Readonly<Record<string, unknown>>): number {
  const v = payload.decisionMakerRefKeyVersion;
  if (v === undefined) return LEGACY_DECISION_MAKER_REF_KEY_VERSION;
  assertKeyVersion(v);
  return v;
}

/** Normaliza el canal (trim, NFC, minusculas) para que el mismo correo siempre produzca el mismo ref. */
export function normalizeChannelForRef(channel: string): string {
  return channel.trim().normalize("NFC").toLowerCase();
}

const TENANT_REF_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function deriveDecisionMakerRef(dmKey: DecisionMakerRefKey, tenantId: TenantId, channel: string): string {
  if (typeof tenantId !== "string" || tenantId.length === 0) throw new Error("decisionMakerRef: tenantId es obligatorio (fail-closed).");
  if (!TENANT_REF_RE.test(tenantId)) throw new Error("decisionMakerRef: tenantId debe tener forma Ref UUIDv4 en minusculas (fail-closed).");
  const normalized = normalizeChannelForRef(channel);
  if (normalized.length === 0) throw new Error("decisionMakerRef: canal normalizado vacio (fail-closed).");
  const tenant = Buffer.from(tenantId, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(tenant.length);
  const mac = createHmac("sha256", dmKey.key)
    .update("dmref\u0000", "utf8")
    .update(len)
    .update(tenant)
    .update(normalized, "utf8");
  return uuidV4FromDigest(mac.digest());
}

/** Verificador: recomputa un ref historico con la clave de la version registrada en su evento (no prueba todas). */
export function recomputeDecisionMakerRef(
  secret: Buffer,
  payload: Readonly<Record<string, unknown>>,
  tenantId: TenantId,
  channel: string,
  maxKnownVersion: number = DECISION_MAKER_REF_KEY_VERSION,
): string {
  const version = resolveDecisionMakerRefKeyVersion(payload);
  if (version > maxKnownVersion) throw new Error("decisionMakerRef: keyVersion registrada mayor que la conocida (fail-closed).");
  return deriveDecisionMakerRef(deriveDecisionMakerRefKey(secret, version), tenantId, channel);
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
