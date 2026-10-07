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
// OPEN-CM-10 (keyring): cada version tiene SU secreto (`createDecisionMakerRefKeyring`/`loadDecisionMakerRefKeyring`); una
// version activa calcula refs nuevos y las demas solo verifican eventos que la registraron. Version ausente, desconocida o
// invalida -> error uniforme fail-closed (`recomputeDecisionMakerRef`), sin probar otras versiones. Rotar con secreto nuevo
// SI es recuperacion ante compromiso del secreto anterior para refs nuevos. El ledger NO se re-escribe (append-only). NO decide nada sobre quien es el
// decisionMaker (LEGAL DECISION de Carlos).

import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import { inspect } from "node:util";

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
  const dmKey: DecisionMakerRefKey = {
    key: Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), decisionMakerRefHkdfInfo(keyVersion), 32)),
    keyVersion,
  };
  // OPEN-CM-10 P2-4: inmutable y sin exponer la clave por JSON/inspect (props no enumerables: no afectan deepEqual).
  Object.defineProperty(dmKey, "toJSON", { value: () => ({ keyVersion }), enumerable: false });
  Object.defineProperty(dmKey, inspect.custom, { value: () => `DecisionMakerRefKey { keyVersion: ${keyVersion} }`, enumerable: false });
  return Object.freeze(dmKey);
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

function assertRefInputs(tenantId: TenantId, channel: string): string {
  if (typeof tenantId !== "string" || tenantId.length === 0) throw new Error("decisionMakerRef: tenantId es obligatorio (fail-closed).");
  if (!TENANT_REF_RE.test(tenantId)) throw new Error("decisionMakerRef: tenantId debe tener forma Ref UUIDv4 en minusculas (fail-closed).");
  const normalized = normalizeChannelForRef(channel);
  if (normalized.length === 0) throw new Error("decisionMakerRef: canal normalizado vacio (fail-closed).");
  return normalized;
}

export function deriveDecisionMakerRef(dmKey: DecisionMakerRefKey, tenantId: TenantId, channel: string): string {
  const normalized = assertRefInputs(tenantId, channel);
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

/** Error uniforme del keyring (OPEN-CM-10): no distingue version ausente, desconocida o invalida, ni incluye claves. */
const KEYRING_UNAVAILABLE = "decisionMakerRef: clave de la version registrada no disponible (fail-closed).";

/**
 * Keyring version->secreto (OPEN-CM-10, INV-CM-09). Una version ACTIVA calcula refs nuevos; las demas solo
 * sirven para verificar/recomputar eventos que registraron esa version. Version ausente/desconocida/invalida -> error
 * uniforme (fail-closed), sin revelar cuales versiones existen. Nunca expone secretos (ni en toString/JSON).
 */
export interface DecisionMakerRefKeyring {
  /** Clave de la version activa (`{key, keyVersion}`), para emitir refs nuevos. */
  active(): DecisionMakerRefKey;
  /** Clave de una version para verificar; lanza error uniforme si no esta en el keyring o la version es invalida. */
  keyFor(version: unknown): DecisionMakerRefKey;
}

export function createDecisionMakerRefKeyring(secrets: ReadonlyMap<number, Buffer>, activeVersion: number): DecisionMakerRefKeyring {
  assertKeyVersion(activeVersion);
  const keys = new Map<number, DecisionMakerRefKey>();
  const raws: Buffer[] = [];
  for (const [version, secret] of secrets) {
    assertKeyVersion(version);
    for (const other of raws) {
      if (other.length === secret.length && timingSafeEqual(other, secret)) {
        throw new Error("decisionMakerRef: dos versiones del keyring comparten secreto (rotar exige un secreto distinto, fail-closed).");
      }
    }
    raws.push(Buffer.from(secret));
    keys.set(version, deriveDecisionMakerRefKey(secret, version));
  }
  if (!keys.has(activeVersion)) throw new Error("decisionMakerRef: la version activa no tiene secreto en el keyring (fail-closed).");
  const keyring: DecisionMakerRefKeyring = {
    active: () => keys.get(activeVersion) as DecisionMakerRefKey,
    keyFor(version: unknown): DecisionMakerRefKey {
      const k = typeof version === "number" ? keys.get(version) : undefined;
      if (k === undefined) throw new Error(KEYRING_UNAVAILABLE);
      return k;
    },
  };
  return Object.freeze(keyring);
}

/** Verificador: recomputa un ref historico con la clave de la version registrada en su evento (no prueba todas). */
export function recomputeDecisionMakerRef(keyring: DecisionMakerRefKeyring, payload: Readonly<Record<string, unknown>>, tenantId: TenantId, channel: string): string {
  let version: number;
  try {
    version = resolveDecisionMakerRefKeyVersion(payload);
  } catch {
    throw new Error(KEYRING_UNAVAILABLE);
  }
  assertRefInputs(tenantId, channel); // P2-3: entradas invalidas fallan igual con cualquier version, antes de consultar el keyring.
  return deriveDecisionMakerRef(keyring.keyFor(version), tenantId, channel);
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
  return decodeSecret(raw, "CNS_DECISION_MAKER_REF_SECRET");
}

const VERSIONED_SECRET_PREFIX = "CNS_DECISION_MAKER_REF_SECRET_V";
const VERSIONED_SECRET_RE = /^CNS_DECISION_MAKER_REF_SECRET_V([1-9]\d{0,3})$/;
const VERSION_RE = /^[1-9]\d{0,3}$/;

/** Base64 estricto: ida y vuelta (re-encode == entrada sin padding ni espacios de borde) y al menos 32 bytes. */
function decodeSecret(raw: string, name: string): Buffer {
  const secret = Buffer.from(raw, "base64");
  const norm = (x: string): string => x.trim().replace(/=+$/, "");
  if (norm(secret.toString("base64")) !== norm(raw) || secret.length < 32) {
    throw new Error(`${name} debe ser base64 valido de al menos 32 bytes. Abortando (fail-closed).`);
  }
  return secret;
}

/**
 * Keyring desde el entorno (OPEN-CM-10). Misma forma de carga que la clave actual:
 *  - `CNS_DECISION_MAKER_REF_SECRET`: secreto de la v2 (legado; sin otras variables, el keyring es {2} activo 2).
 *  - `CNS_DECISION_MAKER_REF_SECRET_V<N>` (N >= 3): secreto de la version N (base64, >= 32 bytes, distinto de los demas).
 *  - `CNS_DECISION_MAKER_REF_ACTIVE_VERSION`: version activa; obligatoria si hay variables versionadas; por defecto 2.
 * Fuera de LOCAL, cualquier falta aborta. En LOCAL sin variables: claves sinteticas de dev (v2, y la activa si es > 2).
 * Los mensajes de error nunca incluyen valores de secretos.
 */
export function loadDecisionMakerRefKeyring(env: Readonly<Record<string, string | undefined>>, environment: string): DecisionMakerRefKeyring {
  const secrets = new Map<number, Buffer>();
  secrets.set(2, loadDecisionMakerRefSecret(env, environment));
  let hasVersioned = false;
  for (const [name, raw] of Object.entries(env)) {
    if (!name.startsWith(VERSIONED_SECRET_PREFIX)) continue;
    const m = VERSIONED_SECRET_RE.exec(name);
    // C1: una variable con el prefijo versionado que no es canonica (ceros a la izquierda, no numerica...) falla cerrado.
    if (m === null) throw new Error("decisionMakerRef: nombre de variable versionada invalido (fail-closed).");
    if (raw === undefined || raw === "") continue;
    const version = Number(m[1]);
    if (version < 3) throw new Error("decisionMakerRef: la v2 se configura solo con CNS_DECISION_MAKER_REF_SECRET (fail-closed).");
    if (secrets.has(version)) throw new Error("decisionMakerRef: version repetida en la configuracion (fail-closed).");
    hasVersioned = true;
    secrets.set(version, decodeSecret(raw, name));
  }
  const rawActive = env.CNS_DECISION_MAKER_REF_ACTIVE_VERSION;
  if (hasVersioned && (rawActive === undefined || rawActive === "")) {
    throw new Error("CNS_DECISION_MAKER_REF_ACTIVE_VERSION es obligatoria si hay secretos versionados. Abortando (fail-closed).");
  }
  if (rawActive !== undefined && rawActive !== "" && !VERSION_RE.test(rawActive)) {
    throw new Error("CNS_DECISION_MAKER_REF_ACTIVE_VERSION invalida. Abortando (fail-closed).");
  }
  const active = rawActive === undefined || rawActive === "" ? 2 : Number(rawActive);
  if (!Number.isInteger(active)) throw new Error("CNS_DECISION_MAKER_REF_ACTIVE_VERSION invalida. Abortando (fail-closed).");
  if (environment === "LOCAL" && !secrets.has(active) && active >= 3 && active <= 1000) {
    secrets.set(active, Buffer.from(`LOCAL_ONLY_DEV_DECISION_MAKER_REF_SECRET_V${active}_SYNTHETIC_DATA_ONLY`));
  }
  return createDecisionMakerRefKeyring(secrets, active);
}
