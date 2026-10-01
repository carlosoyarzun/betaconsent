// Gobierna: common.schema.json $defs/Ref (UUIDv4 opaco, INV-CM-09; ADR-002 §3), ledger-event-payloads /
// security-event-payloads (X6 P1-A). Deriva un Ref con forma UUIDv4 de forma DETERMINISTA a partir de un
// identificador de dominio, sin exponerlo (p. ej. el canal de contacto: nunca el email en claro). Con `key`
// (HMAC-SHA256) no es invertible por diccionario sin el secreto; sin `key` es un SHA-256 simple.

import { createHash, createHmac } from "node:crypto";

export function opaqueUuidV4(label: string, input: string, key?: Buffer): string {
  const data = `${label}\u0000${input}`;
  const digest = key ? createHmac("sha256", key).update(data).digest() : createHash("sha256").update(data).digest();
  return uuidV4FromDigest(digest);
}

/** Da forma UUIDv4 a los primeros 128 bits de un digest. */
export function uuidV4FromDigest(digest: Buffer): string {
  const b = Buffer.from(digest.subarray(0, 16));
  b[6] = (b[6]! & 0x0f) | 0x40; // versión 4
  b[8] = (b[8]! & 0x3f) | 0x80; // variante RFC 4122
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * PRODUCT DECISION OPEN-CT-03 (ledger-event-payloads x-pending): el enum de `bindingResult` no está definido en la
 * spec. Hasta que Carlos lo fije, los emisores usan este placeholder (cumple ^[A-Z_]{1,40}$) y el código no decide
 * nada con él.
 */
export const BINDING_RESULT_PLACEHOLDER_OPEN_CT03 = "OPEN_CT_PENDING";
