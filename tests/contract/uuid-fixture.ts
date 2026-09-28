// Fixture de tests (SYNTHETIC DATA ONLY): deriva una Ref UUIDv4 determinista desde una etiqueta
// legible, para que los eventos del ledger de los tests cumplan common.schema.json#/$defs/Ref
// (CA-127) sin perder la trazabilidad "rv-575" -> UUID estable entre corridas.

import { createHash } from "node:crypto";

export function fixtureUuid(label: string): string {
  const h = createHash("sha1").update(label).digest("hex");
  const variant = "89ab"[Number.parseInt(h.slice(16, 17), 16) % 4]!;
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
