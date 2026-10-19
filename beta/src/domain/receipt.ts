// Gobierna: plan v2 H1-05/H1-06. Referencia opaca del comprobante: la misma función la usa la respuesta HTTP de /decision/submit y el correo del outbox,
// así el titular ve en pantalla la misma referencia que recibe por correo. No es reversible a la decisión sin conocer el consentId.
import { createHash } from "node:crypto";

export function receiptRefFor(consentId: string): string {
  return `rcp-${createHash("sha256").update(consentId, "utf8").digest("hex").slice(0, 24)}`;
}
