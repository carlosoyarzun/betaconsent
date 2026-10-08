// Gobierna: INV-CM-09 / OPEN-CM-10, revision lampone-security P2-6 (C3). Decodificador unico de secretos
// de entorno: base64 estricto (ida y vuelta, sin caracteres ajenos) y al menos 32 bytes. Los mensajes de error
// nombran la variable, nunca el valor.

export const SECRET_MIN_BYTES = 32;

export function decodeStrictSecret(raw: string, name: string): Buffer {
  const secret = Buffer.from(raw, "base64");
  const norm = (x: string): string => x.trim().replace(/=+$/, "");
  if (norm(secret.toString("base64")) !== norm(raw) || secret.length < SECRET_MIN_BYTES) {
    throw new Error(`${name} debe ser base64 valido de al menos ${SECRET_MIN_BYTES} bytes. Abortando (fail-closed).`);
  }
  return secret;
}
