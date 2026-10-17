#!/usr/bin/env node
// Gobierna: ADR-010 rev. 6 §4.5.3, decision de Carlos del 2026-10-16 (C-4: apertura de la ceremonia con verificador SCRAM calculado en el CLIENTE, sin contrasena en texto plano en open.sql), PR-7e.
//
// Calcula un verificador SCRAM-SHA-256 de PostgreSQL (RFC 5802 / RFC 7677) con node:crypto (sin dependencias). Uso:
//   VERIFIER=$(node tools/ceremony/scram-verifier.ts)        # contrasena aleatoria de 24 bytes: el verificador va a stdout y la contrasena a STDERR (una sola vez; no se escribe en disco)
// La contrasena se entrega a quien abre la sesion de ddl_breakglass por un canal fuera de banda; el verificador (hash salado) es lo unico que llega al servidor (db/ceremonies/open.sql).
// Contrasenas ASCII (SASLprep es la identidad para ASCII imprimible); el generador solo produce base64url.

import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

export const SCRAM_ITERATIONS = 4096;

/** Verificador `SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>` (formato de pg_authid.rolpassword). */
export function scramVerifier(password: string, salt: Buffer = randomBytes(16), iterations: number = SCRAM_ITERATIONS): string {
  if (!/^[\x21-\x7e]{1,128}$/.test(password)) throw new Error("la contrasena debe ser ASCII imprimible sin espacios, de 1 a 128 caracteres (el generador produce 32)");
  const salted = pbkdf2Sync(password, salt, iterations, 32, "sha256");
  const clientKey = createHmac("sha256", salted).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const serverKey = createHmac("sha256", salted).update("Server Key").digest();
  return `SCRAM-SHA-256$${iterations}:${salt.toString("base64")}$${storedKey.toString("base64")}:${serverKey.toString("base64")}`;
}

export function generateCeremonyPassword(): string {
  return randomBytes(24).toString("base64url");
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  const password = generateCeremonyPassword();
  process.stderr.write(`contrasena de la ceremonia (entreguela fuera de banda; no se vuelve a mostrar): ${password}\n`);
  process.stdout.write(`${scramVerifier(password)}\n`);
}
