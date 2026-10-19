// Gobierna: plan v2 H1-04 + SEC-CNS-024 F-SB-01. Primitivas de secretos de corta vida del lado Node: token de invitación (a la base solo llega su hash) y
// seudónimo del canal verificado. El código OTP YA NO se genera ni se hashea aquí: lo genera issue_otp y lo verifica verify_otp dentro de la base
// (sin CNS_OTP_SECRET ni HMAC). generateOtpCode queda solo para el adaptador en memoria de los tests.

import { createHash, createHmac, hkdfSync, randomBytes, randomInt } from "node:crypto";

import { APPROVED_P01_OTP_CODE_LENGTH } from "../otp/approved-parameters.ts";

export function generateOtpCode(length: number = APPROVED_P01_OTP_CODE_LENGTH): string {
  let code = "";
  for (let i = 0; i < length; i += 1) code += String(randomInt(0, 10));
  return code;
}

export function generateInvitationToken(): { readonly token: string; readonly tokenHash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, tokenHash: hashInvitationToken(token) };
}

/** SHA-256 hex del token (la columna token_hash exige 64 hex). */
export function hashInvitationToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** Seudónimo del canal verificado (decision_maker_ref): HKDF de `secret` (CNS_SESSION_SECRET) + HMAC del canal normalizado. No es PII reversible sin la clave. */
export function deriveDecisionMakerRef(secret: Buffer, channel: string): string {
  const key = Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), "consent-beta/decision-maker-ref/v1", 32));
  return `dm-${createHmac("sha256", key).update(channel.trim().toLowerCase()).digest("hex").slice(0, 32)}`;
}
