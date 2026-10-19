// Gobierna: plan v2 H1-04. Generación y hash de secretos de corta vida. A la base solo llegan hashes; el código y el token en claro
// los devuelve el adaptador al llamador (para el correo) y nunca se persisten ni se loguean.
// origen (ideas): src/server/modules/otp-challenge/otp-challenge.ts:121-130@9345b78 (HMAC-SHA256 con CNS_OTP_SECRET, código por randomInt).
// Desviación: el origen liga el HMAC a `verificationRef`; aquí la base genera esa ref dentro de issue_otp (el HMAC se entrega antes), así que el
// HMAC se liga a (scope, parentRef): un código no sirve en otro padre ni en otro scope.

import { createHash, createHmac, hkdfSync, randomBytes, randomInt } from "node:crypto";

import { APPROVED_P01_OTP_CODE_LENGTH } from "../otp/approved-parameters.ts";
import type { OtpScope } from "./types.ts";

export function generateOtpCode(length: number = APPROVED_P01_OTP_CODE_LENGTH): string {
  let code = "";
  for (let i = 0; i < length; i += 1) code += String(randomInt(0, 10));
  return code;
}

/** HMAC-SHA256 hex (64 chars) del código; la clave nunca entra a la base. */
export function computeOtpHmac(secret: Buffer, parentRef: string, scope: OtpScope, code: string): string {
  return createHmac("sha256", secret).update(`${scope}\u0000${parentRef}\u0000${code}`).digest("hex");
}

export function generateInvitationToken(): { readonly token: string; readonly tokenHash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, tokenHash: hashInvitationToken(token) };
}

/** SHA-256 hex del token (la columna token_hash exige 64 hex). */
export function hashInvitationToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** Seudónimo del canal verificado (decision_maker_ref): HKDF de CNS_OTP_SECRET + HMAC del canal normalizado. No es PII reversible sin la clave. */
export function deriveDecisionMakerRef(secret: Buffer, channel: string): string {
  const key = Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), "consent-beta/decision-maker-ref/v1", 32));
  return `dm-${createHmac("sha256", key).update(channel.trim().toLowerCase()).digest("hex").slice(0, 32)}`;
}
