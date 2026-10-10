// Gobierna: SEC-CNS-021 PR-4 (CA-146 / DF-10), otp-challenge.spec.yaml (budget: CFG-OT-BUDGET), SEC-CNS-006 rev. 5 (P-04, P-04a/b/c, P-05, P-08),
// INV-21-13 (P-05: una clase no toca la otra), INV-21-15 (cero correo/nombre/RUT en la clave; subclave HKDF propia).
// Claves del presupuesto de fallos de OTP. key_hmac = HMAC-SHA256(HKDF(K_otp_env, info = "lampone-cns/otp-budget-key/v1"),
//   tenant_id || 0x00 || key_kind || 0x00 || valor). Valor: CHANNEL = channelRef real (el correo nunca se guarda: solo su HMAC), INVITATION =
// invitationRef, CHAIN = chainRef. La subclave es DISTINTA de la de channelRef (otp-challenge.ts) y de la de hashCode: una colision de uso entre
// HMAC no puede revelar el canal ni el codigo (X6 P2-5).
// Claves por clase (P-05): DECISION {CHANNEL, INVITATION} en DAY_1; RIGHTS {CHANNEL, CHAIN} en DAY_1. La ventana DAYS_30 de RIGHTS (P-07, V6c) queda
// DIFERIDA (D6, Carlos 2026-10-08; approved-parameters.ts P07_RIGHTS_DAYS_30_CAP_ENFORCED = false): ninguna clave de aqui la usa.
// ORDEN FIJO de las claves (CHANNEL primero, luego INVITATION|CHAIN): es parte del orden global de locks (cabecera de otp-challenge.ts, F-4).

import { createHmac, hkdfSync } from "node:crypto";

import { P07_RIGHTS_DAYS_30_CAP_ENFORCED } from "../common/approved-parameters.ts";
import type { TenantId } from "../common/types.ts";
import type { OtpBudgetKey, OtpBudgetKeyKind, OtpBudgetScopeClass } from "../../ports/otp-budget.port.ts";
import type { OtpScope } from "../../ports/otp-verification-repository.port.ts";

const OTP_BUDGET_KEY_HKDF_INFO = "lampone-cns/otp-budget-key/v1";

/** Version de K_otp_env que firma las claves (P-08: la rotacion sube este valor). */
export const OTP_BUDGET_KEY_VERSION = 1;

export function deriveOtpBudgetKey(secret: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), OTP_BUDGET_KEY_HKDF_INFO, 32));
}

export function otpBudgetKeyHmac(secret: Buffer, tenantId: TenantId, keyKind: OtpBudgetKeyKind, value: string): string {
  return createHmac("sha256", deriveOtpBudgetKey(secret)).update(`${tenantId}\u0000${keyKind}\u0000${value}`).digest("hex");
}

export function scopeClassOf(scope: OtpScope): OtpBudgetScopeClass {
  return scope === "DECISION" ? "DECISION" : "RIGHTS";
}

/** Claves de presupuesto aplicables a un challenge (P-04a/b/c, P-05), en el orden fijo CHANNEL -> INVITATION|CHAIN. */
export function otpBudgetKeys(secret: Buffer, tenantId: TenantId, scope: OtpScope, parentRef: string, channelRef: string): readonly OtpBudgetKey[] {
  const scopeClass = scopeClassOf(scope);
  const secondary: OtpBudgetKeyKind = scopeClass === "DECISION" ? "INVITATION" : "CHAIN";
  const make = (keyKind: OtpBudgetKeyKind, value: string): OtpBudgetKey => ({
    scopeClass,
    keyKind,
    keyHmac: otpBudgetKeyHmac(secret, tenantId, keyKind, value),
    keyVersion: OTP_BUDGET_KEY_VERSION,
    windowKind: "DAY_1",
  });
  const keys = [make("CHANNEL", channelRef), make(secondary, parentRef)];
  if (P07_RIGHTS_DAYS_30_CAP_ENFORCED) {
    // D6: deliberadamente inalcanzable hasta la historia de rotacion del management token (V6c, ADR-006 §6.1). Activarlo exige DEC + codigo nuevo.
    throw new Error("P-07 DAYS_30 no esta implementado (D6): V6c requiere la rotacion del management token");
  }
  return keys;
}
