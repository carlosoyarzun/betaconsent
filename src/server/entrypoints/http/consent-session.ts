// D5 (decisión técnica mínima de Carlos, 2026-09-27): ni specs/state-machines/*.spec.yaml ni
// contracts/openapi/consent-it0.openapi.yaml fijan el mecanismo concreto de sesión HTTP para
// el flujo invitación/otp/decisión (solo dicen "el actor se deriva de la sesión", SM R0.2, y
// listan cookies __Host-cns-landing/__Host-cns-manage como `x-pending: P-26`, sin firma ni
// formato). A falta de esa definición, este módulo implementa la sesión mínima que pide la
// tarea: una cookie opaca firmada con HMAC-SHA256 de node:crypto (nunca JWT de librería
// externa, cero dependencias nuevas), ligada al tenant_id y al challenge (verificationRef una
// vez existe). decisionMakerRef y tenantId SIEMPRE se leen de aquí, nunca de un campo del
// body (SM R0.2; CLAUDE.md "Límites de IA" no aplica: esto no decide identidad legal, solo
// referencia opaca ya derivada por otp-challenge V3).
//
// Reportar a Carlos: este mecanismo es un stand-in de IT0, no un ADR. Si la sesión real llega
// por un ADR/spec distinto (p.ej. P-30 rotación de ID de sesión), este archivo se reemplaza.

import { createHmac, timingSafeEqual } from "node:crypto";

export interface ConsentSessionPayload {
  readonly tenantId: string;
  /** Sesión del flujo invitación/otp/decisión (GET /i/{token}); ausente en una sesión MANAGE_ENTRY
   * (GET /m/{token}, CA-116 UX-CNS-004). */
  readonly invitationRef?: string;
  /** Presente desde V1 (otp-challenge) scope DECISION: liga la sesión al challenge activo. */
  readonly verificationRef?: string;
  /** Presente solo tras V3 scope DECISION (OTP verificado): nunca se acepta si viene del cliente. */
  readonly decisionMakerRef?: string;
  /** Presente desde la primera llamada de POST /decision/steps de esta sesión (C1 perezoso,
   * consent-flow.handler.ts x-scope-note): nunca se acepta si viene del cliente. */
  readonly consentId?: string;

  // ---------------------------------------------------------------------
  // CA-116 (revocación IT0, UX-CNS-004): sesión MANAGE_ENTRY creada por GET /m/{token}
  // (CFG-RV-MANAGEMENT-LINK). chainRef/revokedDecisionRef se fijan SIEMPRE al resolver el
  // handle (TenantHandlePort), nunca desde el cliente.
  // ---------------------------------------------------------------------
  /** chainRef resuelto del handle MANAGE_ENTRY; presente en toda sesión MANAGE. */
  readonly chainRef?: string;
  /** Decisión GRANTED vigente de la cadena al emitir el handle (R14-C). */
  readonly revokedDecisionRef?: string;
  /** verificationRef del OTP scope MANAGE activo (V1 MANAGE), antes de V3. */
  readonly manageVerificationRef?: string;
  /** Presente solo tras V3 scope MANAGE (identidad MANAGE verificada): nunca del cliente. */
  readonly manageDecisionMakerRef?: string;
  /** revocationRef de la Revocation abierta por R1 en esta sesión MANAGE. */
  readonly revocationRef?: string;
  /** verificationRef del OTP scope REVOCATION activo (V1 REVOCATION, posterior a R1). */
  readonly revocationVerificationRef?: string;
  /** true solo tras V3 scope REVOCATION correcto: habilita R2 (verifyRevocationOtp). */
  readonly revocationOtpVerified?: boolean;

  // ---------------------------------------------------------------------
  // CA-116 PR 2 (recovery, UX-CNS-004, SEC-CNS-014 P2-03): GET /r/{token} y POST
  // /recovery/revoke YA NO usan esta sesión: el hash del token de recuperación vive solo en la
  // cookie dedicada `__Host-cns-recovery` (recovery-handle.ts), firmada con una clave HKDF
  // propia y aislada de esta cookie de sesión (P2-02). Un `recoveryTokenHash` en el body o en
  // esta cookie de sesión nunca se acepta (P2-03): esta interfaz ya no declara ese campo a
  // propósito, para que un intento de reintroducirlo sea un error de tipos.
  // ---------------------------------------------------------------------
}

function sign(secret: Buffer, payloadJson: string): string {
  return createHmac("sha256", secret).update(payloadJson).digest("base64url");
}

/** Serializa y firma la sesión. El valor de cookie es `<base64url(json)>.<hmac>`. */
export function encodeSession(secret: Buffer, payload: ConsentSessionPayload): string {
  const json = JSON.stringify(payload);
  const body = Buffer.from(json, "utf8").toString("base64url");
  return `${body}.${sign(secret, body)}`;
}

/**
 * Verifica y decodifica la sesión. Cualquier fallo (formato, firma, JSON) devuelve `null`;
 * el llamador SIEMPRE trata eso como sesión inexistente (404 uniforme, GRD-CM-01), nunca como
 * un error distinguible.
 */
export function decodeSession(secret: Buffer, cookieValue: string | undefined): ConsentSessionPayload | null {
  if (!cookieValue) return null;
  const dot = cookieValue.indexOf(".");
  if (dot === -1) return null;
  const body = cookieValue.slice(0, dot);
  const mac = cookieValue.slice(dot + 1);
  const expectedMac = sign(secret, body);
  const macBuf = Buffer.from(mac, "utf8");
  const expectedBuf = Buffer.from(expectedMac, "utf8");
  if (macBuf.length !== expectedBuf.length || !timingSafeEqual(macBuf, expectedBuf)) {
    return null;
  }
  try {
    const json = Buffer.from(body, "base64url").toString("utf8");
    const parsed = JSON.parse(json) as unknown;
    // CA-116: invitationRef ya no es obligatorio (una sesión MANAGE_ENTRY de GET /m/{token}
    // nunca lo tiene); tenantId sigue siendo la única clave de aislamiento obligatoria
    // (DEC-BR-015 §1).
    if (typeof parsed === "object" && parsed !== null && typeof (parsed as Record<string, unknown>).tenantId === "string") {
      return parsed as ConsentSessionPayload;
    }
    return null;
  } catch {
    return null;
  }
}
