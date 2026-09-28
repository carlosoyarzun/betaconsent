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
  readonly invitationRef: string;
  /** Presente desde V1 (otp-challenge): liga la sesión al challenge activo. */
  readonly verificationRef?: string;
  /** Presente solo tras V3 (OTP verificado): nunca se acepta si viene del cliente. */
  readonly decisionMakerRef?: string;
  /** Presente desde la primera llamada de POST /decision/steps de esta sesión (C1 perezoso,
   * consent-flow.handler.ts x-scope-note): nunca se acepta si viene del cliente. */
  readonly consentId?: string;
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
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      typeof (parsed as Record<string, unknown>).tenantId === "string" &&
      typeof (parsed as Record<string, unknown>).invitationRef === "string"
    ) {
      return parsed as ConsentSessionPayload;
    }
    return null;
  } catch {
    return null;
  }
}
