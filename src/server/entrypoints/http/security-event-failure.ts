// Gobierna: CA-141 (D-3: logout fail-closed; P1-2: el fallo de escritura del evento se mapea EXPLICITAMENTE a 503), specs/session.spec.yaml
// GRD-SE-14 / ERR-SE-04, common.spec.yaml ERR-CM-12 (GUARD_EVALUATOR_UNAVAILABLE).
// Si no se puede escribir el evento de seguridad, el login no deja sesion ni Set-Cookie y el logout no revoca ni borra cookies: 503 sin
// Set-Cookie. Sin esto el fallo caeria al catch global (500 con correlationId, sin semantica de reintento).

import { randomUUID } from "node:crypto";

import { SecurityEventWriteError } from "../../ports/security-event.port.ts";
import type { HttpResult } from "./consent-flow.handler.ts";

export function isSecurityEventWriteError(error: unknown): error is SecurityEventWriteError {
  return error instanceof SecurityEventWriteError;
}

/**
 * Contador de proceso `security_event_write_failed` SIN etiquetas de la request (sin tenant, principal, sesion ni tipo de evento): el repo no tiene
 * infraestructura de metricas, asi que sigue el patron existente de senales de fallo (`staff_session_purge_failed`, `request_failed`): una linea
 * con solo `name` y el SQLSTATE opcional, nunca el mensaje ni valores.
 */
export function reportSecurityEventWriteFailure(error: SecurityEventWriteError): void {
  const code = typeof error.code === "string" ? error.code.slice(0, 20) : undefined;
  console.error(`security_event_write_failed name=${error.name}${code !== undefined ? ` code=${code}` : ""}`);
}

/** 503 ERR-CM-12 sin Set-Cookie ni borrado de cookies (el HttpResult no lleva campos set ni clear de cookies). */
export function securityEventUnavailable(error: SecurityEventWriteError): HttpResult {
  reportSecurityEventWriteFailure(error);
  return { status: 503, body: { code: "GUARD_EVALUATOR_UNAVAILABLE", status: 503, correlationId: randomUUID() }, extraHeaders: { "Cache-Control": "no-store" } };
}
