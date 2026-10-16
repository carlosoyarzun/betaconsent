// Gobierna: ADR-010 rev. 5 (enmienda rev. c) §4.2.a punto 4 (G-3: reintentos acotados de la tx completa ante errores TRANSITORIOS: 40001, 40P01, 55P03; commit ambiguo = conexion perdida despues del COMMIT);
// src/server/modules/revocation/apply-guard.ts. ADR-001 §11: la clasificacion por SQLSTATE vive en infraestructura; el dominio solo recibe el predicado.

import { LedgerSequenceConflictError } from "../../../server/ports/ledger.port.ts";

const TRANSIENT_SQLSTATES: ReadonlySet<string> = new Set(["40001", "40P01", "55P03", "57P01", "57P02", "57P03"]);
const CONNECTION_MESSAGE = /connection terminated|connection.*(closed|reset|lost)|ECONNRESET|EPIPE|timeout exceeded when trying to connect/i;

/** true = transitorio o de commit ambiguo (se lee el estado antes de reintentar). Un guard de dominio, un rechazo de privilegio o un error de programa NO lo son. */
export function isTransientTxError(error: unknown): boolean {
  if (error instanceof LedgerSequenceConflictError) return true;
  const e = error as { code?: unknown; message?: unknown } | null;
  const code = typeof e?.code === "string" ? e.code : undefined;
  if (code !== undefined) return TRANSIENT_SQLSTATES.has(code) || code.startsWith("08") || code === "ECONNRESET" || code === "EPIPE";
  return error instanceof Error && CONNECTION_MESSAGE.test(error.message);
}

const UNAVAILABLE_NODE_CODES: ReadonlySet<string> = new Set(["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EPIPE"]);

/**
 * ADR-010 PR-7a (F-PR7-10, T-10): la base NO esta disponible para atender (indisponibilidad transitoria, sin relacion con la existencia del recurso): SQLSTATE de clase 08 (conexion), 40 (rollback/serializacion/
 * deadlock), 53 (recursos), 57 (apagado/cancelacion) o 55P03 (lock no disponible), errores de socket o conexion perdida/pool agotado. Nunca un guard de dominio (RVxxx/RCxxx), un rechazo de privilegio (42501)
 * ni un error de programa/datos: esos NO son indisponibilidad y siguen el camino uniforme previo (404). La respuesta 503 es la misma para cualquier recurso (ni existe ni se distingue): sin oraculo.
 */
export function isServiceUnavailableError(error: unknown): boolean {
  const e = error as { code?: unknown; message?: unknown } | null;
  const code = typeof e?.code === "string" ? e.code : undefined;
  if (code !== undefined) return code.startsWith("08") || code.startsWith("40") || code.startsWith("53") || code.startsWith("57") || code === "55P03" || UNAVAILABLE_NODE_CODES.has(code);
  return error instanceof Error && CONNECTION_MESSAGE.test(error.message);
}

/** Maximo de intentos internos (incluye el primero) ante un error de tx revertida antes de responder 503 uniforme (condicion de seguridad de PR-7a). */
export const MAX_ROLLED_BACK_ATTEMPTS = 3;

/**
 * SQLSTATE de clase 40 (serializacion/deadlock) y 55P03 (lock no disponible): la tx se revirtio entera, no hay commit ambiguo y reintentarla es seguro. Pueden correlacionar con la existencia o actividad del
 * recurso (otra tx lo toca), por eso NO se traducen de inmediato en una respuesta distinta: se reintenta con tope y solo entonces el borde responde el 503 uniforme.
 */
export function isRolledBackRetryable(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && (code.startsWith("40") || code === "55P03");
}

export interface RetryRolledBackOptions {
  readonly maxAttempts?: number;
  /** Espera entre intentos (inyectable en tests); por defecto setTimeout. */
  readonly sleep?: (ms: number) => Promise<void>;
  /** Aleatoriedad del jitter en [0, 1) (inyectable en tests). */
  readonly random?: () => number;
  /** Base de la espera exponencial en ms. */
  readonly baseDelayMs?: number;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Ejecuta UNA tx completa (`attempt` abre, ejecuta y confirma o revierte) con reintentos acotados solo ante errores de tx revertida. Entre intentos espera base * 2^(n-1) * (0.5 + random) ms (backoff exponencial
 * con jitter: evita reintentos sincronizados contra el mismo lock). Cualquier otro error, o agotar el tope, se relanza tal cual.
 */
export async function retryRolledBack<T>(attempt: () => Promise<T>, options: RetryRolledBackOptions = {}): Promise<T> {
  const maxAttempts = options.maxAttempts ?? MAX_ROLLED_BACK_ATTEMPTS;
  const sleep = options.sleep ?? defaultSleep;
  const random = options.random ?? Math.random;
  const base = options.baseDelayMs ?? 25;
  for (let n = 1; ; n++) {
    try {
      return await attempt();
    } catch (error) {
      if (n >= maxAttempts || !isRolledBackRetryable(error)) throw error;
      await sleep(Math.round(base * 2 ** (n - 1) * (0.5 + random())));
    }
  }
}
