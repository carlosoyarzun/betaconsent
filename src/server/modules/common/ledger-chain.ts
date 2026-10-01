// Gobierna: DEC-BR-014 rev. 8 §3 X6 ("Ledger verificado" = subconjunto IT0 de ADR-011 / S4-16:
// recomputacion de la cadena SHA-256 por tenant), common.spec.yaml ledgerEnvelope
// (payloadHash, previousEventHash, eventHash; streams.LEDGER "cadena SHA-256 por tenant en IT0";
// HMAC y ancla = ADR-011/DEC-BR-009, FUERA de este archivo).
//
// FINDING P2 (spec incompleta): ledgerEnvelope nombra los campos pero NO define la
// canonicalizacion, el orden de la cadena ni el genesis. Eleccion IT0 (a ratificar en ADR-011):
//   * orden total por tenant = `chainSeq` (1, 2, 3...), asignado por el adaptador bajo un lock por
//     tenant (pg_advisory_xact_lock / serializacion in-memory); no depende de relojes;
//   * payloadHash = SHA-256(hex) de canonicalJson(payload);
//   * eventHash   = SHA-256(hex) de canonicalJson(sobre), con sobre = { v, tenantId, chainSeq,
//     aggregateType, aggregateId, sequence, eventType, actorType, actorRole, recordedByRef,
//     cosignedByRef, idempotencyKeyHash, payloadHash, previousEventHash } (ausentes = null);
//   * genesis: previousEventHash del primer eslabon = 64 ceros;
//   * NO cubre eventId/occurredAt/environment: los fija la base DESPUES del hash (default de
//     columna sin grant para runtime, SEC N2-06). ADR-011 debe decidir si el HMAC los cubre.
// El hash se calcula en el adaptador (in-memory y Postgres identicos) con ESTE modulo.

import { createHash } from "node:crypto";

import { isLedgerEventType } from "./ledger-event-types.ts";

export const LEDGER_CHAIN_VERSION = 1;
export const LEDGER_GENESIS_HASH = "0".repeat(64);

const HEX64 = /^[0-9a-f]{64}$/;

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * JSON canonico: claves ordenadas por punto de codigo, sin espacios, solo tipos JSON. El valor se
 * normaliza antes con JSON.parse(JSON.stringify(x)) (descarta `undefined`, aplica toJSON), igual
 * que lo que Postgres guarda en jsonb. Numeros no enteros o no seguros se rechazan: jsonb los
 * renormaliza y el hash dejaria de ser reproducible entre adaptadores (la lista blanca de payload
 * solo usa enums, refs y enteros).
 */
export function canonicalJson(value: unknown): string {
  const normalized: unknown = JSON.parse(JSON.stringify(value === undefined ? null : value));
  return serialize(normalized);
}

function serialize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isSafeInteger(value)) throw new TypeError("canonicalJson: solo enteros seguros (ledger-chain)");
      return String(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${serialize(obj[k])}`).join(",")}}`;
    }
    default:
      throw new TypeError("canonicalJson: tipo no JSON");
  }
}

export function computePayloadHash(payload: unknown): string {
  return sha256Hex(canonicalJson(payload));
}

/** Campos del eslabon que entran al eventHash (ver cabecera). */
export interface ChainLinkFields {
  readonly tenantId: string;
  readonly chainSeq: number;
  readonly aggregateType: string;
  readonly aggregateId: string;
  readonly sequence: number;
  readonly eventType: string;
  readonly actorType: string;
  readonly actorRole: string | null;
  readonly recordedByRef: string | null;
  readonly cosignedByRef: string | null;
  readonly idempotencyKeyHash: string | null;
  readonly payloadHash: string;
  readonly previousEventHash: string;
}

export function computeEventHash(link: ChainLinkFields): string {
  return sha256Hex(
    canonicalJson({
      v: LEDGER_CHAIN_VERSION,
      tenantId: link.tenantId,
      chainSeq: link.chainSeq,
      aggregateType: link.aggregateType,
      aggregateId: link.aggregateId,
      sequence: link.sequence,
      eventType: link.eventType,
      actorType: link.actorType,
      actorRole: link.actorRole,
      recordedByRef: link.recordedByRef,
      cosignedByRef: link.cosignedByRef,
      idempotencyKeyHash: link.idempotencyKeyHash,
      payloadHash: link.payloadHash,
      previousEventHash: link.previousEventHash,
    }),
  );
}

/** Eslabon leido (por `LedgerPort.readChain`) con lo necesario para recomputar. */
export interface ChainRow extends ChainLinkFields {
  readonly payload: Readonly<Record<string, unknown>>;
  readonly eventHash: string;
}

export type ChainBreakReason =
  | "CHAIN_SEQ_GAP" // chainSeq no es el esperado (fila borrada, insertada o reordenada)
  | "PREVIOUS_HASH_MISMATCH" // previousEventHash != eventHash del eslabon anterior (o genesis)
  | "PAYLOAD_HASH_MISMATCH" // payload mutado
  | "EVENT_HASH_MISMATCH" // algun campo del sobre mutado
  | "MALFORMED_HASH" // hash que no es sha256 hex
  | "EVENT_TYPE_NOT_ALLOWED"; // fuera de la lista blanca (CHECK de BD saltado)

export type LedgerChainReport =
  | { readonly ok: true; readonly verified: number }
  | {
      readonly ok: false;
      readonly verified: number; // eslabones correctos antes del primero roto
      readonly brokenAt: { readonly chainSeq: number; readonly aggregateId: string; readonly sequence: number; readonly reason: ChainBreakReason };
    };

/** Funcion pura: recomputa la cadena de UN tenant (filas ya ordenadas por chainSeq) y reporta el primer eslabon roto. */
export function verifyChainRows(rows: readonly ChainRow[]): LedgerChainReport {
  let previous = LEDGER_GENESIS_HASH;
  let expectedSeq = 1;
  let verified = 0;
  for (const row of rows) {
    const fail = (reason: ChainBreakReason): LedgerChainReport => ({
      ok: false,
      verified,
      brokenAt: { chainSeq: row.chainSeq, aggregateId: row.aggregateId, sequence: row.sequence, reason },
    });
    if (row.chainSeq !== expectedSeq) return fail("CHAIN_SEQ_GAP");
    if (!HEX64.test(row.payloadHash) || !HEX64.test(row.previousEventHash) || !HEX64.test(row.eventHash)) return fail("MALFORMED_HASH");
    if (row.previousEventHash !== previous) return fail("PREVIOUS_HASH_MISMATCH");
    if (computePayloadHash(row.payload) !== row.payloadHash) return fail("PAYLOAD_HASH_MISMATCH");
    if (computeEventHash(row) !== row.eventHash) return fail("EVENT_HASH_MISMATCH");
    if (!isLedgerEventType(row.eventType)) return fail("EVENT_TYPE_NOT_ALLOWED");
    previous = row.eventHash;
    expectedSeq += 1;
    verified += 1;
  }
  return { ok: true, verified };
}

/** Lectura minima que necesita el verificador (la implementa LedgerPort). */
export interface ChainReader {
  readChain(tenantId: string): Promise<readonly ChainRow[]>;
}

/**
 * X6: recomputa la cadena SHA-256 del tenant y reporta el primer eslabon roto. Limitaciones
 * conocidas (ADR-011/DEC-BR-009, fuera de IT0): sin ancla externa no detecta el truncamiento de
 * la COLA de la cadena; sin HMAC un actor que reescriba toda la cadena desde el punto de
 * mutacion produce una cadena valida. Filas previas a 0013 (chain_seq NULL) no pertenecen a la cadena.
 */
export async function verifyLedgerChain(reader: ChainReader, tenantId: string): Promise<LedgerChainReport> {
  return verifyChainRows(await reader.readChain(tenantId));
}
