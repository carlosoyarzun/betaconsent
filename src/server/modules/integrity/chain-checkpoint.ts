// Gobierna: ADR-010 rev. 6 §3 (fila PR-7: checkpoints y cabeza por tenant persistidos por el chain-verifier; el calculo de la raiz Merkle pasa al chain-verifier, sin firma), F-PR6E-05 (deteccion de truncamiento de cola),
// F-PR6E-06, D-1 (b); plan PR-7 v3 (PR-7b, T-6, T-16); C-10 (Carlos, 2026-10-17). specs/db-roles.spec.yaml (integrity_chain_verifier).
//
// Logica PURA (sin E/S, sin Postgres): (1) raiz Merkle estilo RFC 6962 sobre las cabezas por tenant; (2) comparacion de las cabezas observadas con las previas (checkpoint de la base y copia local) para detectar
// truncamiento o reescritura de la cola, un tenant desaparecido y una copia local en desacuerdo con la base. Estas anomalias son exit 2 del chain-verifier. NO firma ni publica nada (C-7 pendiente: F-R6-1).
// Cero PII: solo ids opacos de tenant (uuid), enteros y hashes SHA-256 que nunca se imprimen en el log del proceso.

import { createHash } from "node:crypto";

/** Formato de la raiz guardado en integrity.chain_run.merkle_format. Cambiar el algoritmo o la codificacion de las hojas exige un valor nuevo. */
export const MERKLE_FORMAT = "RFC6962-SHA256-V1";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;

/** Cabeza de la cadena de un tenant: ultimo eslabon verificado. */
export interface ChainHead {
  readonly tenantId: string;
  readonly chainSeq: number;
  readonly eventHash: string;
}

export type ChainAnomalyKind = "TAIL_TRUNCATED_OR_REWRITTEN" | "TENANT_MISSING" | "CHECKPOINT_STATE_MISMATCH";

/** Anomalia de cola/estado. `tenantId` null = global (p. ej. copia local ilegible o ausente). Enum cerrado: nunca texto libre. */
export interface ChainAnomaly {
  readonly kind: ChainAnomalyKind;
  readonly tenantId: string | null;
}

export class MalformedHeadError extends Error {
  constructor() {
    super("cabeza de cadena malformada (tenant uuid, chainSeq entero >= 1, eventHash SHA-256 hex minuscula)");
    this.name = "MalformedHeadError";
  }
}

function assertHead(head: ChainHead): void {
  if (!UUID.test(head.tenantId) || !Number.isSafeInteger(head.chainSeq) || head.chainSeq < 1 || !HEX64.test(head.eventHash)) throw new MalformedHeadError();
}

const sha256 = (...parts: Uint8Array[]): Buffer => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};

/** Hoja: SHA-256(0x00 || utf8("<tenantId>:<chainSeq>:<eventHash>")). Prefijo 0x00 de hoja (RFC 6962 §2.1). */
export function leafHash(head: ChainHead): Buffer {
  assertHead(head);
  return sha256(Buffer.from([0x00]), Buffer.from(`${head.tenantId}:${head.chainSeq}:${head.eventHash}`, "utf8"));
}

const nodeHash = (left: Buffer, right: Buffer): Buffer => sha256(Buffer.from([0x01]), left, right);

/** MTH de RFC 6962 §2.1: n = 1 -> la hoja; si no, k = mayor potencia de 2 estrictamente menor que n; H(0x01 || MTH(izq) || MTH(der)). */
function mth(leaves: readonly Buffer[]): Buffer {
  if (leaves.length === 1) return leaves[0]!;
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return nodeHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

export interface MerkleResult {
  readonly root: string;
  readonly leafCount: number;
  readonly format: typeof MERKLE_FORMAT;
}

/**
 * Raiz Merkle sobre las cabezas (una hoja por tenant), ordenadas por tenantId (uuid minuscula, orden de bytes): estable ante el orden de entrada. Un tenant repetido es error.
 * Arbol vacio = SHA-256 de la cadena vacia (RFC 6962 §2.1).
 */
export function merkleRoot(heads: readonly ChainHead[]): MerkleResult {
  const sorted = [...heads].sort((a, b) => (a.tenantId < b.tenantId ? -1 : a.tenantId > b.tenantId ? 1 : 0));
  for (let i = 1; i < sorted.length; i++) if (sorted[i]!.tenantId === sorted[i - 1]!.tenantId) throw new MalformedHeadError();
  const leaves = sorted.map(leafHash);
  const root = leaves.length === 0 ? sha256() : mth(leaves);
  return { root: root.toString("hex"), leafCount: leaves.length, format: MERKLE_FORMAT };
}

/** Un testigo (checkpoint de la base o copia local) se sostiene si el ledger tiene ESE hash en ESA secuencia. `hashAtSeq` null = no existe la secuencia. */
export function witnessHolds(witness: { readonly chainSeq: number; readonly eventHash: string }, headSeq: number, hashAtSeq: string | null): boolean {
  return headSeq >= witness.chainSeq && hashAtSeq === witness.eventHash;
}

/** Cabeza ya observada (sin tenant: se asocia por la clave del mapa). */
export interface HeadRef {
  readonly chainSeq: number;
  readonly eventHash: string;
}

/** Estado de la copia local de cabezas (StateDirectory del uid del chain-verifier). */
export type LocalHeadState =
  | { readonly status: "ABSENT" }
  | { readonly status: "UNTRUSTED" }
  | { readonly status: "PRESENT"; readonly heads: ReadonlyMap<string, HeadRef> };

/**
 * Compara la copia local con los ultimos checkpoints de la base. La copia se escribe DESPUES del commit de la base, asi que la base puede ir por delante (caida entre ambos) pero nunca por detras:
 * un tenant de la copia sin checkpoint en la base, con secuencia menor, o con la misma secuencia y otro hash = alguien reescribio o borro checkpoints (CHECKPOINT_STATE_MISMATCH).
 * Copia ilegible/insegura = global. Copia ausente con checkpoints en la base: fuera de LOCAL es global (se perdio o la borraron: reiniciarla es decision humana); en LOCAL se resiembra.
 */
export function compareLocalHeads(local: LocalHeadState, db: ReadonlyMap<string, HeadRef>, environment: string): ChainAnomaly[] {
  if (local.status === "UNTRUSTED") return [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: null }];
  if (local.status === "ABSENT") return db.size > 0 && environment !== "LOCAL" ? [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: null }] : [];
  const out: ChainAnomaly[] = [];
  for (const [tenantId, lh] of [...local.heads].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const dh = db.get(tenantId);
    if (dh === undefined || dh.chainSeq < lh.chainSeq || (dh.chainSeq === lh.chainSeq && dh.eventHash !== lh.eventHash)) out.push({ kind: "CHECKPOINT_STATE_MISMATCH", tenantId });
  }
  return out;
}

/** Une las anomalias eliminando duplicados exactos (mismo tipo y tenant) y las ordena de forma estable. */
export function uniqueAnomalies(anomalies: readonly ChainAnomaly[]): ChainAnomaly[] {
  const seen = new Set<string>();
  const out: ChainAnomaly[] = [];
  for (const a of anomalies) {
    const key = `${a.kind}|${a.tenantId ?? "-"}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(a);
    }
  }
  return out.sort((a, b) => (`${a.kind}|${a.tenantId ?? ""}` < `${b.kind}|${b.tenantId ?? ""}` ? -1 : 1));
}
