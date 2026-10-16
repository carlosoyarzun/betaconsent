// Gobierna: ADR-010 rev. 6 §3 (fila PR-7: persistencia de cabezas por tenant), F-PR6E-05, plan PR-7 v3 (PR-7b, T-16: copia de las ultimas cabezas en el StateDirectory 0600 del uid del chain-verifier, comparada con la base);
// infra/systemd/consent-chain-verifier.service (StateDirectory=consent-chain-verifier, modo 0700).
//
// Copia LOCAL de las ultimas cabezas por tenant: un solo archivo JSON `heads.json` (modo 0600, dueno = uid del proceso) dentro del StateDirectory (0700). Un superusuario de la BASE que reescriba a la vez el ledger y
// integrity.chain_checkpoint no ve ni alcanza este archivo salvo que ademas tenga root sobre el uid del chain-verifier (ese caso lo cubre el ancla externa, PR-7f). Lectura fail-closed: symlink, tipo, permisos, dueno,
// tamano, JSON o forma invalidos, o entorno distinto = UNTRUSTED (anomalia, exit 2); ausente = ABSENT. Escritura atomica (archivo temporal 0600 + fsync + rename + fsync del directorio).
// Sin PII: uuid de tenant (colegio), enteros y hashes SHA-256. Nunca se imprime el contenido ni la ruta.
// ADAPTADOR (ADR-001 §11): el dominio no conoce el sistema de archivos.

import { randomBytes } from "node:crypto";
import { lstat, open, readFile, rename, unlink } from "node:fs/promises";
import { join } from "node:path";

import type { HeadRef, LocalHeadState } from "../../../server/modules/integrity/chain-checkpoint.ts";

export const HEAD_STATE_FILE = "heads.json";
const MAX_BYTES = 8 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ENV = /^(LOCAL|DEV|STAGING|PRODUCTION)$/;

export class ChainHeadStateWriteError extends Error {
  readonly code = "CHAIN_HEAD_STATE_WRITE";
  constructor() {
    super("no se pudo escribir la copia local de cabezas (StateDirectory)");
    this.name = "ChainHeadStateWriteError";
  }
}

function ownedByUsAndPrivate(st: { mode: number; uid: number }): boolean {
  if ((st.mode & 0o077) !== 0) return false;
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  return uid === undefined || st.uid === uid;
}

/** Valida y convierte el contenido; null si algo no cuadra (cualquier campo extra tambien es invalido). */
function parseHeads(text: string, environment: string): Map<string, HeadRef> | null {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return null;
  const o = doc as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  if (keys.length !== 3 || keys[0] !== "environment" || keys[1] !== "heads" || keys[2] !== "version") return null;
  if (o.version !== 1 || typeof o.environment !== "string" || !ENV.test(o.environment) || o.environment !== environment) return null;
  const heads = o.heads;
  if (typeof heads !== "object" || heads === null || Array.isArray(heads)) return null;
  const out = new Map<string, HeadRef>();
  for (const [tenantId, value] of Object.entries(heads)) {
    if (!UUID.test(tenantId) || typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const v = value as Record<string, unknown>;
    const vk = Object.keys(v).sort();
    if (vk.length !== 2 || vk[0] !== "chainSeq" || vk[1] !== "eventHash") return null;
    if (typeof v.chainSeq !== "number" || !Number.isSafeInteger(v.chainSeq) || v.chainSeq < 1 || typeof v.eventHash !== "string" || !HEX64.test(v.eventHash)) return null;
    out.set(tenantId, { chainSeq: v.chainSeq, eventHash: v.eventHash });
  }
  return out;
}

export class ChainHeadStateFile {
  readonly #dir: string;
  readonly #environment: string;

  constructor(dir: string, environment: string) {
    this.#dir = dir;
    this.#environment = environment;
  }

  async read(): Promise<LocalHeadState> {
    try {
      const dir = await lstat(this.#dir);
      if (!dir.isDirectory() || dir.isSymbolicLink() || !ownedByUsAndPrivate(dir)) return { status: "UNTRUSTED" };
    } catch {
      return { status: "UNTRUSTED" };
    }
    const file = join(this.#dir, HEAD_STATE_FILE);
    let st;
    try {
      st = await lstat(file);
    } catch (error) {
      return (error as { code?: string }).code === "ENOENT" ? { status: "ABSENT" } : { status: "UNTRUSTED" };
    }
    if (!st.isFile() || st.isSymbolicLink() || st.size > MAX_BYTES || !ownedByUsAndPrivate(st)) return { status: "UNTRUSTED" };
    let text: string;
    try {
      text = await readFile(file, "utf8");
    } catch {
      return { status: "UNTRUSTED" };
    }
    const heads = parseHeads(text, this.#environment);
    return heads === null ? { status: "UNTRUSTED" } : { status: "PRESENT", heads };
  }

  /** Reemplaza el archivo de forma atomica con `heads` (orden estable por tenant). Lanza ChainHeadStateWriteError ante cualquier fallo (sin detalles). */
  async write(heads: ReadonlyMap<string, HeadRef>): Promise<void> {
    const sorted = [...heads].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const body = JSON.stringify({ version: 1, environment: this.#environment, heads: Object.fromEntries(sorted.map(([t, h]) => [t, { chainSeq: h.chainSeq, eventHash: h.eventHash }])) });
    const tmp = join(this.#dir, `${HEAD_STATE_FILE}.${randomBytes(6).toString("hex")}.tmp`);
    try {
      const fh = await open(tmp, "wx", 0o600);
      try {
        await fh.writeFile(body, "utf8");
        await fh.sync();
      } finally {
        await fh.close();
      }
      await rename(tmp, join(this.#dir, HEAD_STATE_FILE));
      const dirHandle = await open(this.#dir, "r");
      try {
        await dirHandle.sync();
      } finally {
        await dirHandle.close();
      }
    } catch {
      await unlink(tmp).catch(() => undefined);
      throw new ChainHeadStateWriteError();
    }
  }
}
