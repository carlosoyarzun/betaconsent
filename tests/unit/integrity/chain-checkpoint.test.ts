// Gobierna: ADR-010 rev. 6 §3 (fila PR-7: checkpoints y cabeza por tenant; el calculo de la raiz Merkle pasa al chain-verifier, sin firma), F-PR6E-05, plan PR-7 v3 (PR-7b, T-6, T-16); C-10 (Carlos, 2026-10-17); C-7 pendiente (sin firma).
// TEST-CNS-1770 (raiz Merkle: vectores dorados calculados con una implementacion independiente en Python, estable ante el orden, formato fijo), TEST-CNS-1771 (testigos de cola, copia local frente a la base, anomalias sin duplicados).
// Sin Postgres. SYNTHETIC ONLY.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { compareLocalHeads, leafHash, MalformedHeadError, MERKLE_FORMAT, merkleRoot, uniqueAnomalies, witnessHolds } from "../../../src/server/modules/integrity/chain-checkpoint.ts";
import type { ChainHead, HeadRef, LocalHeadState } from "../../../src/server/modules/integrity/chain-checkpoint.ts";

const T = (i: number): string => `00000000-0000-4000-8000-00000000000${i}`;
const H = (c: string): string => c.repeat(64);
const heads: ChainHead[] = Array.from({ length: 7 }, (_, i) => ({ tenantId: T(i + 1), chainSeq: i + 1, eventHash: H("abcdef0"[i]!) }));

// Vectores dorados: scratchpad merkle_ref.py (hashlib, RFC 6962 §2.1, hoja = sha256(0x00 || "tenant:seq:hash"), nodo = sha256(0x01 || izq || der)).
const GOLDEN: Record<number, string> = {
  1: "bad7b1873eed619d90efc4cc2d9bd658f506dc67fc1259c061084395c701092f",
  2: "64a87113215d5cca4134ba6cd93e2f4b15de2b46487df3ada8aab122987ecee8",
  3: "8670a0e25e7e883521485bbee1ef273e9aa1e81c1581109b4dc2e139e331a620",
  5: "128bcd5c6d1156ed6c749fa3ca193b868331c7153b8002a766a7acaf0f067684",
  7: "d90afd346a8b737dd50c4708187ad7070e69b7731a8c27d053be7594839981c4",
};

test("TEST-CNS-1770 raiz Merkle: vectores dorados (n = 1, 2, 3, 5, 7), arbol vacio = SHA-256 de la cadena vacia, formato fijo", () => {
  for (const [n, root] of Object.entries(GOLDEN)) {
    const r = merkleRoot(heads.slice(0, Number(n)));
    assert.equal(r.root, root, `n=${n}`);
    assert.equal(r.leafCount, Number(n));
    assert.equal(r.format, MERKLE_FORMAT);
  }
  assert.equal(MERKLE_FORMAT, "RFC6962-SHA256-V1");
  assert.equal(merkleRoot([]).root, createHash("sha256").update("").digest("hex"));
  assert.equal(merkleRoot([]).leafCount, 0);
  // Una hoja = la raiz (RFC 6962): y lleva el prefijo 0x00 (distinto del hash del texto sin prefijo).
  assert.equal(leafHash(heads[0]!).toString("hex"), GOLDEN[1]);
  assert.notEqual(createHash("sha256").update(`${T(1)}:1:${H("a")}`).digest("hex"), GOLDEN[1]);
});

test("TEST-CNS-1770 raiz Merkle: estable ante el orden de entrada; cualquier cambio de tenant, secuencia u hoja cambia la raiz; segunda preimagen hoja/nodo imposible por prefijos", () => {
  const base = merkleRoot(heads).root;
  assert.equal(merkleRoot([...heads].reverse()).root, base);
  assert.equal(merkleRoot([heads[3]!, heads[0]!, heads[6]!, heads[1]!, heads[5]!, heads[2]!, heads[4]!]).root, base);
  const bump = (i: number, patch: Partial<ChainHead>): string => merkleRoot(heads.map((h, j) => (j === i ? { ...h, ...patch } : h))).root;
  assert.notEqual(bump(2, { chainSeq: 99 }), base, "secuencia");
  assert.notEqual(bump(2, { eventHash: H("9") }), base, "hash");
  assert.notEqual(bump(2, { tenantId: T(8) }), base, "tenant");
  assert.notEqual(merkleRoot(heads.slice(0, 6)).root, base, "una hoja menos");
  // Truncar la cola de UN tenant (la cabeza retrocede) cambia la raiz: es lo que detecta el ancla externa.
  assert.notEqual(bump(6, { chainSeq: 6, eventHash: H("f") }), base);
  // Un "nodo" no puede hacerse pasar por hoja: la raiz de 2 hojas no coincide con la hoja cuyo texto sea la concatenacion de dos hashes.
  const l1 = leafHash(heads[0]!);
  const l2 = leafHash(heads[1]!);
  const fakeLeaf = createHash("sha256").update(Buffer.from([0x00])).update(Buffer.concat([l1, l2])).digest("hex");
  assert.notEqual(fakeLeaf, GOLDEN[2]);
});

test("TEST-CNS-1770 raiz Merkle: cabezas malformadas o tenants repetidos fallan cerrado (sin eco de valores)", () => {
  const ok = heads[0]!;
  for (const bad of [
    { ...ok, tenantId: "no-uuid" },
    { ...ok, tenantId: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" },
    { ...ok, chainSeq: 0 },
    { ...ok, chainSeq: 1.5 },
    { ...ok, chainSeq: Number.MAX_SAFE_INTEGER + 2 },
    { ...ok, eventHash: "A".repeat(64) },
    { ...ok, eventHash: "a".repeat(63) },
  ]) {
    assert.throws(() => merkleRoot([bad]), (e: unknown) => e instanceof MalformedHeadError && !String(e.message).includes("no-uuid"));
  }
  assert.throws(() => merkleRoot([ok, { ...ok, chainSeq: 2 }]), MalformedHeadError, "dos hojas del mismo tenant");
});

test("TEST-CNS-1771 testigos de cola: el ledger debe tener el MISMO hash en la secuencia testigo y cabeza >= testigo (truncamiento y reescritura = falso)", () => {
  const w = { chainSeq: 5, eventHash: H("a") };
  assert.equal(witnessHolds(w, 5, H("a")), true, "misma cabeza");
  assert.equal(witnessHolds(w, 9, H("a")), true, "la cadena crecio y conserva el eslabon testigo");
  assert.equal(witnessHolds(w, 4, null), false, "cola truncada: cabeza menor que el testigo");
  assert.equal(witnessHolds(w, 5, H("b")), false, "eslabon reescrito (mismo seq, otro hash)");
  assert.equal(witnessHolds(w, 9, null), false, "la secuencia testigo ya no existe (hueco)");
  assert.equal(witnessHolds(w, 9, H("b")), false, "la historia fue reescrita bajo el testigo");
});

test("TEST-CNS-1771 copia local frente a la base: la base puede ir por delante, nunca por detras; ilegible = global; ausente solo se resiembra en LOCAL", () => {
  const present = (entries: Array<[string, HeadRef]>): LocalHeadState => ({ status: "PRESENT", heads: new Map(entries) });
  const db = new Map<string, HeadRef>([[T(1), { chainSeq: 5, eventHash: H("a") }], [T(2), { chainSeq: 3, eventHash: H("b") }]]);
  // Iguales o la base por delante (caida entre el commit y la escritura de la copia): sin anomalia.
  assert.deepEqual(compareLocalHeads(present([[T(1), { chainSeq: 5, eventHash: H("a") }], [T(2), { chainSeq: 2, eventHash: H("0") }]]), db, "STAGING"), [], "base por delante con hash anterior: lo valida el testigo contra el ledger, no esta comparacion");
  // Copia por delante de la base (checkpoints retrocedidos o borrados), mismo seq con otro hash, o tenant que la base no tiene.
  assert.deepEqual(compareLocalHeads(present([[T(1), { chainSeq: 6, eventHash: H("c") }]]), db, "STAGING"), [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: T(1) }]);
  assert.deepEqual(compareLocalHeads(present([[T(2), { chainSeq: 3, eventHash: H("9") }]]), db, "LOCAL"), [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: T(2) }]);
  assert.deepEqual(compareLocalHeads(present([[T(3), { chainSeq: 1, eventHash: H("d") }]]), db, "LOCAL"), [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: T(3) }]);
  assert.deepEqual(compareLocalHeads(present([[T(1), { chainSeq: 1, eventHash: H("d") }]]), new Map(), "LOCAL"), [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: T(1) }], "la base perdio todos sus checkpoints");
  // Estados globales.
  assert.deepEqual(compareLocalHeads({ status: "UNTRUSTED" }, db, "LOCAL"), [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: null }]);
  assert.deepEqual(compareLocalHeads({ status: "ABSENT" }, db, "STAGING"), [{ kind: "CHECKPOINT_STATE_MISMATCH", tenantId: null }], "copia perdida con checkpoints en la base fuera de LOCAL");
  assert.deepEqual(compareLocalHeads({ status: "ABSENT" }, db, "LOCAL"), [], "LOCAL resiembra");
  assert.deepEqual(compareLocalHeads({ status: "ABSENT" }, new Map(), "STAGING"), [], "primera corrida: nada que comparar");
});

test("TEST-CNS-1771 uniqueAnomalies: sin duplicados exactos y con orden estable", () => {
  const a = { kind: "TENANT_MISSING", tenantId: T(2) } as const;
  const b = { kind: "TAIL_TRUNCATED_OR_REWRITTEN", tenantId: T(1) } as const;
  const g = { kind: "CHECKPOINT_STATE_MISMATCH", tenantId: null } as const;
  assert.deepEqual(uniqueAnomalies([a, b, a, g, b]), [g, b, a]);
  assert.deepEqual(uniqueAnomalies([]), []);
});
