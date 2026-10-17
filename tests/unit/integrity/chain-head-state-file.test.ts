// Gobierna: ADR-010 rev. 6 §3 (fila PR-7: persistencia de cabezas por tenant), F-PR6E-05, plan PR-7 v3 (PR-7b, T-16: copia local 0600 en el StateDirectory del uid del chain-verifier).
// TEST-CNS-1772: lectura fail-closed (symlink, tipo, permisos, forma, entorno) y escritura atomica 0600 de la copia local de cabezas. Solo fs en un directorio temporal. SYNTHETIC ONLY.

import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { ChainHeadStateFile, HEAD_STATE_FILE } from "../../../src/infra/adapters/chain-state/chain-head-state-file.ts";
import type { HeadRef } from "../../../src/server/modules/integrity/chain-checkpoint.ts";

const T1 = "00000000-0000-4000-8000-000000000001";
const T2 = "00000000-0000-4000-8000-000000000002";
const H = (c: string): string => c.repeat(64);

async function fresh(): Promise<{ dir: string; file: ChainHeadStateFile; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), "cns-heads-"));
  await chmod(dir, 0o700);
  return { dir, file: new ChainHeadStateFile(dir, "STAGING"), cleanup: () => rm(dir, { recursive: true, force: true }) };
}

test("TEST-CNS-1772 la copia local: ausente = ABSENT; escribe 0600 atomico y se relee identica (orden estable, sin archivos temporales residuales)", async () => {
  const { dir, file, cleanup } = await fresh();
  try {
    assert.deepEqual(await file.read(), { status: "ABSENT" });
    const heads = new Map<string, HeadRef>([[T2, { chainSeq: 7, eventHash: H("b") }], [T1, { chainSeq: 3, eventHash: H("a") }]]);
    await file.write(heads);
    const st = await lstat(join(dir, HEAD_STATE_FILE));
    assert.equal(st.mode & 0o777, 0o600, "0600");
    const back = await file.read();
    assert.equal(back.status, "PRESENT");
    assert.deepEqual([...(back.status === "PRESENT" ? back.heads : [])], [[T1, { chainSeq: 3, eventHash: H("a") }], [T2, { chainSeq: 7, eventHash: H("b") }]]);
    assert.equal(JSON.parse(await readFile(join(dir, HEAD_STATE_FILE), "utf8")).environment, "STAGING");
    // Reemplazo: sigue 0600 y sin temporales.
    await file.write(new Map([[T1, { chainSeq: 4, eventHash: H("c") }]]));
    assert.deepEqual(await readdir(dir), [HEAD_STATE_FILE]);
    assert.equal((await lstat(join(dir, HEAD_STATE_FILE))).mode & 0o777, 0o600);
  } finally {
    await cleanup();
  }
});

test("TEST-CNS-1772 la copia local: permisos laxos, symlink, directorio que no es directorio, JSON o forma invalida, campos extra y entorno distinto = UNTRUSTED (nunca se confia)", async () => {
  const { dir, file, cleanup } = await fresh();
  const path = join(dir, HEAD_STATE_FILE);
  const good = { version: 1, environment: "STAGING", heads: { [T1]: { chainSeq: 3, eventHash: H("a") } } };
  const put = async (doc: unknown, mode = 0o600): Promise<void> => {
    await rm(path, { force: true });
    await writeFile(path, typeof doc === "string" ? doc : JSON.stringify(doc), { mode });
    await chmod(path, mode);
  };
  try {
    await put(good);
    assert.equal((await file.read()).status, "PRESENT", "base valida");
    await put(good, 0o644);
    assert.equal((await file.read()).status, "UNTRUSTED", "lectura para otros");
    await put(good, 0o640);
    assert.equal((await file.read()).status, "UNTRUSTED", "lectura para el grupo");
    for (const bad of [
      "no es json",
      "[]",
      "null",
      { ...good, version: 2 },
      { ...good, environment: "PRODUCTION" },
      { ...good, extra: true },
      { version: 1, environment: "STAGING" },
      { ...good, heads: [] },
      { ...good, heads: { "no-uuid": { chainSeq: 1, eventHash: H("a") } } },
      { ...good, heads: { [T1]: { chainSeq: 0, eventHash: H("a") } } },
      { ...good, heads: { [T1]: { chainSeq: 1.5, eventHash: H("a") } } },
      { ...good, heads: { [T1]: { chainSeq: "1", eventHash: H("a") } } },
      { ...good, heads: { [T1]: { chainSeq: 1, eventHash: "A".repeat(64) } } },
      { ...good, heads: { [T1]: { chainSeq: 1, eventHash: H("a"), extra: 1 } } },
    ]) {
      await put(bad);
      assert.equal((await file.read()).status, "UNTRUSTED", JSON.stringify(bad));
    }
    // Symlink al archivo valido: no se sigue.
    await put(good);
    const real = join(dir, "real.json");
    await rm(real, { force: true });
    await writeFile(real, JSON.stringify(good), { mode: 0o600 });
    await rm(path, { force: true });
    await symlink(real, path);
    assert.equal((await file.read()).status, "UNTRUSTED", "symlink");
    await rm(path, { force: true });
    // Directorio con permisos laxos, inexistente o symlink: UNTRUSTED.
    await put(good);
    await chmod(dir, 0o755);
    assert.equal((await file.read()).status, "UNTRUSTED", "directorio abierto");
    await chmod(dir, 0o700);
    assert.equal((await new ChainHeadStateFile(join(dir, "no-existe"), "STAGING").read()).status, "UNTRUSTED", "directorio inexistente");
    const link = join(dir, "lnk");
    await mkdir(join(dir, "sub"), { mode: 0o700 });
    await symlink(join(dir, "sub"), link);
    assert.equal((await new ChainHeadStateFile(link, "STAGING").read()).status, "UNTRUSTED", "directorio symlink");
    assert.equal((await new ChainHeadStateFile(dir, "LOCAL").read()).status, "UNTRUSTED", "el archivo es de otro entorno");
  } finally {
    await cleanup();
  }
});

test("TEST-CNS-1772 la copia local: una escritura fallida lanza un error sin detalles (ni ruta) y no deja temporales", async () => {
  const { dir, cleanup } = await fresh();
  try {
    const missing = new ChainHeadStateFile(join(dir, "no-existe"), "STAGING");
    await assert.rejects(
      () => missing.write(new Map([[T1, { chainSeq: 1, eventHash: H("a") }]])),
      (e: unknown) => (e as { code?: string }).code === "CHAIN_HEAD_STATE_WRITE" && !String((e as Error).message).includes(dir),
    );
    assert.deepEqual(await readdir(dir), []);
  } finally {
    await cleanup();
  }
});
