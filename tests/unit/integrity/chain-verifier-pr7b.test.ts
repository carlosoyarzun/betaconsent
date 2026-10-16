// Gobierna: ADR-010 rev. 6 §3 (fila PR-7: checkpoints y cabeza por tenant), F-PR6E-05, D-4 (retiro de ledger-verify-cli.ts, Carlos 2026-10-16), plan PR-7 v3 (PR-7b, T-16); C-10 (Carlos, 2026-10-16); C-7 pendiente (sin firma ni publicacion).
// TEST-CNS-1773 (configuracion de la copia local y log de anomalias sin PII ni hashes), TEST-CNS-1782 (unidad systemd con StateDirectory; el CLI retirado no existe; el chain-verifier no importa firma ni egress). Sin Postgres. SYNTHETIC ONLY.

import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { ChainVerifierConfigError, parseChainVerifierConfig } from "../../../src/server/entrypoints/chain-verifier/chain-verify-process.ts";
import type { ChainAnomaly } from "../../../src/server/modules/integrity/chain-checkpoint.ts";
import { formatChainReport, summarizeChainAudit } from "../../../src/server/modules/integrity/ledger-chain-audit.ts";
import type { TenantChainResult } from "../../../src/server/modules/integrity/ledger-chain-audit.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const T1 = "00000000-0000-4000-8000-000000000001";
const T2 = "00000000-0000-4000-8000-000000000002";
const HASH = "a".repeat(64);
const result = (tenantId: string, head: number): TenantChainResult => ({ tenantId, events: head, verified: head, head, headHash: HASH, broken: null, unchainedAfterStart: 0 });

test("TEST-CNS-1773 CNS_CHAIN_VERIFIER_STATE_DIR: ruta absoluta sin '..' ni controles; opcional en la config (se exige fuera de LOCAL al arrancar); sin eco del valor", () => {
  assert.equal(parseChainVerifierConfig({}).stateDir, undefined);
  assert.equal(parseChainVerifierConfig({ CNS_CHAIN_VERIFIER_STATE_DIR: "/var/lib/consent-chain-verifier" }).stateDir, "/var/lib/consent-chain-verifier");
  for (const bad of ["relativa/ruta", "", "./x", "/var/lib/../etc", "/var/lib/x\ny", `/${"a".repeat(250)}`]) {
    assert.throws(() => parseChainVerifierConfig({ CNS_CHAIN_VERIFIER_STATE_DIR: bad }), (e: unknown) => e instanceof ChainVerifierConfigError && !String(e.message).includes(`"${bad}"`) && !String(e.message).includes("etc"), JSON.stringify(bad));
  }
  assert.throws(() => parseChainVerifierConfig({ CNS_CHAIN_VERIFIER_STATE_DIRX: "/x" }), ChainVerifierConfigError, "un CNS_CHAIN_VERIFIER_* desconocido sigue sin ignorarse");
});

test("TEST-CNS-1773 log de anomalias: kind enum y tenant uuid; `anomalies=N` solo si hay; ni hashes ni rutas; status=bad del tenant afectado; ok=false", () => {
  const anomalies: ChainAnomaly[] = [
    { kind: "TAIL_TRUNCATED_OR_REWRITTEN", tenantId: T1 },
    { kind: "TENANT_MISSING", tenantId: T2 },
    { kind: "CHECKPOINT_STATE_MISMATCH", tenantId: null },
  ];
  const clean = formatChainReport(summarizeChainAudit([result(T1, 3), result(T2, 4)]));
  assert.equal(clean[0], "chain_verify_run ok=true tenants=2 events=7 broken=0 unchained=0", "sin anomalias el formato no cambia");
  const report = summarizeChainAudit([result(T1, 3), result(T2, 4)], anomalies);
  assert.equal(report.ok, false);
  const lines = formatChainReport(report);
  assert.equal(lines[0], "chain_verify_run ok=false tenants=2 events=7 broken=0 unchained=0 anomalies=3 kinds=CHECKPOINT_STATE_MISMATCH=1,TAIL_TRUNCATED_OR_REWRITTEN=1,TENANT_MISSING=1");
  assert.ok(lines.includes(`chain_verify_tenant tenant=${T1} head=3 events=3 verified=3 status=bad`));
  assert.ok(lines.includes(`chain_verify_tenant tenant=${T2} head=4 events=4 verified=4 status=bad`));
  assert.ok(lines.includes(`chain_verify_anomaly kind=TAIL_TRUNCATED_OR_REWRITTEN tenant=${T1}`));
  assert.ok(lines.includes("chain_verify_anomaly kind=CHECKPOINT_STATE_MISMATCH tenant=-"));
  const text = lines.join("\n");
  assert.ok(!/[0-9a-f]{64}/i.test(text), "sin hashes");
  assert.ok(!text.includes("/var/lib") && !text.includes("heads.json"), "sin rutas");
  // Un tenant con id hostil se enmascara tambien en la linea de anomalia.
  const hostile = formatChainReport(summarizeChainAudit([], [{ kind: "TENANT_MISSING", tenantId: "x\nchain_verify_run ok=true" }]));
  assert.ok(hostile.includes("chain_verify_anomaly kind=TENANT_MISSING tenant=?"));
  assert.equal(hostile.filter((l) => l.startsWith("chain_verify_run ")).length, 1, "ninguna linea de resumen forjada");
});

/** Cierre transitivo de imports relativos de un archivo .ts del repo. */
function importGraph(entry: string): string[] {
  const seen = new Set<string>();
  const visit = (file: string): void => {
    if (seen.has(file)) return;
    seen.add(file);
    for (const m of readFileSync(file, "utf8").matchAll(/(?:from\s+|import\s*\(\s*|import\s+)"(\.{1,2}\/[^"]+)"/g)) {
      const target = resolve(dirname(file), m[1]!);
      if (existsSync(target)) visit(target);
    }
  };
  visit(entry);
  return [...seen].map((f) => relative(ROOT, f)).sort();
}

test("TEST-CNS-1782 D-4: ledger-verify-cli.ts no existe en el arbol; el chain-verifier no firma ni publica (C-7 pendiente): sin Ed25519/sign, sin red, sin importar el signer, y su unidad declara StateDirectory 0700", () => {
  assert.ok(!existsSync(join(ROOT, "src/infra/adapters/postgres/ledger-verify-cli.ts")), "CLI retirado");
  const walk = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.name === "node_modules" || e.name === ".git" ? [] : e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
  for (const f of [...walk(join(ROOT, "src")), ...walk(join(ROOT, "infra"))].filter((x) => /\.(ts|service|timer|example)$/.test(x))) {
    assert.ok(!/ledger-verify-cli/.test(readFileSync(f, "utf8")), `${relative(ROOT, f)} aun cita el CLI retirado (src/ e infra/)`);
  }
  const graph = importGraph(join(ROOT, "src/server/entrypoints/chain-verifier/main.ts"));
  for (const f of graph) {
    const text = readFileSync(join(ROOT, f), "utf8");
    assert.ok(!/ed25519|createSign|createPrivateKey|sign\(|node:net|node:http|node:https|node:dns|fetch\(/i.test(text.replace(/\/\/.*$/gm, "")), `${f}: firma o red en el grafo del chain-verifier`);
  }
  const unit = readFileSync(join(ROOT, "infra/systemd/consent-chain-verifier.service"), "utf8");
  assert.equal(/^StateDirectory=(.*)$/m.exec(unit)?.[1], "consent-chain-verifier");
  assert.equal(/^StateDirectoryMode=(.*)$/m.exec(unit)?.[1], "0700");
  assert.equal(/^Environment=CNS_CHAIN_VERIFIER_STATE_DIR=(.*)$/m.exec(unit)?.[1], "/var/lib/consent-chain-verifier");
  assert.equal(/^UMask=(.*)$/m.exec(unit)?.[1], "0077");
});
