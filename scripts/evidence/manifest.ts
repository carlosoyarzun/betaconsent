#!/usr/bin/env node
// Gobierna: DEC-BR-014 rev. 8 §3 (G-IT0-EXIT: X3 "controles synthetic-only verificados con evidencia en
// evidence/", X5, X6); decision de Carlos 2026-10-01, "evidencia (a)": se commitea en evidence/it0/ un
// RESUMEN por corrida y condicion, sin logs crudos ni datos. Cita: TEST-CNS-990.
//
// Entrada: los JSONL `test-evidence/v1` de tools/testing/run-tests.ts (evidence/test-runs/, gitignored) y
// traceability/test-matrix.csv (asignacion test -> condicion por token X3/X5/X6 en governed_by/test_name).
// Salida: evidence/it0/<condicion>/<YYYY-MM-DD>-<commit corto>[-nopg].json. Solo IDs, titulos, rutas y estados.
// Se niega a escribir un manifiesto que contenga emails, tokens u otros secretos (fail-closed).
//
// Uso: node scripts/evidence/manifest.ts [--runs evidence/test-runs] [--environment LOCAL|CI]
//        [--postgres-digest sha256:<64hex>|none] [--exit-code N] [--out evidence/it0] [--commit <sha>] [--branch <name>]
// SYNTHETIC DATA ONLY.

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const CONDITIONS = ["X3", "X5", "X6"] as const;
export type Condition = (typeof CONDITIONS)[number];
export type Status = "pass" | "fail" | "skip";

export interface ManifestTest {
  id: string;
  title: string;
  file: string;
  status: Status;
}

export interface Manifest {
  condition: Condition;
  commit: string;
  branch: string;
  runAt: string;
  environment: "LOCAL" | "CI";
  postgres: { imageDigest: string | null };
  tests: ManifestTest[];
  summary: { pass: number; fail: number; skip: number };
  exitCode: number;
}

export interface RunRecord {
  file: string | null;
  testName: string;
  result: string;
}

export interface MatrixRow {
  id: string;
  layer: string;
  file: string;
  title: string;
  governedBy: string;
  status: string;
}

/** CSV RFC4180 minimo (comillas dobles, "" escapado, saltos dentro de comillas). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cell); cell = "";
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
    } else cell += c;
  }
  if (cell !== "" || row.length > 0) { row.push(cell); rows.push(row); }
  return rows;
}

export function parseMatrix(csv: string): MatrixRow[] {
  const [header, ...rows] = parseCsv(csv);
  if (!header || header.join(",") !== "test_id,layer,file,test_name,governed_by,status") {
    throw new Error("test-matrix.csv: cabecera inesperada");
  }
  return rows.map((r) => ({ id: r[0] ?? "", layer: r[1] ?? "", file: r[2] ?? "", title: r[3] ?? "", governedBy: r[4] ?? "", status: r[5] ?? "" }));
}

export function parseRunRecords(jsonl: string): RunRecord[] {
  const out: RunRecord[] = [];
  for (const line of jsonl.split("\n")) {
    if (line.trim() === "") continue;
    const o = JSON.parse(line) as Record<string, unknown>;
    if (o.schema !== "test-evidence/v1") throw new Error("JSONL: schema distinto de test-evidence/v1");
    out.push({ file: typeof o.file === "string" ? o.file : null, testName: String(o.testName ?? ""), result: String(o.result ?? "") });
  }
  return out;
}

export function conditionsOf(row: MatrixRow): Condition[] {
  const hay = `${row.governedBy} ${row.title}`;
  return CONDITIONS.filter((c) => new RegExp(`(?<![A-Za-z0-9])${c}(?![A-Za-z0-9])`).test(hay));
}

function aggregate(results: readonly string[]): Status {
  if (results.length === 0) return "skip";
  if (results.includes("fail")) return "fail";
  if (results.every((r) => r === "skip" || r === "todo")) return "skip";
  return "pass";
}

/** Estado de una fila de la matriz: registros del mismo archivo cuyo nombre lleva el ID; si ninguno lo lleva,
 * agregado del archivo; sin registros (p. ej. pg sin Postgres, o rama no corrida) => skip. */
export function statusOf(row: MatrixRow, records: readonly RunRecord[]): Status {
  const inFile = records.filter((r) => r.file === row.file);
  const byId = inFile.filter((r) => r.testName.includes(row.id));
  return aggregate((byId.length > 0 ? byId : inFile).map((r) => r.result));
}

export function buildManifests(args: {
  matrix: readonly MatrixRow[];
  records: readonly RunRecord[];
  commit: string;
  branch: string;
  runAt: string;
  environment: "LOCAL" | "CI";
  postgresDigest: string | null;
  exitCode: number;
}): Manifest[] {
  return CONDITIONS.map((condition) => {
    const seen = new Set<string>();
    const tests: ManifestTest[] = [];
    for (const row of args.matrix) {
      if (row.status !== "ACTIVE" || !conditionsOf(row).includes(condition)) continue;
      const key = `${row.id}|${row.file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      tests.push({ id: row.id, title: row.title, file: row.file, status: statusOf(row, args.records) });
    }
    tests.sort((a, b) => (a.id + a.file).localeCompare(b.id + b.file));
    const summary = { pass: 0, fail: 0, skip: 0 };
    for (const t of tests) summary[t.status]++;
    return {
      condition, commit: args.commit, branch: args.branch, runAt: args.runAt, environment: args.environment,
      postgres: { imageDigest: args.postgresDigest }, tests, summary, exitCode: args.exitCode,
    };
  });
}

const COMMIT_RE = /^[0-9a-f]{7,40}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+/;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/;
const LONG_TOKEN_RE = /[A-Za-z0-9_-]{32,}/g;
const SECRET_ASSIGN_RE = /\b(password|passwd|secret|token|apikey|api_key)\s*[=:]\s*\S{6,}/i;
const BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/-]{8,}/i;
const URL_CREDS_RE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@]+:[^\s/@]+@/i;

/** Devuelve hallazgos (sin el valor) de emails/tokens/secretos en el manifiesto. El digest de imagen y el commit se validan
 * por forma exacta y se excluye del escaneo de tokens largos. Lista vacia = limpio. */
export function scanManifest(m: Manifest): string[] {
  const findings: string[] = [];
  const digest = m.postgres.imageDigest;
  if (digest !== null && !DIGEST_RE.test(digest)) findings.push("postgres.imageDigest: forma invalida");
  if (!COMMIT_RE.test(m.commit)) findings.push("commit: forma invalida");
  const text = JSON.stringify({ ...m, commit: "", postgres: { imageDigest: null } });
  if (EMAIL_RE.test(text)) findings.push("email-like");
  if (JWT_RE.test(text)) findings.push("jwt-like");
  if (BEARER_RE.test(text)) findings.push("bearer");
  if (SECRET_ASSIGN_RE.test(text)) findings.push("secret-assignment");
  if (URL_CREDS_RE.test(text)) findings.push("url-credentials");
  for (const t of text.match(LONG_TOKEN_RE) ?? []) {
    if (/\d/.test(t) && /[A-Za-z]/.test(t)) { findings.push("token-like"); break; }
  }
  return findings;
}

export function assertCleanManifest(m: Manifest): void {
  const findings = scanManifest(m);
  if (findings.length > 0) throw new Error(`manifiesto ${m.condition} rechazado (posible PII/secreto): ${findings.join(", ")}`);
}

export function manifestPath(outDir: string, m: Manifest): string {
  // Sufijo -nopg: corrida sin Postgres (los tests pg figuran skip); no pisa la corrida completa del mismo commit.
  const suffix = m.postgres.imageDigest === null ? "-nopg" : "";
  return join(outDir, m.condition, `${m.runAt.slice(0, 10)}-${m.commit.slice(0, 7)}${suffix}.json`);
}

function git(...a: string[]): string {
  return execFileSync("git", a, { encoding: "utf8" }).trim();
}

function flag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

export function main(argv: string[]): number {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
  const runsDir = resolve(root, flag(argv, "--runs") ?? "evidence/test-runs");
  const outDir = resolve(root, flag(argv, "--out") ?? "evidence/it0");
  const env = (flag(argv, "--environment") ?? (process.env.GITHUB_ACTIONS === "true" ? "CI" : "LOCAL")) as "LOCAL" | "CI";
  if (env !== "LOCAL" && env !== "CI") throw new Error("--environment: LOCAL|CI");
  const dg = flag(argv, "--postgres-digest") ?? "none";
  const records = readdirSync(runsDir).filter((f) => f.endsWith(".jsonl")).sort()
    .flatMap((f) => parseRunRecords(readFileSync(join(runsDir, f), "utf8")));
  const failed = records.some((r) => r.result === "fail");
  const manifests = buildManifests({
    matrix: parseMatrix(readFileSync(join(root, "traceability", "test-matrix.csv"), "utf8")),
    records,
    commit: flag(argv, "--commit") ?? git("rev-parse", "HEAD"),
    branch: flag(argv, "--branch") ?? git("branch", "--show-current"),
    runAt: new Date().toISOString(),
    environment: env,
    postgresDigest: dg === "none" ? null : dg,
    exitCode: Number(flag(argv, "--exit-code") ?? (failed ? 1 : 0)),
  });
  for (const m of manifests) assertCleanManifest(m); // todo o nada: ninguno se escribe si alguno falla
  for (const m of manifests) {
    const p = manifestPath(outDir, m);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, `${JSON.stringify(m, null, 2)}\n`);
    console.log(`${p}: ${m.condition} pass=${m.summary.pass} fail=${m.summary.fail} skip=${m.summary.skip}`);
  }
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) process.exit(main(process.argv.slice(2)));
