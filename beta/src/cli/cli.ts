// Gobierna: DEC de Carlos "Reconstrucción mínima" (2026-10-19) y plan v2 H1-09 (CLI consent-admin). Lógica de los comandos, separada de main.ts para poder probarla con pools reales.
// Dos pools: `app` (consent_app: import_invitation, enqueue_invitation_email, lecturas, authorization_status) y `mailer` (consent_mailer: request_invitation_resend y worker del outbox).
// Salida sin PII: nunca imprime correos completos, tokens ni códigos. Errores de la base: solo SQLSTATE o código de dominio.

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

import { getServedConsentVersion } from "../consent/served-consent-version.ts";
import { DomainError } from "../domain/errors.ts";
import { mapPgError } from "../db/map-error.ts";
import type { Queryable } from "../db/pool.ts";
import { PgUnitOfWork } from "../db/unit-of-work.ts";
import { createChainVerifier } from "../ledger/ledger-chain.ts";
import { readChain } from "../ledger/read-chain.ts";
import type { Mailer } from "../mail/mailer.port.ts";
import { enqueueInvitationEmail, requestInvitationResend, runOutboxTick, type MailLogger, type TickResult } from "../mail/outbox-worker.ts";
import type { RecipientPolicy } from "../mail/recipient-policy.ts";
import { CsvFormatError, isBatchRef, parseInvitationCsv, type RowIssue } from "./csv.ts";

export const RESEND_REASON_SHAPE = /^[A-Z][A-Z0-9_]{2,39}$/;
const INVITATION_REF_SHAPE = /^[A-Za-z0-9_-]{1,100}$/;

export interface PoolLikeForCli extends Queryable {
  connect(): Promise<import("pg").PoolClient>;
}

export interface WorkerDeps {
  readonly mailer: Mailer;
  readonly policy: RecipientPolicy;
}

export interface CliDeps {
  readonly app: PoolLikeForCli;
  readonly mailer: PoolLikeForCli;
  /** Se invoca solo con --run-worker-once: construye el mailer SMTP y la política (necesita CNS_SMTP_*, allowlist). */
  readonly makeWorker: () => Promise<WorkerDeps>;
  readonly readFile?: (path: string) => string;
}

export interface CliResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

class UsageError extends Error {}
class Unsupported extends Error {}

const quietLogger: MailLogger = { info: () => undefined, warn: () => undefined };

const HELP = `consent-admin <comando> [opciones]
  import-csv <archivo> --batch <ref> [--dry-run|--apply]
  send-invitations --batch <ref> [--limit n] [--run-worker-once]
  resend <invitation_ref> --reason <CODE> [--run-worker-once]
  status [--batch <ref>] [--student <ref>]
  cancel <invitation_ref> --reason OPERATOR_CANCELLED   (no disponible hasta H2)
  verify-ledger
Opción global: --json`;

interface Out {
  readonly text: string[];
  readonly data: Record<string, unknown>;
  readonly exitCode: number;
}

function table(rows: readonly (readonly [string, string | number])[]): string[] {
  const w = Math.max(...rows.map(([k]) => k.length));
  return rows.map(([k, v]) => `${k.padEnd(w)}  ${v}`);
}

function safeError(e: unknown): string {
  const mapped = mapPgError(e);
  if (mapped instanceof DomainError) return mapped.code;
  if (e instanceof CsvFormatError) return e.code;
  const code = (e as { code?: unknown } | null)?.code;
  if (code === "42501") return "PERMISSION_DENIED";
  if (typeof code === "string" && /^[A-Z0-9_]{1,40}$/.test(code)) return `DB_ERROR_${code}`;
  return "ERROR";
}

export async function runCli(argv: readonly string[], deps: CliDeps): Promise<CliResult> {
  let json = false;
  try {
    const parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      options: {
        batch: { type: "string" },
        "dry-run": { type: "boolean" },
        apply: { type: "boolean" },
        limit: { type: "string" },
        "run-worker-once": { type: "boolean" },
        reason: { type: "string" },
        student: { type: "string" },
        json: { type: "boolean" },
        help: { type: "boolean" },
      },
    });
    json = parsed.values.json === true;
    const [cmd, ...pos] = parsed.positionals;
    if (cmd === undefined || parsed.values.help === true) return { exitCode: cmd === undefined && parsed.values.help !== true ? 2 : 0, stdout: `${HELP}\n`, stderr: "" };
    const v = parsed.values;
    let out: Out;
    switch (cmd) {
      case "import-csv":
        out = await importCsv(deps, pos, v);
        break;
      case "send-invitations":
        out = await sendInvitations(deps, v);
        break;
      case "resend":
        out = await resend(deps, pos, v);
        break;
      case "status":
        out = await status(deps, v);
        break;
      case "cancel":
        throw new Unsupported(
          "cancel no está disponible: cancel_invitation solo admite el motivo SUBJECT_MISMATCH_REPORTED y las invitaciones OPENED/VERIFIED, y no existe función de operador para READY/SENT (hueco documentado para H2).",
        );
      case "verify-ledger":
        out = await verifyLedger(deps);
        break;
      default:
        throw new UsageError(`comando desconocido: ${cmd}`);
    }
    return { exitCode: out.exitCode, stdout: json ? `${JSON.stringify({ command: cmd, ...out.data })}\n` : `${out.text.join("\n")}\n`, stderr: "" };
  } catch (e) {
    const code = e instanceof UsageError || e instanceof Unsupported ? e.message : e instanceof Error && e.name === "TypeError" ? e.message : safeError(e);
    const exitCode = e instanceof UsageError ? 2 : e instanceof Unsupported ? 3 : 1;
    const msg = json ? JSON.stringify({ ok: false, error: code }) : `ERROR: ${code}`;
    return { exitCode, stdout: "", stderr: `${msg}\n` };
  }
}

type Values = Record<string, string | boolean | undefined>;

function requireBatch(v: Values): string {
  const b = v.batch;
  if (typeof b !== "string" || !isBatchRef(b)) throw new UsageError("--batch es obligatorio y debe ser una referencia opaca ([A-Za-z0-9_-]{8,64})");
  return b;
}

// --- import-csv ---------------------------------------------------------------------------------------------------------------------------------------
async function importCsv(deps: CliDeps, pos: string[], v: Values): Promise<Out> {
  const file = pos[0];
  if (file === undefined || pos.length > 1) throw new UsageError("uso: import-csv <archivo> --batch <ref> [--dry-run|--apply]");
  const batch = requireBatch(v);
  if (v["dry-run"] === true && v.apply === true) throw new UsageError("--dry-run y --apply son excluyentes");
  const apply = v.apply === true;
  const content = (deps.readFile ?? ((p) => readFileSync(p, "utf8")))(file);
  const parsed = parseInvitationCsv(content);
  if (!parsed.ok) {
    const issues: readonly RowIssue[] = parsed.issues;
    const text = [parsed.headerError ?? `Lote RECHAZADO: ${issues.length} fila(s) inválida(s); no se escribió nada.`, ...issues.map((i) => `  fila ${i.row} ${i.field}: ${i.reason}${i.masked_email ? ` (${i.masked_email})` : ""}`)];
    return {
      text: [`import_batch_ref  ${batch}`, ...text],
      data: { ok: false, import_batch_ref: batch, mode: apply ? "apply" : "dry-run", written: 0, header_error: parsed.headerError ?? null, invalid: issues.length, issues },
      exitCode: 1,
    };
  }
  const rows = parsed.rows;
  let created = 0;
  let existing = 0;
  if (apply) {
    // Todo o nada: una sola transacción; cualquier error revierte el lote completo.
    await new PgUnitOfWork(deps.app).withTransaction(async (tx) => {
      created = 0;
      existing = 0;
      for (const r of rows) {
        const res = await tx.query<{ invitation_ref: string; created: boolean }>("SELECT * FROM app.import_invitation($1, $2, $3, $4)", [r.studentRef, r.studentFirstName, r.guardianEmail, batch]);
        if (res.rows[0]?.created === true) created++;
        else existing++;
      }
    });
  } else {
    const res = await deps.app.query<{ student_ref: string }>("SELECT student_ref FROM app.invitation WHERE student_ref = ANY($1::text[])", [rows.map((r) => r.studentRef)]);
    existing = new Set(res.rows.map((r) => r.student_ref)).size;
    created = rows.length - existing;
  }
  const label = apply ? "APLICADO" : "DRY-RUN (no se escribió nada; use --apply)";
  return {
    text: [label, ...table([["import_batch_ref", batch], ["total", rows.length], ["nuevas", created], ["existentes", existing], ["inválidas", 0]])],
    data: { ok: true, import_batch_ref: batch, mode: apply ? "apply" : "dry-run", total: rows.length, new: created, existing, invalid: 0 },
    exitCode: 0,
  };
}

// --- worker --------------------------------------------------------------------------------------------------------------------------------------------
async function drainOutbox(deps: CliDeps): Promise<TickResult & { ticks: number }> {
  const w = await deps.makeWorker();
  const total: TickResult & { ticks: number } = { sent: 0, retry: 0, failed: 0, suppressed: 0, ticks: 0 };
  for (let i = 0; i < 1000; i++) {
    const r = await runOutboxTick({ db: deps.mailer, mailer: w.mailer, policy: w.policy, logger: quietLogger });
    total.ticks++;
    total.sent += r.sent;
    total.retry += r.retry;
    total.failed += r.failed;
    total.suppressed += r.suppressed;
    if (r.sent + r.retry + r.failed + r.suppressed === 0) break;
  }
  return total;
}

function workerLines(w: (TickResult & { ticks: number }) | null): string[] {
  if (w === null) return ["Los correos los envía el worker del proceso web (si el web no está corriendo, quedan PENDING: use --run-worker-once)."];
  return [`worker (una pasada): enviados=${w.sent} reintento=${w.retry} fallidos=${w.failed} suprimidos=${w.suppressed}`];
}

// --- send-invitations ------------------------------------------------------------------------------------------------------------------------------
async function sendInvitations(deps: CliDeps, v: Values): Promise<Out> {
  const batch = requireBatch(v);
  let limit: number | null = null;
  if (typeof v.limit === "string") {
    limit = Number(v.limit);
    if (!Number.isInteger(limit) || limit < 1) throw new UsageError("--limit debe ser un entero >= 1");
  }
  const ready = await deps.app.query<{ invitation_ref: string }>(
    "SELECT invitation_ref FROM app.invitation WHERE import_batch_ref = $1 AND state = 'READY' ORDER BY created_at, invitation_ref LIMIT $2",
    [batch, limit],
  );
  const version = getServedConsentVersion().consentVersion;
  let enqueued = 0;
  let alreadyQueued = 0;
  for (const r of ready.rows) {
    if (await enqueueInvitationEmail(deps.app, r.invitation_ref, version)) enqueued++;
    else alreadyQueued++;
  }
  const worker = v["run-worker-once"] === true ? await drainOutbox(deps) : null;
  return {
    text: [...table([["import_batch_ref", batch], ["ready", ready.rows.length], ["encoladas", enqueued], ["ya_encoladas", alreadyQueued]]), ...workerLines(worker)],
    data: { ok: true, import_batch_ref: batch, ready: ready.rows.length, enqueued, already_queued: alreadyQueued, worker },
    exitCode: 0,
  };
}

// --- resend ---------------------------------------------------------------------------------------------------------------------------------------------
async function resend(deps: CliDeps, pos: string[], v: Values): Promise<Out> {
  const ref = pos[0];
  if (ref === undefined || pos.length > 1 || !INVITATION_REF_SHAPE.test(ref)) throw new UsageError("uso: resend <invitation_ref> --reason <CODE>");
  if (typeof v.reason !== "string" || !RESEND_REASON_SHAPE.test(v.reason)) throw new UsageError("--reason es obligatorio y debe cumplir ^[A-Z][A-Z0-9_]{2,39}$");
  await requestInvitationResend(deps.mailer, ref, v.reason);
  const worker = v["run-worker-once"] === true ? await drainOutbox(deps) : null;
  return {
    text: [`Reenvío encolado para ${ref} (motivo ${v.reason}).`, ...workerLines(worker)],
    data: { ok: true, invitation_ref: ref, reason: v.reason, worker },
    exitCode: 0,
  };
}

// --- status ---------------------------------------------------------------------------------------------------------------------------------------------
async function status(deps: CliDeps, v: Values): Promise<Out> {
  const batch = typeof v.batch === "string" ? requireBatch(v) : null;
  const inv = await deps.app.query<{ state: string; n: string }>("SELECT state, count(*)::text AS n FROM app.invitation WHERE ($1::text IS NULL OR import_batch_ref = $1) GROUP BY state ORDER BY state", [batch]);
  const dec = await deps.app.query<{ state: string; n: string }>(
    `SELECT d.state, count(*)::text AS n FROM app.consent_decision d JOIN app.invitation i ON i.tenant_id = d.tenant_id AND i.invitation_ref = d.invitation_ref
      WHERE ($1::text IS NULL OR i.import_batch_ref = $1) GROUP BY d.state ORDER BY d.state`,
    [batch],
  );
  const box = await deps.app.query<{ status: string; n: string }>(
    `SELECT o.status, count(*)::text AS n FROM app.email_outbox o JOIN app.invitation i ON i.tenant_id = o.tenant_id AND i.invitation_ref = o.invitation_ref
      WHERE ($1::text IS NULL OR i.import_batch_ref = $1) GROUP BY o.status ORDER BY o.status`,
    [batch],
  );
  const toMap = (rows: { n: string }[], key: "state" | "status"): Record<string, number> =>
    Object.fromEntries(rows.map((r) => [(r as unknown as Record<string, string>)[key] as string, Number(r.n)]));
  const invitations = toMap(inv.rows, "state");
  const decisions = toMap(dec.rows, "state");
  const outbox = toMap(box.rows, "status");
  const fmt = (title: string, m: Record<string, number>): string[] => [`${title}:`, ...(Object.keys(m).length ? table(Object.entries(m).map(([k, n]) => [`  ${k}`, n] as const)) : ["  (sin filas)"])];
  const text = [`alcance  ${batch ?? "todos los lotes"}`, ...fmt("invitaciones por estado", invitations), ...fmt("decisiones por estado", decisions), ...fmt("outbox por estado", outbox)];
  const data: Record<string, unknown> = { ok: true, import_batch_ref: batch, invitations, decisions, outbox };
  if (typeof v.student === "string") {
    const auth = await deps.app.query<{ status: string; as_of: Date }>("SELECT status, as_of FROM app.authorization_status($1)", [v.student]);
    const st = await deps.app.query<{ state: string }>("SELECT state FROM app.invitation WHERE student_ref = $1 ORDER BY created_at LIMIT 1", [v.student]);
    const a = auth.rows[0];
    const studentOut = { student_ref: v.student, authorization_status: a?.status ?? "NOT_AUTHORIZED", as_of: a ? new Date(a.as_of).toISOString() : null, invitation_state: st.rows[0]?.state ?? null };
    text.push(`estudiante ${v.student}: authorization_status=${studentOut.authorization_status} invitación=${studentOut.invitation_state ?? "(ninguna)"} as_of=${studentOut.as_of}`);
    data.student = studentOut;
  }
  return { text, data, exitCode: 0 };
}

// --- verify-ledger ----------------------------------------------------------------------------------------------------------------------------------
async function verifyLedger(deps: CliDeps): Promise<Out> {
  // consent_app tiene SELECT de integrity.audit_event (0001): no hace falta rol de solo lectura aparte en H1.
  const rows = await readChain(deps.app);
  const verifier = createChainVerifier();
  for (const r of rows) if (verifier.push(r) !== null) break;
  const head = rows[rows.length - 1];
  const headInfo = head ? { chain_seq: head.chainSeq, event_hash: head.eventHash } : null;
  if (verifier.broken === null) {
    return {
      text: [`LEDGER OK  eventos=${verifier.verified}`, headInfo ? `cabeza  chain_seq=${headInfo.chain_seq} event_hash=${headInfo.event_hash}` : "cabeza  (cadena vacía)"],
      data: { ok: true, status: "OK", count: rows.length, verified: verifier.verified, head: headInfo },
      exitCode: 0,
    };
  }
  const b = verifier.broken;
  return {
    text: [`LEDGER FALLA  verificados=${verifier.verified} de ${rows.length}`, `roto en chain_seq=${b.chainSeq} motivo=${b.reason}`],
    data: { ok: false, status: "FAILED", count: rows.length, verified: verifier.verified, head: headInfo, broken_at: { chain_seq: b.chainSeq, reason: b.reason } },
    exitCode: 1,
  };
}
