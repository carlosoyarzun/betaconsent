// Gobierna: plan v2 H1-06. Outbox en proceso sobre app.email_outbox, con SOLO los grants que consent_app ya tiene
// (SELECT; INSERT(kind, invitation_ref, dedupe_key, payload, next_attempt_at); UPDATE(status, attempts, next_attempt_at, provider_message_id, last_error_code)).
// El destinatario NO está en la tabla: se resuelve al enviar desde app.invitation (SELECT concedido).
//
// Ciclo de vida: PENDING -> (claim) SENDING -> SENT | PENDING con backoff (fallo transitorio) | FAILED (3 intentos, o suprimido/no enviable).
// Claim: UPDATE ... WHERE email_id IN (SELECT ... FOR UPDATE SKIP LOCKED); el claim fija un "lease" en next_attempt_at.
// Sin duplicados: SENT se marca SOLO tras la respuesta del proveedor y solo si la fila sigue en SENDING; dedupe_key UNIQUE evita doble encolado.
// GARANTÍA AL-MENOS-UNA-VEZ: si el proceso muere entre el envío y la marca SENT, la fila queda en SENDING; al vencer el lease
// (LEASE_SECONDS) se reclama y SE REENVÍA. Ese reenvío duplicado se acepta explícitamente (mejor un duplicado que un correo perdido).
//
// SUPPRESSED: el correo suprimido por la allowlist queda status='SUPPRESSED' con last_error_code='SUPPRESSED_ALLOWLIST' (el CHECK de 0002 lo admite).
//
// INVITACIÓN (SEC-CNS-024): el outbox NO guarda el token. La fila INVITATION solo lleva {consentVersion}; al reclamarla el worker (1) comprueba la allowlist,
// (2) genera el token en TS (generateInvitationToken: aleatorio, a la base solo va su hash), (3) llama app.arm_invitation_token(ref, hash, expiresAt, consentVersion)
// y (4) envía el enlace /i/<token>. Cada reintento rota el token (el anterior queda muerto). Si la invitación ya no es armable (INVITATION_NOT_ARMABLE: cancelada,
// abierta o decidida) la fila pasa a FAILED con ese motivo y NO se envía nada. Residual conocido: si el proceso muere entre el envío y la marca SENT, el reenvío
// rota el token y el enlace del primer correo queda muerto (duplicado aceptado, ver arriba).

import { generateInvitationToken } from "../domain/crypto.ts";
import { DomainError } from "../domain/errors.ts";
import { mapPgError } from "../db/map-error.ts";
import type { Mailer, SendRequest } from "./mailer.port.ts";
import { isRecipientAllowed, SUPPRESSED_REASON, type Queryable, type RecipientPolicy } from "./recipient-policy.ts";
import { receiptRefFor } from "../domain/receipt.ts";
import type { PurposeChoice, ReceiptParams } from "./templates/index.ts";

const ALL_PURPOSES = ["STUDY_PARTICIPATION", "AUDIO_RECORDING", "AUTOMATED_ANALYSIS", "HUMAN_REVIEW"] as const;

export const MAX_ATTEMPTS = 3;
export const LEASE_SECONDS = 300;
export const SUPPRESSED_STATUS = "SUPPRESSED";
/** P-10: vigencia del token de invitación = 7 días. */
export const INVITATION_TOKEN_TTL_MS = 7 * 24 * 60 * 60_000;
/** Espera tras el intento 1 y 2 (ms). */
export const DEFAULT_BACKOFF_MS: readonly number[] = [30_000, 120_000];

export interface MailLogger {
  info(msg: string, fields?: Record<string, string | number>): void;
  warn(msg: string, fields?: Record<string, string | number>): void;
}

export interface OutboxDeps {
  readonly db: Queryable;
  readonly mailer: Mailer;
  readonly policy: RecipientPolicy;
  readonly logger: MailLogger;
  readonly backoffMs?: readonly number[];
  readonly batchSize?: number;
  /** Reloj (ms) para el vencimiento del token; inyectable en tests. Default Date.now. */
  readonly now?: () => number;
  /** Vigencia del token de invitación. Default P-10 = 7 días. */
  readonly invitationTokenTtlMs?: number;
  /** H1-05: ruta `/m/<token>` del enlace de gestión de una decisión (token sin estado firmado por el proceso web). Sin ella, RECOVERY_LINK con consentId no es enviable. */
  readonly manageLinkPath?: (consentId: string) => string;
}

interface Claimed {
  email_id: string;
  kind: string;
  invitation_ref: string;
  attempts: number;
  payload: Record<string, unknown>;
}

export interface EnqueueInput {
  readonly kind: "INVITATION" | "DECISION_RECEIPT" | "REVOCATION_RECEIPT" | "RECOVERY_LINK";
  readonly invitationRef: string;
  readonly dedupeKey: string;
  /** Solo parámetros de plantilla: nunca correo, OTP, token ni RUT. INVITATION: {consentVersion}. */
  readonly payload: Record<string, unknown>;
}

/** Encola de forma idempotente por dedupe_key. Devuelve true si insertó. */
export async function enqueueEmail(db: Queryable, input: EnqueueInput): Promise<boolean> {
  const r = await db.query(
    "INSERT INTO app.email_outbox (kind, invitation_ref, dedupe_key, payload) VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (tenant_id, dedupe_key) DO NOTHING RETURNING email_id",
    [input.kind, input.invitationRef, input.dedupeKey, JSON.stringify(input.payload)],
  );
  return r.rows.length === 1;
}

class Unsendable extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

function str(v: unknown, field: string, max = 300): string {
  if (typeof v !== "string" || v === "" || v.length > max) throw new Unsendable(`BAD_PAYLOAD_${field.toUpperCase()}`.slice(0, 60));
  return v;
}

function receiptParams(payload: Record<string, unknown>, studentFirstName: string): ReceiptParams {
  const purposesRaw = payload.purposes;
  if (!Array.isArray(purposesRaw)) throw new Unsendable("BAD_PAYLOAD_PURPOSES");
  const purposes: PurposeChoice[] = purposesRaw.map((x: unknown) => {
    const o = x as { purpose?: unknown; choice?: unknown };
    if (typeof o?.purpose !== "string" || (o.choice !== "GRANT" && o.choice !== "DECLINE")) throw new Unsendable("BAD_PAYLOAD_PURPOSES");
    return { purpose: o.purpose, choice: o.choice };
  });
  return {
    studentFirstName,
    consentVersion: str(payload.consentVersion, "consentVersion"),
    decidedAt: str(payload.decidedAt, "decidedAt"),
    receiptRef: str(payload.receiptRef, "receiptRef"),
    purposes,
    ...(typeof payload.chain_seq === "number" ? { chain_seq: payload.chain_seq } : {}),
    ...(typeof payload.event_hash === "string" ? { event_hash: payload.event_hash } : {}),
  };
}

function buildRequest(row: Claimed, to: string, firstName: string): SendRequest {
  const p = row.payload;
  switch (row.kind) {
    case "INVITATION":
      throw new Unsendable("NO_TEMPLATE"); // se arma en prepareInvitation (necesita el token)
    case "RECOVERY_LINK":
      return { to, template: "management_link", params: { studentFirstName: firstName, linkPath: str(p.linkPath, "linkPath", 200) } };
    case "DECISION_RECEIPT":
      return { to, template: (p.decision ?? p.outcome) === "DECLINED" ? "receipt_declined" : "receipt_granted", params: receiptParams(p, firstName) };
    case "REVOCATION_RECEIPT":
      return { to, template: "receipt_revoked", params: receiptParams(p, firstName) };
    default:
      throw new Unsendable("NO_TEMPLATE");
  }
}

/** Genera el token, lo arma en la base (solo el hash) y devuelve el correo con el enlace. El token nunca se loguea ni se persiste en claro. */
async function prepareInvitation(deps: OutboxDeps, row: Claimed, to: string, firstName: string): Promise<SendRequest> {
  const consentVersion = str(row.payload.consentVersion, "consentVersion", 64);
  const { token, tokenHash } = generateInvitationToken();
  const expiresAt = new Date((deps.now ?? Date.now)() + (deps.invitationTokenTtlMs ?? INVITATION_TOKEN_TTL_MS));
  try {
    await deps.db.query("SELECT app.arm_invitation_token($1, $2, $3, $4)", [row.invitation_ref, tokenHash, expiresAt, consentVersion]);
  } catch (e) {
    const mapped = mapPgError(e);
    if (mapped instanceof DomainError && (mapped.code === "INVITATION_NOT_ARMABLE" || mapped.code === "INVITATION_NOT_FOUND")) throw new Unsendable(mapped.code);
    throw e;
  }
  return { to, template: "invitation", params: { studentFirstName: firstName, linkPath: `/i/${token}` } };
}

/**
 * Las funciones SQL de 0003 encolan el recibo con payload mínimo ({consentId, outcome} / {consentId, revocationRef}); la plantilla necesita versión, fecha,
 * finalidades y referencia. Si faltan, se completan desde app.consent_decision (SELECT concedido). Un payload ya completo se respeta tal cual.
 */
async function enrichReceiptPayload(deps: OutboxDeps, row: Claimed): Promise<Record<string, unknown>> {
  const p = row.payload;
  if (typeof p.receiptRef === "string") return p;
  const consentId = str(p.consentId, "consentId", 80);
  const r = await deps.db.query<{ purposes: unknown; consent_version: string; decided_at: Date; revoked_at: Date | null; state: string }>(
    "SELECT purposes, consent_version, decided_at, revoked_at, state FROM app.consent_decision WHERE consent_id = $1",
    [consentId],
  );
  const d = r.rows[0];
  if (d === undefined) throw new Unsendable("NO_DECISION");
  const granted = Array.isArray(d.purposes) ? (d.purposes as unknown[]).filter((x): x is string => typeof x === "string") : [];
  const when = row.kind === "REVOCATION_RECEIPT" ? (d.revoked_at ?? d.decided_at) : d.decided_at;
  return {
    ...p,
    decision: row.kind === "REVOCATION_RECEIPT" ? "REVOKED" : (p.outcome ?? d.state),
    consentVersion: d.consent_version,
    decidedAt: new Date(when).toISOString(),
    receiptRef: row.kind === "REVOCATION_RECEIPT" && typeof p.revocationRef === "string" ? p.revocationRef : receiptRefFor(consentId),
    purposes: ALL_PURPOSES.map((purpose) => ({ purpose, choice: granted.includes(purpose) ? "GRANT" : "DECLINE" })),
  };
}

function errorCode(e: unknown): string {
  const c = (e as { code?: unknown })?.code;
  return typeof c === "string" && /^[A-Za-z0-9_]{1,60}$/.test(c) ? c : "SEND_ERROR";
}

async function claim(deps: OutboxDeps): Promise<Claimed[]> {
  // Filas con lease vencido que ya agotaron los intentos: cierre sin reenviar.
  await deps.db.query(
    "UPDATE app.email_outbox SET status = 'FAILED', last_error_code = 'LEASE_EXPIRED' WHERE status = 'SENDING' AND attempts >= $1 AND next_attempt_at <= now()",
    [MAX_ATTEMPTS],
  );
  const { rows } = await deps.db.query<Claimed>(
    `UPDATE app.email_outbox o
        SET status = 'SENDING', attempts = o.attempts + 1, next_attempt_at = now() + make_interval(secs => $3)
       FROM (SELECT email_id FROM app.email_outbox
              WHERE status IN ('PENDING', 'SENDING') AND next_attempt_at <= now() AND attempts < $1
              ORDER BY next_attempt_at, created_at
              LIMIT $2
              FOR UPDATE SKIP LOCKED) due
      WHERE o.email_id = due.email_id
      RETURNING o.email_id, o.kind, o.invitation_ref, o.attempts, o.payload`,
    [MAX_ATTEMPTS, deps.batchSize ?? 10, LEASE_SECONDS],
  );
  return rows;
}

async function finish(deps: OutboxDeps, id: string, status: string, code: string | null, msgId: string | null, retryInMs?: number): Promise<void> {
  await deps.db.query(
    `UPDATE app.email_outbox
        SET status = $2, last_error_code = $3, provider_message_id = COALESCE($4, provider_message_id),
            next_attempt_at = CASE WHEN $5::bigint IS NULL THEN next_attempt_at ELSE now() + make_interval(secs => $5::bigint / 1000.0) END
      WHERE email_id = $1 AND status = 'SENDING'`,
    [id, status, code, msgId, retryInMs ?? null],
  );
}

async function processOne(deps: OutboxDeps, row: Claimed): Promise<"sent" | "retry" | "failed" | "suppressed"> {
  const fields = { email_id: row.email_id, kind: row.kind, attempt: row.attempts };
  try {
    const inv = await deps.db.query<{ guardian_email: string; student_first_name: string }>(
      "SELECT guardian_email, student_first_name FROM app.invitation WHERE invitation_ref = $1",
      [row.invitation_ref],
    );
    const rec = inv.rows[0];
    if (rec === undefined) throw new Unsendable("NO_RECIPIENT");
    if (!isRecipientAllowed(rec.guardian_email, deps.policy)) {
      await finish(deps, row.email_id, SUPPRESSED_STATUS, SUPPRESSED_REASON, null);
      deps.logger.info("outbox: suprimido por allowlist", fields);
      return "suppressed";
    }
    if (row.kind === "DECISION_RECEIPT" || row.kind === "REVOCATION_RECEIPT") row.payload = await enrichReceiptPayload(deps, row);
    if (row.kind === "RECOVERY_LINK" && typeof row.payload.consentId === "string" && row.payload.linkPath === undefined) {
      if (deps.manageLinkPath === undefined) throw new Unsendable("NO_LINK_BUILDER");
      row.payload = { ...row.payload, linkPath: deps.manageLinkPath(row.payload.consentId) };
    }
    const request = row.kind === "INVITATION" ? await prepareInvitation(deps, row, rec.guardian_email, rec.student_first_name) : buildRequest(row, rec.guardian_email, rec.student_first_name);
    const result = await deps.mailer.send(request);
    try {
      await finish(deps, row.email_id, "SENT", null, result.providerMessageId ?? null);
    } catch {
      // El proveedor ya aceptó el mensaje pero no pudimos marcarlo: queda SENDING y se reenviará al vencer el lease (ver cabecera).
      deps.logger.warn("outbox: enviado pero sin marcar SENT", { ...fields, code: "MARK_FAILED" });
      return "sent";
    }
    deps.logger.info("outbox: enviado", fields);
    return "sent";
  } catch (e) {
    if (e instanceof Unsendable) {
      await finish(deps, row.email_id, "FAILED", e.code, null);
      deps.logger.warn("outbox: no enviable", { ...fields, code: e.code });
      return "failed";
    }
    const code = errorCode(e); // nunca se registra el mensaje del error (puede contener destinatario o cuerpo)
    if (row.attempts >= MAX_ATTEMPTS) {
      await finish(deps, row.email_id, "FAILED", code, null);
      deps.logger.warn("outbox: agotó intentos", { ...fields, code });
      return "failed";
    }
    const backoff = deps.backoffMs ?? DEFAULT_BACKOFF_MS;
    const wait = backoff[Math.min(row.attempts - 1, backoff.length - 1)] ?? 0;
    await finish(deps, row.email_id, "PENDING", code, null, wait);
    deps.logger.warn("outbox: reintento programado", { ...fields, code, retry_in_ms: wait });
    return "retry";
  }
}

export interface TickResult {
  sent: number;
  retry: number;
  failed: number;
  suppressed: number;
}

/** Un ciclo: reclama un lote y lo procesa en serie. */
export async function runOutboxTick(deps: OutboxDeps): Promise<TickResult> {
  const out: TickResult = { sent: 0, retry: 0, failed: 0, suppressed: 0 };
  for (const row of await claim(deps)) {
    try {
      out[await processOne(deps, row)] += 1;
    } catch {
      deps.logger.warn("outbox: fila no resuelta", { email_id: row.email_id, code: "ROW_ERROR" }); // queda SENDING hasta vencer el lease
    }
  }
  return out;
}

/** Arranca el worker en el proceso web (setInterval; sin proceso aparte). Devuelve la función de parada. */
export function startOutboxWorker(deps: OutboxDeps, intervalMs = 5_000): () => void {
  let running = false;
  const timer = setInterval(() => {
    if (running) return;
    running = true;
    runOutboxTick(deps)
      .catch(() => deps.logger.warn("outbox: tick falló", { code: "TICK_ERROR" }))
      .finally(() => {
        running = false;
      });
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
