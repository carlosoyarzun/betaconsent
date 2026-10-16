// Gobierna: ADR-010 rev. 6 §2 (recomputo de la cadena SHA-256 por tenant en el proceso `chain-verifier`; exit 0/2/1; aislamiento por tenant, C8; log sin PII, C9/C10), §3 fila PR-6f, F-PR6E-06, SEC-06-4, SEC-06-5.
//
// Auditoria PURA de la cadena (sin Postgres, sin E/S): consume los eslabones de cada tenant por lotes con el oraculo unico `createChainVerifier` (modules/common/ledger-chain.ts; no duplica el algoritmo) y arma
// el reporte y las lineas de log. Cero PII y cero secretos en el log: solo ids opacos (uuid del tenant), enums y conteos. NUNCA payload, hashes, refs de actor, `idempotency_key_hash` ni texto libre de una fila:
// `aggregate_id` (texto libre 1..100, 0002) solo sale si pasa una allowlist estricta y, si no, se enmascara (`?`); `aggregate_type` no se imprime; `\n`, ANSI y controles no pueden pasar la allowlist (SEC-06-5, C10).

import { createChainVerifier } from "../common/ledger-chain.ts";
import type { ChainBreak, ChainRow } from "../common/ledger-chain.ts";

/** Tope de lineas de detalle por corrida (el conteo total siempre se informa). Mismo valor que el reconciler. */
export const MAX_LOGGED_DIVERGENCES = 200;
/** Tope de lineas `chain_verify_tenant` por corrida (C9: una por tenant con `head=`). */
export const MAX_LOGGED_TENANTS = 1000;

/** Resultado de verificar la cadena de UN tenant. */
export interface TenantChainResult {
  readonly tenantId: string;
  /** Eslabones leidos del tenant (con chain_seq), incluidos los posteriores a una rotura. */
  readonly events: number;
  /** Eslabones correctos antes del primero roto. */
  readonly verified: number;
  /** chainSeq del ultimo eslabon leido (0 si el tenant no tiene cadena): cabeza de la cadena para compararla a mano hasta PR-7 (C9). */
  readonly head: number;
  /** Primer eslabon roto, si lo hay. */
  readonly broken: ChainBreak | null;
  /** Filas sin eslabon (chain_seq NULL) posteriores al inicio de la cadena: evaden el verificador (ver ledger-verify-cli.ts). */
  readonly unchainedAfterStart: number;
}

export interface ChainAuditReport {
  /** true solo si ningun tenant esta roto ni tiene filas sin eslabon. */
  readonly ok: boolean;
  readonly tenants: number;
  readonly events: number;
  readonly broken: number;
  readonly unchained: number;
  readonly byReason: Readonly<Record<string, number>>;
  readonly results: readonly TenantChainResult[];
}

/**
 * Verifica la cadena de un tenant a partir de lotes ya ordenados por chainSeq. Un payload no canonicalizable es una rotura (MALFORMED_PAYLOAD) de ESTE tenant: no lanza ni detiene a los demas (C8).
 * Tras la primera rotura sigue contando eslabones y cabeza (sin recomputar) para informar `events` y `head`.
 */
export async function auditTenantChain(tenantId: string, batches: AsyncIterable<readonly ChainRow[]>, unchainedAfterStart: number): Promise<TenantChainResult> {
  const verifier = createChainVerifier();
  let events = 0;
  let head = 0;
  for await (const batch of batches) {
    for (const row of batch) {
      events += 1;
      head = row.chainSeq;
      verifier.push(row);
    }
  }
  return { tenantId, events, verified: verifier.verified, head, broken: verifier.broken, unchainedAfterStart };
}

export function summarizeChainAudit(results: readonly TenantChainResult[]): ChainAuditReport {
  const byReason: Record<string, number> = {};
  let events = 0;
  let broken = 0;
  let unchained = 0;
  for (const r of results) {
    events += r.events;
    unchained += r.unchainedAfterStart;
    if (r.broken !== null) {
      broken += 1;
      byReason[r.broken.reason] = (byReason[r.broken.reason] ?? 0) + 1;
    }
  }
  return { ok: broken === 0 && unchained === 0, tenants: results.length, events, broken, unchained, byReason, results };
}

/** Exit codes del proceso: 0 cadena integra en todos los tenants; 2 algun tenant roto o con filas sin eslabon; 1 arranque, configuracion, lectura o asercion fallida (fail-closed). */
export const CHAIN_VERIFIER_EXIT = { OK: 0, ERROR: 1, BROKEN: 2 } as const;

export function exitCodeFor(report: ChainAuditReport): number {
  return report.ok ? CHAIN_VERIFIER_EXIT.OK : CHAIN_VERIFIER_EXIT.BROKEN;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Ref opaca de un agregado: solo letras, digitos, `_` y `-` (sin espacios, `=`, `:` ni controles) y nunca una secuencia hex larga (podria ser un hash o un secreto). Si no, se enmascara. */
const OPAQUE_AGGREGATE = /^[0-9A-Za-z_-]{1,64}$/;
const LONG_HEX = /[0-9a-fA-F]{32,}/;
const REASON = /^[A-Z_]{1,40}$/;

const safeTenant = (value: string): string => (UUID.test(value) ? value : "?");
const safeAggregate = (value: string): string => (OPAQUE_AGGREGATE.test(value) && !LONG_HEX.test(value) ? value : "?");
const safeInt = (value: number): string => (Number.isSafeInteger(value) && value >= 0 ? String(value) : "?");

/**
 * Lineas de log de una corrida (sin PII). La primera resume; luego una por tenant con `head=` (C9, hasta el tope), una por tenant roto y una por tenant con filas sin eslabon (hasta el tope).
 * Los campos que vienen de la base pasan por allowlist o se enmascaran (C10).
 */
export function formatChainReport(report: ChainAuditReport): string[] {
  const kinds = Object.entries(report.byReason).filter(([k]) => REASON.test(k)).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, n]) => `${k}=${n}`).join(",");
  const lines = [`chain_verify_run ok=${report.ok} tenants=${report.tenants} events=${report.events} broken=${report.broken} unchained=${report.unchained}${kinds === "" ? "" : ` kinds=${kinds}`}`];
  for (const r of report.results.slice(0, MAX_LOGGED_TENANTS)) {
    lines.push(`chain_verify_tenant tenant=${safeTenant(r.tenantId)} head=${safeInt(r.head)} events=${safeInt(r.events)} verified=${safeInt(r.verified)} status=${r.broken === null && r.unchainedAfterStart === 0 ? "ok" : "bad"}`);
  }
  if (report.results.length > MAX_LOGGED_TENANTS) lines.push(`chain_verify_tenants_truncated shown=${MAX_LOGGED_TENANTS} total=${report.results.length}`);
  let detail = 0;
  let detailTotal = 0;
  for (const r of report.results) {
    if (r.broken !== null) {
      detailTotal += 1;
      if (detail < MAX_LOGGED_DIVERGENCES) {
        detail += 1;
        lines.push(
          `chain_verify_break tenant=${safeTenant(r.tenantId)} reason=${REASON.test(r.broken.reason) ? r.broken.reason : "?"} chainSeq=${safeInt(r.broken.chainSeq)} verified=${safeInt(r.verified)} aggregate=${safeAggregate(r.broken.aggregateId)} sequence=${safeInt(r.broken.sequence)}`,
        );
      }
    }
    if (r.unchainedAfterStart > 0) {
      detailTotal += 1;
      if (detail < MAX_LOGGED_DIVERGENCES) {
        detail += 1;
        lines.push(`chain_verify_unchained tenant=${safeTenant(r.tenantId)} count=${safeInt(r.unchainedAfterStart)}`);
      }
    }
  }
  if (detailTotal > MAX_LOGGED_DIVERGENCES) lines.push(`chain_verify_details_truncated shown=${MAX_LOGGED_DIVERGENCES} total=${detailTotal}`);
  return lines;
}
