// Gobierna: ADR-001 rev. 8 F1 (fase B). Lectura de los endpoints JSON `GET /decision/page-state` (API-CNS-194) y
// `GET /manage/page-state` (API-CNS-195): los datos que el SSR interpolaba en el HTML y que el `index.html` de la SPA no
// trae. GET de solo lectura: misma sesión por cookie HttpOnly (`credentials: same-origin`), sin CSRF (no hay efecto), sin
// registrar ni reflejar el cuerpo. Los POST de las páginas siguen usando `postJson` de ./client.ts.
import type { ApiResult } from "./client.ts";

export interface ServedVersionView {
  readonly consentVersion: string;
  readonly privacyNoticeVersion: string;
  readonly text: string;
}

export interface DecisionPageState {
  readonly relationshipRefs: readonly string[];
  readonly servedVersion: ServedVersionView;
  /** Etiqueta sintética de solo lectura («Alumno de prueba N»); ausente si el directorio no la tiene. */
  readonly subjectLabel?: string;
}

export type ManageVariant = "entry" | "status" | "revoked";

export interface ManagePageState {
  readonly variant: ManageVariant;
}

async function getJson(path: string): Promise<ApiResult<unknown>> {
  let res: Response;
  try {
    res = await fetch(path, { method: "GET", headers: { accept: "application/json" }, credentials: "same-origin" });
  } catch {
    return { ok: false, error: { kind: "network", status: 0 } };
  }
  if (!res.ok) return { ok: false, error: { kind: "http", status: res.status } };
  try {
    return { ok: true, status: res.status, data: (await res.json()) as unknown };
  } catch {
    return { ok: true, status: res.status, data: undefined };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseDecisionPageState(raw: unknown): DecisionPageState | undefined {
  if (!isRecord(raw) || !Array.isArray(raw.relationshipRefs) || !raw.relationshipRefs.every((r) => typeof r === "string")) return undefined;
  const v = raw.servedVersion;
  if (!isRecord(v) || typeof v.consentVersion !== "string" || typeof v.privacyNoticeVersion !== "string" || typeof v.text !== "string") return undefined;
  const servedVersion: ServedVersionView = { consentVersion: v.consentVersion, privacyNoticeVersion: v.privacyNoticeVersion, text: v.text };
  const base = { relationshipRefs: raw.relationshipRefs as string[], servedVersion };
  return typeof raw.subjectLabel === "string" ? { ...base, subjectLabel: raw.subjectLabel } : base;
}

export function parseManagePageState(raw: unknown): ManagePageState | undefined {
  if (!isRecord(raw)) return undefined;
  return raw.variant === "entry" || raw.variant === "status" || raw.variant === "revoked" ? { variant: raw.variant } : undefined;
}

/** Resultado de un page-state: `uniform` = 404 uniforme (INV-CM-05); `unavailable` = red, 5xx o cuerpo fuera del contrato. */
export type PageStateResult<T> =
  | { readonly kind: "ready"; readonly data: T }
  | { readonly kind: "uniform" }
  | { readonly kind: "unavailable" };

async function loadPageState<T>(path: string, parse: (raw: unknown) => T | undefined): Promise<PageStateResult<T>> {
  const result = await getJson(path);
  if (!result.ok) return result.error.kind === "http" && result.error.status === 404 ? { kind: "uniform" } : { kind: "unavailable" };
  const data = parse(result.data);
  return data === undefined ? { kind: "unavailable" } : { kind: "ready", data };
}

export function loadDecisionPageState(): Promise<PageStateResult<DecisionPageState>> {
  return loadPageState("/decision/page-state", parseDecisionPageState);
}

export function loadManagePageState(): Promise<PageStateResult<ManagePageState>> {
  return loadPageState("/manage/page-state", parseManagePageState);
}
