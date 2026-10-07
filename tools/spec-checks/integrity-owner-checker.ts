// Gobierna: JIRA CA-142 (C3 de PR #60, X8 decision 3, F-X8-11), migraciones 0026/0027. Residual P1 aceptado por Carlos
// solo para IT0 sintetico (2026-10-06; cierre de fondo CA-144, ADR-010 break-glass): el migrador puede hacer SET ROLE
// integrity_owner y entonces controla el ledger. Este checker garantiza que SOLO los caminos aprobados (allowlist
// explicita, abajo) hagan `SET [LOCAL|SESSION] ROLE integrity_owner` o concedan la membresia de integrity_owner.
// Funcion pura: recibe {path, text}; el llamador (test unit) recorre el repo. Ampliar la allowlist exige cambio
// revisado en este archivo (y CODEOWNERS/DEC si cambia la superficie).
// FUERA DE ALCANCE (limitacion conocida, cubierta por CA-144): SQL armado dinamicamente (p.ej. format('SET ROLE %I', ...)
// o concatenacion de strings) y SET SESSION AUTHORIZATION no se detectan; el cierre de fondo es CA-144 (ADR-010).

export type UsageKind = "set-role" | "grant-membership";
export interface SourceFile { readonly path: string; readonly text: string }
export interface Usage { readonly kind: UsageKind; readonly line: number }

/** Caminos aprobados. Cada entrada debe usar realmente el patron (si no, el checker la marca obsoleta). */
export const INTEGRITY_OWNER_ALLOWLIST: Readonly<Record<string, readonly UsageKind[]>> = {
  // 0026: GRANT integrity_owner TO consent_owner WITH INHERIT FALSE, SET TRUE (membresia del migrador).
  "db/migrations/0026_integrity_owner_role.sql": ["grant-membership"],
  // 0027: transfiere el ledger a integrity_owner (SET LOCAL ROLE integrity_owner para sus DEFAULT PRIVILEGES).
  "db/migrations/0027_ledger_integrity_owner.sql": ["set-role"],
  // Test de ataque residual P1 (TEST-CNS-915/ledger-chain): demuestra el SET ROLE explicito del migrador.
  "tests/integration/postgres/ledger-chain.test.ts": ["set-role"],
};

/** Extensiones que pueden ejecutar SQL / abrir sesiones (el checker se ignora a si mismo y a su test, ver SELF_EXCLUDED). */
export const SCANNED_EXT_RE = /\.(sql|ts|tsx|mts|js|cjs|mjs|sh|ya?ml)$/;
export const SELF_EXCLUDED: readonly string[] = [
  "tools/spec-checks/integrity-owner-checker.ts",
  "tests/unit/spec-checks/integrity-owner-check.test.ts",
];

const ROLE = String.raw`["'\`]?integrity_owner["'\`]?`;
const SET_ROLE_RE = new RegExp(String.raw`\bSET\s+(?:LOCAL\s+|SESSION\s+)?ROLE\s+${ROLE}(?![\w$])`, "gi");
const SET_CONFIG_RE = /\bset_config\s*\(\s*'role'\s*,\s*'integrity_owner'/gi;
const GRANT_RE = /\bGRANT\s+([^;]*?)\s+TO\b/gi;

/** Reemplaza comentarios por espacios (conserva saltos de linea para numerar). */
export function stripComments(path: string, text: string): string {
  const blank = (s: string): string => s.replace(/[^\n]/g, " ");
  let out = text.replace(/\/\*[\s\S]*?\*\//g, blank);
  if (path.endsWith(".sql")) out = out.replace(/--[^\n]*/g, blank);
  else if (path.endsWith(".yml") || path.endsWith(".yaml") || path.endsWith(".sh")) out = out.replace(/^[ \t]*#[^\n]*/gm, blank);
  else out = out.replace(/^[ \t]*\/\/[^\n]*/gm, blank);
  return out;
}

export function findUsages(path: string, text: string): Usage[] {
  const t = stripComments(path, text);
  const lineOf = (idx: number): number => t.slice(0, idx).split("\n").length;
  const found: Usage[] = [];
  for (const re of [SET_ROLE_RE, SET_CONFIG_RE]) {
    for (const m of t.matchAll(re)) found.push({ kind: "set-role", line: lineOf(m.index ?? 0) });
  }
  for (const m of t.matchAll(GRANT_RE)) {
    // `GRANT <lista> TO ...`: solo cuenta si integrity_owner es uno de los roles concedidos (no el destinatario).
    const granted = (m[1] ?? "").split(",").map((s) => s.trim().replace(/^["'`]|["'`]$/g, "").toLowerCase());
    if (granted.includes("integrity_owner")) found.push({ kind: "grant-membership", line: lineOf(m.index ?? 0) });
  }
  return found;
}

export function checkIntegrityOwnerUsage(
  files: readonly SourceFile[],
  allowlist: Readonly<Record<string, readonly UsageKind[]>> = INTEGRITY_OWNER_ALLOWLIST,
  excluded: readonly string[] = SELF_EXCLUDED,
): string[] {
  const errors: string[] = [];
  const byPath = new Map(files.map((f) => [f.path, f]));
  for (const f of files) {
    if (excluded.includes(f.path) || !SCANNED_EXT_RE.test(f.path)) continue;
    const allowed = allowlist[f.path] ?? [];
    for (const u of findUsages(f.path, f.text)) {
      if (!allowed.includes(u.kind)) {
        errors.push(`integrity_owner: ${f.path}:${u.line} usa ${u.kind} fuera de la allowlist (CA-142; residual P1, cierre CA-144)`);
      }
    }
  }
  for (const [path, kinds] of Object.entries(allowlist)) {
    const f = byPath.get(path);
    if (!f) { errors.push(`integrity_owner: allowlist obsoleta, no existe ${path}`); continue; }
    const used = new Set(findUsages(path, f.text).map((u) => u.kind));
    for (const k of kinds) if (!used.has(k)) errors.push(`integrity_owner: allowlist obsoleta, ${path} ya no usa ${k}`);
  }
  return errors;
}
