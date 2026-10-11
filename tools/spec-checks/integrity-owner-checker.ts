// Gobierna: JIRA CA-142 (C3 de PR #60, X8 decision 3, F-X8-11), migraciones 0026/0027. Residual P1 aceptado por Carlos
// solo para IT0 sintetico (2026-10-06; cierre de fondo CA-144, ADR-010 break-glass): el migrador puede hacer SET ROLE
// integrity_owner y entonces controla el ledger. Este checker garantiza que SOLO los caminos aprobados (allowlist
// explicita, abajo) hagan `SET [LOCAL|SESSION] ROLE integrity_owner` o concedan la membresia de integrity_owner.
// Funcion pura: recibe {path, text}; el llamador (test unit) recorre el repo. Ampliar la allowlist exige cambio
// revisado en este archivo (y CODEOWNERS/DEC si cambia la superficie).
// SEC-CNS-021 PR-1 (CA-146, INV-21-06): el mismo patron se aplica a security_event_owner (migraciones 0028/0029; dueno de
// ops.security_event) con su propia allowlist (SECURITY_EVENT_OWNER_ALLOWLIST / checkSecurityEventOwnerUsage).
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
  // 0030 (SEC-CNS-021 PR-2): redefine la lista blanca de event_type del ledger sin los tipos transitorios del stream SECURITY (DDL sobre integrity.*).
  "db/migrations/0030_ledger_drop_transitional_security_events.sql": ["set-role"],
  // Test de ataque residual P1 (TEST-CNS-915/ledger-chain): demuestra el SET ROLE explicito del migrador.
  "tests/integration/postgres/ledger-chain.test.ts": ["set-role"],
};

/** SEC-CNS-021 PR-1: caminos aprobados para security_event_owner. Mismas reglas que INTEGRITY_OWNER_ALLOWLIST. */
export const SECURITY_EVENT_OWNER_ALLOWLIST: Readonly<Record<string, readonly UsageKind[]>> = {
  // 0028: GRANT security_event_owner TO consent_owner WITH INHERIT FALSE, SET TRUE (membresia del migrador, transitoria F-7).
  "db/migrations/0028_security_event_owner_role.sql": ["grant-membership"],
  // 0029: transfiere ops.security_event (SET LOCAL ROLE security_event_owner para sus DEFAULT PRIVILEGES).
  "db/migrations/0029_security_event_otp_family.sql": ["set-role"],
  // 0031 (SEC-CNS-021 PR-3): crea retention_policy / purge_run / ops.purge_p34 como security_event_owner (SET LOCAL ROLE).
  "db/migrations/0031_retention_purge_p34.sql": ["set-role"],
  // 0032 (SEC-CNS-021 PR-4): crea ops.otp_budget como security_event_owner (SET LOCAL ROLE).
  "db/migrations/0032_otp_budget_p06_v6a.sql": ["set-role"],
  // 0033 (SEC-CNS-021 PR-5): fila otp_budget en retention_policy, policies de purga y ops.purge_p34 como security_event_owner (SET LOCAL ROLE).
  "db/migrations/0033_retention_purge_otp_budget.sql": ["set-role"],
  // TEST-CNS-1308/1311: demuestran que el dueno sin la bandera de purga tampoco muta, y los privilegios del dueno (SET ROLE explicito del migrador).
  "tests/integration/postgres/security-event-retention.test.ts": ["set-role"],
  // TEST-CNS-1326: demuestra que el nuevo dueno tampoco puede mutar la tabla (SET ROLE explicito del migrador).
  "tests/integration/postgres/security-event-otp-family.test.ts": ["set-role"],
};

/**
 * ADR-010 PR-2 (INV-DBR-03): owners nuevos de cluster. Mismas reglas; solo 0034 concede su membresia a consent_owner.
 * ADR-010 PR-3: 0035 crea el esquema platform y sus objetos con SET LOCAL ROLE de platform_schema_owner, membership_owner y grant_owner
 * (patron 0027); la allowlist es POR ROL (una entrada que el rol no usa se marca obsoleta).
 */
export const ADR010_OWNER_ROLES: readonly string[] = ["platform_schema_owner", "membership_owner", "grant_owner", "case_state_owner", "transition_owner"];
const M0034 = "db/migrations/0034_adr010_cluster_roles.sql";
const M0035 = "db/migrations/0035_adr010_platform_schema.sql";
export const ADR010_OWNER_ALLOWLIST_BY_ROLE: Readonly<Record<string, Readonly<Record<string, readonly UsageKind[]>>>> = {
  // 0034: GRANT <owner> TO consent_owner WITH INHERIT FALSE, SET TRUE (Q-15 c, transitorio IT0B; PR-7 lo revoca en REAL_DATA).
  // 0035 (PR-3): SET LOCAL ROLE para crear el esquema platform (platform_schema_owner) y sus tablas/funciones (membership_owner, grant_owner).
  platform_schema_owner: { [M0034]: ["grant-membership"], [M0035]: ["set-role"] },
  membership_owner: { [M0034]: ["grant-membership"], [M0035]: ["set-role"] },
  grant_owner: { [M0034]: ["grant-membership"], [M0035]: ["set-role"] },
  // Sin otros caminos: PR-5 (case_state_owner, transition_owner) y PR-7 amplian esta allowlist con revision (CODEOWNERS).
  case_state_owner: { [M0034]: ["grant-membership"] },
  transition_owner: { [M0034]: ["grant-membership"] },
};
/** Compatibilidad: allowlist uniforme (solo 0034), usada por tests que pasan su propia lista para todos los roles. */
export const ADR010_OWNER_ALLOWLIST: Readonly<Record<string, readonly UsageKind[]>> = {
  [M0034]: ["grant-membership"],
};

/** Extensiones que pueden ejecutar SQL / abrir sesiones (el checker se ignora a si mismo y a su test, ver SELF_EXCLUDED). */
export const SCANNED_EXT_RE = /\.(sql|ts|tsx|mts|js|cjs|mjs|sh|ya?ml)$/;
export const SELF_EXCLUDED: readonly string[] = [
  "tools/spec-checks/integrity-owner-checker.ts",
  "tests/unit/spec-checks/integrity-owner-check.test.ts",
];

interface RoleRegexes { readonly role: string; readonly setRole: RegExp; readonly setConfig: RegExp }
function regexesFor(role: string): RoleRegexes {
  const r = String.raw`["'\`]?${role}["'\`]?`;
  return {
    role,
    setRole: new RegExp(String.raw`\bSET\s+(?:LOCAL\s+|SESSION\s+)?ROLE\s+${r}(?![\w$])`, "gi"),
    setConfig: new RegExp(String.raw`\bset_config\s*\(\s*'role'\s*,\s*'${role}'`, "gi"),
  };
}
const INTEGRITY_RE = regexesFor("integrity_owner");
const SECURITY_EVENT_RE = regexesFor("security_event_owner");
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

function findUsagesFor(rx: RoleRegexes, path: string, text: string): Usage[] {
  const t = stripComments(path, text);
  const lineOf = (idx: number): number => t.slice(0, idx).split("\n").length;
  const found: Usage[] = [];
  for (const re of [rx.setRole, rx.setConfig]) {
    for (const m of t.matchAll(re)) found.push({ kind: "set-role", line: lineOf(m.index ?? 0) });
  }
  for (const m of t.matchAll(GRANT_RE)) {
    // `GRANT <lista> TO ...`: solo cuenta si el rol es uno de los roles concedidos (no el destinatario).
    const granted = (m[1] ?? "").split(",").map((s) => s.trim().replace(/^["'`]|["'`]$/g, "").toLowerCase());
    if (granted.includes(rx.role)) found.push({ kind: "grant-membership", line: lineOf(m.index ?? 0) });
  }
  return found;
}

function checkUsageFor(
  rx: RoleRegexes,
  ticket: string,
  files: readonly SourceFile[],
  allowlist: Readonly<Record<string, readonly UsageKind[]>>,
  excluded: readonly string[],
): string[] {
  const errors: string[] = [];
  const byPath = new Map(files.map((f) => [f.path, f]));
  for (const f of files) {
    if (excluded.includes(f.path) || !SCANNED_EXT_RE.test(f.path)) continue;
    const allowed = allowlist[f.path] ?? [];
    for (const u of findUsagesFor(rx, f.path, f.text)) {
      if (!allowed.includes(u.kind)) {
        errors.push(`${rx.role}: ${f.path}:${u.line} usa ${u.kind} fuera de la allowlist (${ticket})`);
      }
    }
  }
  for (const [path, kinds] of Object.entries(allowlist)) {
    const f = byPath.get(path);
    if (!f) { errors.push(`${rx.role}: allowlist obsoleta, no existe ${path}`); continue; }
    const used = new Set(findUsagesFor(rx, path, f.text).map((u) => u.kind));
    for (const k of kinds) if (!used.has(k)) errors.push(`${rx.role}: allowlist obsoleta, ${path} ya no usa ${k}`);
  }
  return errors;
}

export function findUsages(path: string, text: string): Usage[] {
  return findUsagesFor(INTEGRITY_RE, path, text);
}

export function checkIntegrityOwnerUsage(
  files: readonly SourceFile[],
  allowlist: Readonly<Record<string, readonly UsageKind[]>> = INTEGRITY_OWNER_ALLOWLIST,
  excluded: readonly string[] = SELF_EXCLUDED,
): string[] {
  return checkUsageFor(INTEGRITY_RE, "CA-142; residual P1, cierre CA-144", files, allowlist, excluded);
}

/** SEC-CNS-021 PR-1 (INV-21-06): usos de `SET ROLE security_event_owner` / GRANT de su membresia fuera de la allowlist. */
export function findSecurityEventOwnerUsages(path: string, text: string): Usage[] {
  return findUsagesFor(SECURITY_EVENT_RE, path, text);
}

export function checkSecurityEventOwnerUsage(
  files: readonly SourceFile[],
  allowlist: Readonly<Record<string, readonly UsageKind[]>> = SECURITY_EVENT_OWNER_ALLOWLIST,
  excluded: readonly string[] = SELF_EXCLUDED,
): string[] {
  return checkUsageFor(SECURITY_EVENT_RE, "SEC-CNS-021 INV-21-06; CA-146", files, allowlist, excluded);
}

/** ADR-010 PR-2: usos de `SET ROLE <owner nuevo>` / GRANT de su membresia fuera de la allowlist. Una entrada de la allowlist vale para cada owner. */
export function findAdr010OwnerUsages(role: string, path: string, text: string): Usage[] {
  return findUsagesFor(regexesFor(role), path, text);
}

export function checkAdr010OwnerUsage(
  files: readonly SourceFile[],
  allowlist: Readonly<Record<string, readonly UsageKind[]>> | undefined = undefined,
  excluded: readonly string[] = SELF_EXCLUDED,
  roles: readonly string[] = ADR010_OWNER_ROLES,
): string[] {
  return roles.flatMap((role) =>
    checkUsageFor(regexesFor(role), "ADR-010 PR-2/PR-3; INV-DBR-03", files, allowlist ?? ADR010_OWNER_ALLOWLIST_BY_ROLE[role] ?? ADR010_OWNER_ALLOWLIST, excluded));
}
