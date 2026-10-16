// Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7c), F-PR7-01 (P1 hoy; P0 antes de REAL_DATA), decision de Carlos del 2026-10-16 (C-3: inventario por catalogo con allowlist como chequeo permanente);
// specs/db-roles.spec.yaml rev. 0.7 (INV-DBR-03).
//
// Inventario por catalogo de lo que consent_owner (el migrador) controla y que otros owners ejecutan o leen (F-PR7-01, "trojan del migrador"):
//   V1  funcion de consent_owner referida por un objeto (trigger, policy, DEFAULT, CHECK, regla, indice) de una relacion de OTRO dueño, o nombrada en el cuerpo de una funcion de OTRO dueño. Esperado: ninguna.
//   V2  lo que consent_owner puede cambiar: en SUS relaciones, triggers (tgtype, tgqual, tgattr, tgargs, estado, funcion y dueño), policies (permissive, md5 de USING/WITH CHECK, roles), reglas, TODOS los DEFAULT y constraints
//       (md5 de la definicion; NOT NULL de PG18 excluido), indices con funciones de usuario, ACL de tabla (con RLS/FORCE RLS; se omite solo la autoconcesion MAINTAIN del dueño, PG17+) y huella de ACL de columnas;
//       y las funciones que posee o de los roles a los que puede hacer SET ROLE (identidad, SECURITY DEFINER, md5(prosrc), proconfig, ACL).
//   V3  dueño y ACL de los esquemas app y ops; miembros de pg_maintain (esperado: ninguno).
//   V4  tipos de usuario (dominios, enums, rangos), operadores, casts, agregados, triggers de evento, extensiones (salvo plpgsql), colaciones, conversiones y objetos de text search. Esperado: ninguno.
// La igualdad con la allowlist (consent-owner-inventory.allowlist.ts) es EXACTA y fail-closed: cualquier fila nueva o faltante falla. Cambiar la allowlist es un cambio revisado (CODEOWNERS). Lo ejecutan la
// aserción de la migracion 0082 (V1), startup-checks.ts (todos los procesos), el test TEST-CNS-1805 y el modo REAL_DATA queda BLOQUEADO mientras F-PR7-01 siga abierto (REAL_DATA_BLOCKERS).
// Detecta, NO previene: la prevencion total exige que consent_owner no sea dueño de nada (C-3 (a), antes de datos reales).

import type { Queryable } from "./pool.ts";
import { CONSENT_OWNER_INVENTORY_ALLOWLIST } from "./consent-owner-inventory.allowlist.ts";

/** Consulta del inventario: una fila `line` por hallazgo, ordenada con collation C. Solo lee catalogos publicos (corre con cualquier rol de runtime). */
export const CONSENT_OWNER_INVENTORY_SQL = `
WITH co AS (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'consent_owner'),
rels AS (
  SELECT c.oid, n.nspname::pg_catalog.text || '.' || c.relname::pg_catalog.text AS qname, c.relowner, c.relkind, c.relacl, c.relrowsecurity, c.relforcerowsecurity
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
),
crels AS (SELECT * FROM rels WHERE relowner = (SELECT oid FROM co)),
fns AS (
  SELECT p.oid, n.nspname::pg_catalog.text || '.' || p.proname::pg_catalog.text AS qname, p.proowner, p.prosecdef, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
-- (dependiente -> funcion de usuario) por pg_depend, para las clases que pueden llevar una expresion evaluada por otro rol
dep AS (
  SELECT d.classid, d.objid, f.qname AS fname, f.proowner
    FROM pg_catalog.pg_depend d JOIN fns f ON d.refclassid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.refobjid = f.oid
   WHERE d.classid IN ('pg_catalog.pg_trigger'::pg_catalog.regclass, 'pg_catalog.pg_policy'::pg_catalog.regclass, 'pg_catalog.pg_attrdef'::pg_catalog.regclass,
                       'pg_catalog.pg_constraint'::pg_catalog.regclass, 'pg_catalog.pg_rewrite'::pg_catalog.regclass, 'pg_catalog.pg_class'::pg_catalog.regclass, 'pg_catalog.pg_type'::pg_catalog.regclass)
),
-- cada objeto dependiente con la relacion a la que pertenece (o el dominio)
objs AS (
  SELECT 'trigger' AS kind, t.oid AS oid, 'pg_catalog.pg_trigger'::pg_catalog.regclass AS cls, t.tgrelid AS rel, t.tgname::pg_catalog.text AS oname FROM pg_catalog.pg_trigger t WHERE NOT t.tgisinternal
  UNION ALL SELECT 'policy', p.oid, 'pg_catalog.pg_policy'::pg_catalog.regclass, p.polrelid, p.polname::pg_catalog.text FROM pg_catalog.pg_policy p
  UNION ALL SELECT 'default', a.oid, 'pg_catalog.pg_attrdef'::pg_catalog.regclass, a.adrelid, a.adnum::pg_catalog.text FROM pg_catalog.pg_attrdef a
  UNION ALL SELECT 'constraint', c.oid, 'pg_catalog.pg_constraint'::pg_catalog.regclass, c.conrelid, c.conname::pg_catalog.text FROM pg_catalog.pg_constraint c WHERE c.conrelid <> 0
  UNION ALL SELECT 'rule', r.oid, 'pg_catalog.pg_rewrite'::pg_catalog.regclass, r.ev_class, r.rulename::pg_catalog.text FROM pg_catalog.pg_rewrite r WHERE r.rulename <> '_RETURN'
  UNION ALL SELECT 'index', i.indexrelid, 'pg_catalog.pg_class'::pg_catalog.regclass, i.indrelid, ic.relname::pg_catalog.text FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
),
refs AS (
  SELECT o.kind, o.oid, o.rel, o.oname,
         COALESCE((SELECT pg_catalog.string_agg(DISTINCT d.fname, ',' ORDER BY d.fname) FROM dep d WHERE d.classid = o.cls AND d.objid = o.oid), '') AS fnrefs
    FROM objs o
),
rows AS (
  -- V1: funcion de consent_owner referida por un objeto de una relacion de OTRO dueño (esperado: ninguna)
  SELECT 'V1|' || r.kind || '|' || rl.qname || '|' || r.oname || '|' || d.fname AS line
    FROM refs r JOIN rels rl ON rl.oid = r.rel
    JOIN dep d ON d.objid = r.oid AND d.classid = (CASE r.kind WHEN 'trigger' THEN 'pg_catalog.pg_trigger' WHEN 'policy' THEN 'pg_catalog.pg_policy' WHEN 'default' THEN 'pg_catalog.pg_attrdef'
                                                      WHEN 'constraint' THEN 'pg_catalog.pg_constraint' WHEN 'rule' THEN 'pg_catalog.pg_rewrite' ELSE 'pg_catalog.pg_class' END)::pg_catalog.regclass
   WHERE d.proowner = (SELECT oid FROM co) AND rl.relowner <> (SELECT oid FROM co)
  UNION ALL
  -- V1b: funcion de consent_owner nombrada en el cuerpo de una funcion de OTRO dueño (cuerpos plpgsql no registran dependencias)
  SELECT 'V1|body|' || g.qname || '|' || f.qname
    FROM fns g JOIN fns f ON f.proowner = (SELECT oid FROM co) AND g.proowner <> (SELECT oid FROM co)
    JOIN pg_catalog.pg_proc gp ON gp.oid = g.oid
   WHERE gp.prosrc ~ ('\m' || pg_catalog.replace(f.qname, '.', '\.') || '\M')
  UNION ALL
  -- V2: triggers, policies, reglas y objetos con funciones de usuario sobre relaciones de consent_owner
  SELECT 'V2|trigger|' || rl.qname || '|' || t.tgname::pg_catalog.text || '|' || t.tgenabled::pg_catalog.text || '|' || t.tgtype::pg_catalog.text || '|' || COALESCE(t.tgattr::pg_catalog.text, '') || '|'
         || pg_catalog.md5(COALESCE(pg_catalog.pg_get_expr(t.tgqual, t.tgrelid), '')) || '|' || pg_catalog.md5(pg_catalog.encode(t.tgargs, 'hex')) || '|' || fn.qname || '(' || fn.args || ')|' || pg_catalog.pg_get_userbyid(fn.proowner)::pg_catalog.text
    FROM pg_catalog.pg_trigger t JOIN crels rl ON rl.oid = t.tgrelid JOIN fns fn ON fn.oid = t.tgfoid WHERE NOT t.tgisinternal
  UNION ALL
  SELECT 'V2|policy|' || rl.qname || '|' || p.polname::pg_catalog.text || '|' || p.polcmd::pg_catalog.text || '|' || p.polpermissive::pg_catalog.text || '|'
         || pg_catalog.md5(COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '')) || '|' || pg_catalog.md5(COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')) || '|'
         || COALESCE((SELECT pg_catalog.string_agg(CASE x WHEN 0 THEN 'public' ELSE pg_catalog.pg_get_userbyid(x)::pg_catalog.text END, ',' ORDER BY CASE x WHEN 0 THEN 'public' ELSE pg_catalog.pg_get_userbyid(x)::pg_catalog.text END) FROM pg_catalog.unnest(p.polroles) x), '')
         || '|' || r.fnrefs
    FROM pg_catalog.pg_policy p JOIN crels rl ON rl.oid = p.polrelid JOIN refs r ON r.kind = 'policy' AND r.oid = p.oid
  UNION ALL
  SELECT 'V2|' || r.kind || '|' || rl.qname || '|' || r.oname || '|' || r.fnrefs
    FROM refs r JOIN crels rl ON rl.oid = r.rel WHERE r.kind = 'rule' OR (r.kind = 'index' AND r.fnrefs <> '')
  UNION ALL
  -- V2 TODOS los DEFAULT y constraints de relaciones de consent_owner (definicion completa; NOT NULL de PG18 en pg_constraint se excluye: contype 'n')
  SELECT 'V2|default|' || rl.qname || '|' || at.attname::pg_catalog.text || '|' || pg_catalog.md5(pg_catalog.pg_get_expr(a.adbin, a.adrelid)) || '|' || r.fnrefs
    FROM pg_catalog.pg_attrdef a JOIN crels rl ON rl.oid = a.adrelid JOIN pg_catalog.pg_attribute at ON at.attrelid = a.adrelid AND at.attnum = a.adnum JOIN refs r ON r.kind = 'default' AND r.oid = a.oid
  UNION ALL
  SELECT 'V2|constraint|' || rl.qname || '|' || c.conname::pg_catalog.text || '|' || c.contype::pg_catalog.text || '|' || pg_catalog.md5(pg_catalog.pg_get_constraintdef(c.oid)) || '|' || r.fnrefs
    FROM pg_catalog.pg_constraint c JOIN crels rl ON rl.oid = c.conrelid JOIN refs r ON r.kind = 'constraint' AND r.oid = c.oid WHERE c.contype <> 'n'
  UNION ALL
  -- V2 acl de relaciones de consent_owner (tabla y columnas)
  SELECT 'V2|acl|' || rl.qname || '|' || rl.relrowsecurity::pg_catalog.text || '|' || rl.relforcerowsecurity::pg_catalog.text || '|' || COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text || ':' || a.privilege_type || ':' || pg_catalog.pg_get_userbyid(a.grantor)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text COLLATE "C", a.privilege_type COLLATE "C", pg_catalog.pg_get_userbyid(a.grantor)::pg_catalog.text COLLATE "C")
                                                    FROM pg_catalog.aclexplode(rl.relacl) a WHERE a.grantee <> 0 AND NOT (a.privilege_type = 'MAINTAIN' AND a.grantee = rl.relowner AND a.grantor = rl.relowner)), '')
    FROM crels rl
  UNION ALL
  SELECT 'V2|colacl|' || rl.qname || '|' || pg_catalog.count(*)::pg_catalog.text || '|' || pg_catalog.md5(pg_catalog.string_agg(at.attname::pg_catalog.text || '=' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text || ':' || a.privilege_type || ':' || pg_catalog.pg_get_userbyid(a.grantor)::pg_catalog.text, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, a.privilege_type) FROM pg_catalog.aclexplode(at.attacl) a), ';' ORDER BY at.attname::pg_catalog.text COLLATE "C"))
    FROM crels rl JOIN pg_catalog.pg_attribute at ON at.attrelid = rl.oid WHERE at.attacl IS NOT NULL AND NOT at.attisdropped GROUP BY rl.qname
  UNION ALL
  -- V2 funciones que consent_owner puede cambiar: las que posee y las de roles a los que puede hacer SET ROLE (shared_fn_owner, owners de esquema): identidad, SECURITY DEFINER, md5(prosrc), proconfig y ACL
  SELECT 'V2|fn|' || pg_catalog.pg_get_userbyid(f.proowner)::pg_catalog.text || '|' || f.qname || '(' || f.args || ')|' || f.prosecdef::pg_catalog.text || '|' || pg_catalog.md5(p.prosrc) || '|' || COALESCE(p.proconfig::pg_catalog.text, '') || '|' || COALESCE(p.proacl::pg_catalog.text, '')
    FROM fns f JOIN pg_catalog.pg_proc p ON p.oid = f.oid
   WHERE f.proowner = (SELECT oid FROM co) OR (pg_catalog.pg_has_role('consent_owner', f.proowner, 'SET') AND pg_catalog.pg_get_userbyid(f.proowner)::pg_catalog.text !~ '^pg_')
  UNION ALL
  -- V3: dueño y ACL de los esquemas del dominio compartido
  SELECT 'V3|schema|' || n.nspname::pg_catalog.text || '|' || pg_catalog.pg_get_userbyid(n.nspowner)::pg_catalog.text || '|'
         || COALESCE((SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text || ':' || a.privilege_type, ',' ORDER BY pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text, a.privilege_type) FROM pg_catalog.aclexplode(n.nspacl) a), '')
    FROM pg_catalog.pg_namespace n WHERE n.nspname IN ('app', 'ops')
  UNION ALL
  -- V4: tipos, operadores, casts, agregados y triggers de evento de usuario (esperado: ninguno)
  SELECT 'V4|domain|' || t.typname::pg_catalog.text FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE t.typtype IN ('d', 'e', 'r', 'm') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL SELECT 'V4|operator|' || o.oprname::pg_catalog.text FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL SELECT 'V4|cast|' || c.castsource::pg_catalog.regtype::pg_catalog.text || '>' || c.casttarget::pg_catalog.regtype::pg_catalog.text FROM pg_catalog.pg_cast c WHERE c.oid >= 16384
  UNION ALL SELECT 'V4|aggregate|' || a.aggfnoid::pg_catalog.text FROM pg_catalog.pg_aggregate a JOIN pg_catalog.pg_proc p ON p.oid = a.aggfnoid JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL SELECT 'V4|event_trigger|' || e.evtname::pg_catalog.text FROM pg_catalog.pg_event_trigger e
  UNION ALL SELECT 'V4|extension|' || x.extname::pg_catalog.text FROM pg_catalog.pg_extension x WHERE x.extname <> 'plpgsql'
  UNION ALL SELECT 'V4|collation|' || n.nspname::pg_catalog.text || '.' || c.collname::pg_catalog.text FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid = c.collnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL SELECT 'V4|conversion|' || n.nspname::pg_catalog.text || '.' || c.conname::pg_catalog.text FROM pg_catalog.pg_conversion c JOIN pg_catalog.pg_namespace n ON n.oid = c.connamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL SELECT 'V4|tsconfig|' || n.nspname::pg_catalog.text || '.' || c.cfgname::pg_catalog.text FROM pg_catalog.pg_ts_config c JOIN pg_catalog.pg_namespace n ON n.oid = c.cfgnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL SELECT 'V4|tsdict|' || n.nspname::pg_catalog.text || '.' || c.dictname::pg_catalog.text FROM pg_catalog.pg_ts_dict c JOIN pg_catalog.pg_namespace n ON n.oid = c.dictnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL SELECT 'V4|tsparser|' || n.nspname::pg_catalog.text || '.' || c.prsname::pg_catalog.text FROM pg_catalog.pg_ts_parser c JOIN pg_catalog.pg_namespace n ON n.oid = c.prsnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL SELECT 'V4|tstemplate|' || n.nspname::pg_catalog.text || '.' || c.tmplname::pg_catalog.text FROM pg_catalog.pg_ts_template c JOIN pg_catalog.pg_namespace n ON n.oid = c.tmplnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  -- V3: miembros de pg_maintain (PG17+): ningun rol gobernado ni de runtime (esperado: ninguno)
  UNION ALL SELECT 'V3|pg_maintain|' || pg_catalog.pg_get_userbyid(m.member)::pg_catalog.text FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid WHERE r.rolname = 'pg_maintain'
)
SELECT line FROM rows ORDER BY line COLLATE "C"
`;

/** Diferencias entre el inventario real y la allowlist (vacio = coincide). Solo nombres de objeto y de rol. */
export function diffInventory(actual: readonly string[], allowlist: readonly string[] = CONSENT_OWNER_INVENTORY_ALLOWLIST): string[] {
  const problems: string[] = [];
  const count = (xs: readonly string[]): Map<string, number> => {
    const m = new Map<string, number>();
    for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1);
    return m;
  };
  const want = count(allowlist);
  const have = count(actual);
  for (const [line, n] of have) if (n > (want.get(line) ?? 0)) problems.push(`fuera de la allowlist (F-PR7-01): ${line}${n - (want.get(line) ?? 0) > 1 || want.has(line) ? " (repetida)" : ""}`);
  for (const [line, n] of want) if (n > (have.get(line) ?? 0)) problems.push(`falta respecto de la allowlist (F-PR7-01): ${line}`);
  return problems;
}

/** Lee el inventario real (ordenado). */
export async function readConsentOwnerInventory(db: Queryable): Promise<string[]> {
  const r = await db.query<{ line: string }>(CONSENT_OWNER_INVENTORY_SQL);
  return r.rows.map((x) => x.line);
}

/** Verifica el inventario contra la allowlist; devuelve las diferencias (vacio = ok). */
export async function checkConsentOwnerInventory(db: Queryable, allowlist: readonly string[] = CONSENT_OWNER_INVENTORY_ALLOWLIST): Promise<string[]> {
  return diffInventory(await readConsentOwnerInventory(db), allowlist);
}
