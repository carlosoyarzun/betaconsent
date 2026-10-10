-- scope: database
-- Gobierna: SEC-CNS-021 PR-4 (aceptada por Carlos 2026-10-08; §5.2 M+5, D3, D6, D8), CA-146 (DF-10), SEC-CNS-006 rev. 5 (P-04, P-04a/b/c, P-05, P-06, P-07),
-- otp-challenge.spec.yaml (CFG-OT-BUDGET, GRD-OT-03/06/09/14, V6/V6r/V6a), ADR-002 §3, INV-21-11/12/13/14/15/17, INV-CM-02 (tenant_id unica clave de aislamiento).
-- Regla de Carlos (2026-10-01): 0000-0031 no se editan; esta migracion es nueva.
--
-- 1. ops.otp_budget (dueno security_event_owner, patron 0028/0029/0031): presupuesto de FALLOS de OTP por clave (P-04). La clave es un HMAC
--    (key_hmac, subclave HKDF propia): nunca el correo, el invitationRef ni el chainRef en claro. Ventana fija que empieza en el primer fallo
--    (window_start) y termina en expires_at (= window_start + largo de ventana). expires_at existe para que la purga P-34 de SEC-CNS-021 PR-5
--    (store 'otp_budget') pueda vencer filas sin conocer el largo de ventana; este PR NO purga ni siembra ops.retention_policy.
--    app_rw: SELECT + INSERT por columnas + UPDATE(failures, window_start, expires_at); sin DELETE/TRUNCATE. RLS por app.current_tenant_id().
--    D6 (Carlos, 2026-10-08): el tope RIGHTS DAYS_30 (P-07 / V6c) NO se aplica en este PR. El CHECK de la tabla conserva el vocabulario
--    (DAYS_30 solo para (RIGHTS, CHAIN)) por paridad con security_event_otp_shape (0029), pero ningun codigo reserva en esa ventana.
-- 2. app.invitation.otp_exhausted (V6a, GRD-OT-09/14): marca de la invitacion cuyo 3.er challenge DECISION quedo LOCKED. Monotona: solo false -> true
--    (trigger ENABLE ALWAYS). app_rw lo actualiza por columna; no es insertable (nace false). Dueno: consent_owner (sin cambio).
-- 3. app.otp_verification: marcas de envio de P-06 (D8: el envio inicial cuenta): last_sent_at, sends_window_start y sends_in_window. Las filas
--    anteriores a esta migracion quedan con last_sent_at/sends_window_start NULL y sends_in_window 0 (el dominio las trata como "sin envios
--    registrados": el primer reenvio las normaliza). app_rw: INSERT y UPDATE de estas tres columnas.
--
-- F-4 (P1, orden de locks): el orden de locks lo fija el codigo (src/server/modules/otp-challenge/otp-challenge.ts, cabecera): invitation ->
-- otp_verification -> ops.otp_budget (CHANNEL, luego INVITATION|CHAIN) -> filas nuevas (security_event, ledger). Esta migracion no agrega locks.

-- A. Como consent_owner (dueno de app.invitation / app.otp_verification): columnas, trigger y grants.
ALTER TABLE app.invitation ADD COLUMN otp_exhausted boolean NOT NULL DEFAULT false;

CREATE FUNCTION app.invitation_otp_exhausted_monotonic() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF OLD.otp_exhausted AND NOT NEW.otp_exhausted THEN
    RAISE EXCEPTION 'app.invitation.otp_exhausted es monotona (solo false -> true; GRD-OT-09)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION app.invitation_otp_exhausted_monotonic() FROM PUBLIC;

CREATE TRIGGER invitation_otp_exhausted_monotonic
  BEFORE UPDATE ON app.invitation
  FOR EACH ROW EXECUTE FUNCTION app.invitation_otp_exhausted_monotonic();
ALTER TABLE app.invitation ENABLE ALWAYS TRIGGER invitation_otp_exhausted_monotonic;

GRANT UPDATE (otp_exhausted) ON app.invitation TO app_rw;

ALTER TABLE app.otp_verification
  ADD COLUMN last_sent_at        timestamptz,
  ADD COLUMN sends_window_start  timestamptz,
  ADD COLUMN sends_in_window     smallint NOT NULL DEFAULT 0 CONSTRAINT otp_sends_in_window_nonneg CHECK (sends_in_window >= 0);
-- Marcas coherentes: ambas NULL (fila anterior a 0032) o ambas presentes con ventana <= ultimo envio. Cada rama usa IS [NOT] NULL (sin depender del orden de evaluacion).
ALTER TABLE app.otp_verification
  ADD CONSTRAINT otp_send_marks_shape CHECK (
    CASE WHEN last_sent_at IS NULL THEN sends_window_start IS NULL AND sends_in_window = 0
         ELSE sends_window_start IS NOT NULL AND sends_in_window >= 1 AND sends_window_start <= last_sent_at END);

GRANT INSERT (last_sent_at, sends_window_start, sends_in_window) ON app.otp_verification TO app_rw;
GRANT UPDATE (last_sent_at, sends_window_start, sends_in_window) ON app.otp_verification TO app_rw;

-- Para crear sus objetos security_event_owner necesita CREATE en ops (grant temporal; se revoca en C).
GRANT USAGE, CREATE ON SCHEMA ops TO security_event_owner;

-- B. Como security_event_owner: ops.otp_budget nace con ese dueno.
SET LOCAL ROLE security_event_owner;

CREATE TABLE ops.otp_budget (
  tenant_id    uuid        NOT NULL,
  scope_class  text        NOT NULL CONSTRAINT otp_budget_scope_class_enum CHECK (scope_class IN ('DECISION', 'RIGHTS')),
  key_kind     text        NOT NULL CONSTRAINT otp_budget_key_kind_enum CHECK (key_kind IN ('CHANNEL', 'INVITATION', 'CHAIN')),
  key_hmac     text        NOT NULL CONSTRAINT otp_budget_key_hmac_shape CHECK (key_hmac ~ '^[0-9a-f]{64}$'),
  key_version  smallint    NOT NULL CONSTRAINT otp_budget_key_version_pos CHECK (key_version >= 1),
  window_kind  text        NOT NULL CONSTRAINT otp_budget_window_kind_enum CHECK (window_kind IN ('DAY_1', 'DAYS_30')),
  window_start timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  failures     integer     NOT NULL CONSTRAINT otp_budget_failures_nonneg CHECK (failures >= 0),
  data_class   text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT otp_budget_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  CONSTRAINT otp_budget_pkey PRIMARY KEY (tenant_id, scope_class, key_kind, key_hmac, window_kind),
  CONSTRAINT otp_budget_window_order CHECK (expires_at > window_start),
  CONSTRAINT otp_budget_invitation_only_decision CHECK (key_kind <> 'INVITATION' OR scope_class = 'DECISION'),
  CONSTRAINT otp_budget_chain_only_rights CHECK (key_kind <> 'CHAIN' OR scope_class = 'RIGHTS'),
  CONSTRAINT otp_budget_days30_only_rights_chain CHECK (window_kind <> 'DAYS_30' OR (scope_class = 'RIGHTS' AND key_kind = 'CHAIN'))
);
-- Para la purga P-34 (PR-5): vencimiento por expires_at.
CREATE INDEX otp_budget_expires_idx ON ops.otp_budget (expires_at);

ALTER TABLE ops.otp_budget ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.otp_budget FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ops.otp_budget FROM PUBLIC;

-- Una policy por comando (sin DELETE para app_rw). Todas exigen app.current_tenant_id() (INV-CM-02).
CREATE POLICY otp_budget_tenant_select ON ops.otp_budget FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY otp_budget_tenant_insert ON ops.otp_budget FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY otp_budget_tenant_update ON ops.otp_budget FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

GRANT SELECT ON ops.otp_budget TO app_rw;
-- data_class lo fija la base (DEFAULT + CHECK); la identidad de la clave no es actualizable.
GRANT INSERT (tenant_id, scope_class, key_kind, key_hmac, key_version, window_kind, window_start, expires_at, failures) ON ops.otp_budget TO app_rw;
GRANT UPDATE (failures, window_start, expires_at) ON ops.otp_budget TO app_rw;

-- C. De vuelta como consent_owner: retiro del CREATE temporal.
SET LOCAL ROLE consent_owner;
REVOKE CREATE ON SCHEMA ops FROM security_event_owner;

-- D. Aserciones: la migracion aborta si algo no quedo como se declara (INV-21-06). Se consulta el catalogo por nombre.
DO $assert$
DECLARE
  tbl oid;
  inv oid;
  otp oid;
BEGIN
  IF pg_catalog.has_schema_privilege('security_event_owner', 'ops', 'CREATE') THEN
    RAISE EXCEPTION 'security_event_owner conserva CREATE en el esquema ops (el grant temporal no quedo revocado)';
  END IF;

  -- ops.otp_budget: dueno, ENABLE + FORCE RLS, sin acceso de consent_owner, privilegios exactos de runtime.
  SELECT c.oid INTO tbl FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'ops' AND c.relname = 'otp_budget' AND c.relkind = 'r';
  IF tbl IS NULL THEN RAISE EXCEPTION 'falta ops.otp_budget'; END IF;
  IF pg_catalog.pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = tbl)) <> 'security_event_owner' THEN
    RAISE EXCEPTION 'ops.otp_budget no pertenece a security_event_owner';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'ops' AND c.relname LIKE 'otp\_budget%' AND pg_catalog.pg_get_userbyid(c.relowner) <> 'security_event_owner') THEN
    RAISE EXCEPTION 'hay relaciones otp_budget* (indices) que no pertenecen a security_event_owner';
  END IF;
  IF NOT (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c WHERE c.oid = tbl) THEN
    RAISE EXCEPTION 'ops.otp_budget sin ENABLE/FORCE ROW LEVEL SECURITY';
  END IF;
  IF pg_catalog.has_table_privilege('consent_owner', tbl, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'consent_owner conserva privilegios sobre ops.otp_budget';
  END IF;
  IF pg_catalog.has_table_privilege('public', tbl, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'PUBLIC tiene privilegios sobre ops.otp_budget';
  END IF;
  -- app_rw: SELECT; INSERT y UPDATE exactamente por las columnas declaradas; nada de DELETE/TRUNCATE/REFERENCES/TRIGGER.
  IF NOT pg_catalog.has_table_privilege('app_rw', tbl, 'SELECT')
     OR pg_catalog.has_table_privilege('app_rw', tbl, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'app_rw debe tener SELECT sobre ops.otp_budget y ningun privilegio de tabla de escritura';
  END IF;
  IF (SELECT pg_catalog.string_agg(a.attname::pg_catalog.text, ',' ORDER BY a.attname) FROM pg_catalog.pg_attribute a
       WHERE a.attrelid = tbl AND a.attnum > 0 AND NOT a.attisdropped AND pg_catalog.has_column_privilege('app_rw', a.attrelid, a.attnum, 'INSERT'))
     IS DISTINCT FROM 'expires_at,failures,key_hmac,key_kind,key_version,scope_class,tenant_id,window_kind,window_start' THEN
    RAISE EXCEPTION 'app_rw debe poder insertar exactamente las columnas declaradas de ops.otp_budget (no data_class)';
  END IF;
  IF (SELECT pg_catalog.string_agg(a.attname::pg_catalog.text, ',' ORDER BY a.attname) FROM pg_catalog.pg_attribute a
       WHERE a.attrelid = tbl AND a.attnum > 0 AND NOT a.attisdropped AND pg_catalog.has_column_privilege('app_rw', a.attrelid, a.attnum, 'UPDATE'))
     IS DISTINCT FROM 'expires_at,failures,window_start' THEN
    RAISE EXCEPTION 'app_rw debe poder actualizar exactamente expires_at, failures y window_start de ops.otp_budget';
  END IF;
  IF pg_catalog.has_any_column_privilege('worker', tbl, 'SELECT,INSERT,UPDATE,REFERENCES')
     OR pg_catalog.has_table_privilege('worker', tbl, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     OR pg_catalog.has_any_column_privilege('platform_rw', tbl, 'SELECT,INSERT,UPDATE,REFERENCES')
     OR pg_catalog.has_table_privilege('platform_rw', tbl, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'worker o platform_rw tienen privilegios sobre ops.otp_budget';
  END IF;
  -- security_event_owner (dueno): nada para el runtime en este PR (la policy de DELETE de la purga llega con PR-5).
  -- Policies: nombre, comando y roles exactos. polcmd: a=INSERT, r=SELECT, w=UPDATE, d=DELETE.
  IF (SELECT pg_catalog.string_agg(p.polname::pg_catalog.text || ':' || p.polcmd::pg_catalog.text || ':' || (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(x), ',' ORDER BY pg_catalog.pg_get_userbyid(x)) FROM pg_catalog.unnest(p.polroles) AS x), ' ' ORDER BY p.polname)
        FROM pg_catalog.pg_policy p WHERE p.polrelid = tbl)
     IS DISTINCT FROM 'otp_budget_tenant_insert:a:app_rw otp_budget_tenant_select:r:app_rw otp_budget_tenant_update:w:app_rw' THEN
    RAISE EXCEPTION 'las policies de ops.otp_budget no son exactamente las declaradas (rol y comando)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = tbl
              AND (COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '') || COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')) NOT LIKE '%current_tenant_id()%') THEN
    RAISE EXCEPTION 'toda policy de ops.otp_budget debe exigir app.current_tenant_id()';
  END IF;

  -- app.invitation.otp_exhausted: monotona (trigger ENABLE ALWAYS), actualizable por app_rw y no insertable.
  SELECT c.oid INTO inv FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'invitation';
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_proc p ON p.oid = g.tgfoid
                  WHERE g.tgrelid = inv AND g.tgname = 'invitation_otp_exhausted_monotonic' AND g.tgenabled = 'A' AND NOT g.tgisinternal
                    AND p.proname = 'invitation_otp_exhausted_monotonic' AND (g.tgtype & 1) = 1 AND (g.tgtype & 2) = 2 AND (g.tgtype & 16) = 16) THEN
    RAISE EXCEPTION 'app.invitation: falta el trigger BEFORE UPDATE ENABLE ALWAYS de otp_exhausted';
  END IF;
  IF NOT pg_catalog.has_column_privilege('app_rw', inv, 'otp_exhausted', 'UPDATE')
     OR pg_catalog.has_column_privilege('app_rw', inv, 'otp_exhausted', 'INSERT') THEN
    RAISE EXCEPTION 'app_rw debe poder actualizar y no insertar app.invitation.otp_exhausted';
  END IF;
  IF pg_catalog.has_function_privilege('public', 'app.invitation_otp_exhausted_monotonic()', 'EXECUTE')
     OR pg_catalog.has_function_privilege('app_rw', 'app.invitation_otp_exhausted_monotonic()', 'EXECUTE') THEN
    RAISE EXCEPTION 'la funcion de trigger de otp_exhausted no debe ser ejecutable por PUBLIC ni por el runtime';
  END IF;

  -- app.otp_verification: marcas de envio P-06 para app_rw; ningun privilegio nuevo para security_event_owner (la purga solo lee tenant_id, expires_at).
  SELECT c.oid INTO otp FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'otp_verification';
  IF NOT (pg_catalog.has_column_privilege('app_rw', otp, 'last_sent_at', 'INSERT') AND pg_catalog.has_column_privilege('app_rw', otp, 'last_sent_at', 'UPDATE')
          AND pg_catalog.has_column_privilege('app_rw', otp, 'sends_window_start', 'INSERT') AND pg_catalog.has_column_privilege('app_rw', otp, 'sends_window_start', 'UPDATE')
          AND pg_catalog.has_column_privilege('app_rw', otp, 'sends_in_window', 'INSERT') AND pg_catalog.has_column_privilege('app_rw', otp, 'sends_in_window', 'UPDATE')) THEN
    RAISE EXCEPTION 'app_rw debe poder insertar y actualizar las marcas de envio de app.otp_verification';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
              WHERE a.attrelid = otp AND a.attnum > 0 AND NOT a.attisdropped AND a.attname NOT IN ('tenant_id', 'expires_at')
                AND pg_catalog.has_column_privilege('security_event_owner', a.attrelid, a.attnum, 'SELECT,INSERT,UPDATE,REFERENCES')) THEN
    RAISE EXCEPTION 'security_event_owner tiene privilegios sobre columnas de app.otp_verification distintas de tenant_id y expires_at';
  END IF;

  -- consent_owner sigue siendo el unico miembro de security_event_owner.
  IF (SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(m.member), ',' ORDER BY pg_catalog.pg_get_userbyid(m.member))
        FROM pg_catalog.pg_auth_members m WHERE m.roleid = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = 'security_event_owner'))
     IS DISTINCT FROM 'consent_owner' THEN
    RAISE EXCEPTION 'consent_owner debe ser el unico miembro de security_event_owner';
  END IF;
END
$assert$;
