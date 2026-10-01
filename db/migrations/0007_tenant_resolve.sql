-- scope: database
-- Gobierna: CA-124 (H09), PR-C; ADR-006 §4 (excepcion: lookup sin tenant solo via funcion
-- SECURITY DEFINER), common.spec.yaml GRD-CM-01 (el tenant se resuelve en servidor) y INV-CM-02,
-- revocation.spec.yaml RV0 / GRD-RV-06 (tenant_resolve.recovery_token), src/server/ports/
-- tenant-resolver.port.ts, diseno postgres-design.md rev. 2 §3 y §4 P1-2, SEC-CNS-012 (P1-2, P1-5).
--
-- tenant_resolve.recovery_token (token_hash PK -> tenant_id, recovery_ref): SIN RLS (excepcion
-- ADR-006 §4: el llamador aun no tiene tenant), pero inaccesible para runtime: ningun grant sobre
-- la tabla; solo se llega por las dos funciones de este archivo.
--   * by_recovery_token_hash(hash): lookup unico (tenant_id, recovery_ref). No evalua consumo ni
--     expiracion (lo hace el dominio bajo inTenant). Desconocido => 0 filas.
--   * register_recovery_token(hash, recovery_ref): el tenant sale SIEMPRE de app.current_tenant_id()
--     (nunca de un parametro); sin tenant en la transaccion falla. Idempotente para el mismo
--     (hash, tenant, ref); un hash ya registrado para otro tenant/ref falla sin revelar a quien.
-- Ambas: dueno tenant_resolve_owner (NOLOGIN), SECURITY DEFINER, search_path = pg_catalog, pg_temp,
-- nombres calificados, EXECUTE revocado de PUBLIC y concedido solo a app_rw.

-- El dueno de tenant_resolve necesita leer el tenant de la transaccion: USAGE sobre app y EXECUTE
-- sobre app.current_tenant_id() (unico objeto de app que toca).
GRANT USAGE ON SCHEMA app TO tenant_resolve_owner;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO tenant_resolve_owner;

SET LOCAL ROLE tenant_resolve_owner;

CREATE TABLE tenant_resolve.recovery_token (
  token_hash   text        NOT NULL CONSTRAINT recovery_token_hash_shape CHECK (token_hash ~ '^[0-9a-f]{64}$') CONSTRAINT recovery_token_pkey PRIMARY KEY,
  tenant_id    uuid        NOT NULL,
  recovery_ref text        NOT NULL CONSTRAINT recovery_token_ref_len CHECK (pg_catalog.length(recovery_ref) BETWEEN 1 AND 100),
  data_class   text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT recovery_token_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at   timestamptz NOT NULL DEFAULT pg_catalog.now()
);
REVOKE ALL ON tenant_resolve.recovery_token FROM PUBLIC;

CREATE FUNCTION tenant_resolve.by_recovery_token_hash(p_token_hash text)
  RETURNS TABLE (tenant_id uuid, recovery_ref text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
    SELECT t.tenant_id, t.recovery_ref
      FROM tenant_resolve.recovery_token t
     WHERE t.token_hash = p_token_hash
  $$;
REVOKE ALL ON FUNCTION tenant_resolve.by_recovery_token_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_resolve.by_recovery_token_hash(text) TO app_rw;

CREATE FUNCTION tenant_resolve.register_recovery_token(p_token_hash text, p_recovery_ref text)
  RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_tenant uuid := app.current_tenant_id();
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant_resolve.register_recovery_token requiere app.tenant_id en la transaccion' USING ERRCODE = 'insufficient_privilege';
  END IF;
  INSERT INTO tenant_resolve.recovery_token (token_hash, tenant_id, recovery_ref)
  VALUES (p_token_hash, v_tenant, p_recovery_ref)
  ON CONFLICT (token_hash) DO NOTHING;
  IF NOT EXISTS (
    SELECT 1 FROM tenant_resolve.recovery_token t
     WHERE t.token_hash = p_token_hash AND t.tenant_id = v_tenant AND t.recovery_ref = p_recovery_ref
  ) THEN
    RAISE EXCEPTION 'tenant_resolve.register_recovery_token: hash ya registrado' USING ERRCODE = 'unique_violation';
  END IF;
END
$$;
REVOKE ALL ON FUNCTION tenant_resolve.register_recovery_token(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_resolve.register_recovery_token(text, text) TO app_rw;

SET LOCAL ROLE consent_owner;
