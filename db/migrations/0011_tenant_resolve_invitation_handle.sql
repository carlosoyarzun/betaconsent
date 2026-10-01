-- scope: database
-- Gobierna: CA-124 (H09), PR-D; ADR-006 §4 (excepcion: lookup sin tenant solo via funcion
-- SECURITY DEFINER), common.spec.yaml GRD-CM-01 (el tenant se resuelve en servidor) y INV-CM-02,
-- invitation.spec.yaml GRD-IV-05/GRD-IV-07, rights-case.spec.yaml GRD-RC-14, src/server/ports/
-- {tenant-resolver,tenant-handle}.port.ts, diseno postgres-design.md rev. 2 §3 y §4 P1-2,
-- SEC-CNS-012 (P1-2, P1-5). Mismo patron que 0007 (recovery_token).
--
-- tenant_resolve.invitation_token (token_hash PK -> tenant_id, invitation_ref) y
-- tenant_resolve.handle (handle_hash PK -> tenant_id, chain_ref, revoked_decision_ref): SIN RLS
-- (excepcion ADR-006 §4: el llamador aun no tiene tenant), pero inaccesibles para runtime: ningun
-- grant sobre las tablas; solo se llega por las funciones de este archivo.
--   * by_invitation_token_hash / by_handle_hash: lookup unico. Desconocido => 0 filas. No evaluan
--     expiracion ni estado de la invitacion (lo hace el dominio bajo inTenant); el handle rotado
--     ya no resuelve (port: "desconocido, rotado o expirado" => null).
--   * register_invitation_token / register_handle / rotate_handle: el tenant sale SIEMPRE de
--     app.current_tenant_id() (nunca de un parametro); sin tenant en la transaccion fallan.
--     Idempotentes para el mismo (hash, tenant, ref); un hash ya registrado para otro tenant/ref
--     falla sin revelar a quien. rotate_handle solo afecta handles del tenant de la transaccion.
-- Todas: dueno tenant_resolve_owner (NOLOGIN), SECURITY DEFINER, search_path = pg_catalog, pg_temp,
-- nombres calificados, EXECUTE revocado de PUBLIC y concedido solo a app_rw.

SET LOCAL ROLE tenant_resolve_owner;

CREATE TABLE tenant_resolve.invitation_token (
  token_hash     text        NOT NULL CONSTRAINT invitation_token_hash_shape CHECK (token_hash ~ '^[0-9a-f]{64}$') CONSTRAINT invitation_token_pkey PRIMARY KEY,
  tenant_id      uuid        NOT NULL,
  invitation_ref text        NOT NULL CONSTRAINT invitation_token_ref_len CHECK (pg_catalog.length(invitation_ref) BETWEEN 1 AND 100),
  data_class     text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT invitation_token_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at     timestamptz NOT NULL DEFAULT pg_catalog.now()
);
REVOKE ALL ON tenant_resolve.invitation_token FROM PUBLIC;

CREATE TABLE tenant_resolve.handle (
  handle_hash          text        NOT NULL CONSTRAINT handle_hash_shape CHECK (handle_hash ~ '^[0-9a-f]{64}$') CONSTRAINT handle_pkey PRIMARY KEY,
  tenant_id            uuid        NOT NULL,
  chain_ref            text        NOT NULL CONSTRAINT handle_chain_len CHECK (pg_catalog.length(chain_ref) BETWEEN 1 AND 255),
  revoked_decision_ref text        NOT NULL CONSTRAINT handle_decision_len CHECK (pg_catalog.length(revoked_decision_ref) BETWEEN 1 AND 100),
  rotated_at           timestamptz,
  data_class           text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT handle_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at           timestamptz NOT NULL DEFAULT pg_catalog.now()
);
REVOKE ALL ON tenant_resolve.handle FROM PUBLIC;

CREATE FUNCTION tenant_resolve.by_invitation_token_hash(p_token_hash text)
  RETURNS TABLE (tenant_id uuid, invitation_ref text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
    SELECT t.tenant_id, t.invitation_ref
      FROM tenant_resolve.invitation_token t
     WHERE t.token_hash = p_token_hash
  $$;
REVOKE ALL ON FUNCTION tenant_resolve.by_invitation_token_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_resolve.by_invitation_token_hash(text) TO app_rw;

CREATE FUNCTION tenant_resolve.register_invitation_token(p_token_hash text, p_invitation_ref text)
  RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_tenant uuid := app.current_tenant_id();
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant_resolve.register_invitation_token requiere app.tenant_id en la transaccion' USING ERRCODE = 'insufficient_privilege';
  END IF;
  INSERT INTO tenant_resolve.invitation_token (token_hash, tenant_id, invitation_ref)
  VALUES (p_token_hash, v_tenant, p_invitation_ref)
  ON CONFLICT (token_hash) DO NOTHING;
  IF NOT EXISTS (
    SELECT 1 FROM tenant_resolve.invitation_token t
     WHERE t.token_hash = p_token_hash AND t.tenant_id = v_tenant AND t.invitation_ref = p_invitation_ref
  ) THEN
    RAISE EXCEPTION 'tenant_resolve.register_invitation_token: hash ya registrado' USING ERRCODE = 'unique_violation';
  END IF;
END
$$;
REVOKE ALL ON FUNCTION tenant_resolve.register_invitation_token(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_resolve.register_invitation_token(text, text) TO app_rw;

CREATE FUNCTION tenant_resolve.by_handle_hash(p_handle_hash text)
  RETURNS TABLE (tenant_id uuid, chain_ref text, revoked_decision_ref text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
    SELECT h.tenant_id, h.chain_ref, h.revoked_decision_ref
      FROM tenant_resolve.handle h
     WHERE h.handle_hash = p_handle_hash AND h.rotated_at IS NULL
  $$;
REVOKE ALL ON FUNCTION tenant_resolve.by_handle_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_resolve.by_handle_hash(text) TO app_rw;

CREATE FUNCTION tenant_resolve.register_handle(p_handle_hash text, p_chain_ref text, p_revoked_decision_ref text)
  RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_tenant uuid := app.current_tenant_id();
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant_resolve.register_handle requiere app.tenant_id en la transaccion' USING ERRCODE = 'insufficient_privilege';
  END IF;
  INSERT INTO tenant_resolve.handle (handle_hash, tenant_id, chain_ref, revoked_decision_ref)
  VALUES (p_handle_hash, v_tenant, p_chain_ref, p_revoked_decision_ref)
  ON CONFLICT (handle_hash) DO NOTHING;
  IF NOT EXISTS (
    SELECT 1 FROM tenant_resolve.handle h
     WHERE h.handle_hash = p_handle_hash AND h.tenant_id = v_tenant
       AND h.chain_ref = p_chain_ref AND h.revoked_decision_ref = p_revoked_decision_ref
  ) THEN
    RAISE EXCEPTION 'tenant_resolve.register_handle: hash ya registrado' USING ERRCODE = 'unique_violation';
  END IF;
END
$$;
REVOKE ALL ON FUNCTION tenant_resolve.register_handle(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_resolve.register_handle(text, text, text) TO app_rw;

CREATE FUNCTION tenant_resolve.rotate_handle(p_handle_hash text)
  RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $$
DECLARE
  v_tenant uuid := app.current_tenant_id();
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant_resolve.rotate_handle requiere app.tenant_id en la transaccion' USING ERRCODE = 'insufficient_privilege';
  END IF;
  UPDATE tenant_resolve.handle
     SET rotated_at = pg_catalog.now()
   WHERE handle_hash = p_handle_hash AND tenant_id = v_tenant AND rotated_at IS NULL;
END
$$;
REVOKE ALL ON FUNCTION tenant_resolve.rotate_handle(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_resolve.rotate_handle(text) TO app_rw;

SET LOCAL ROLE consent_owner;
