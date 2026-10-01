-- scope: database
-- Gobierna: CA-124 (H09), ADR-002 §2/§8, ADR-006 §1/§4-§6, common.spec.yaml (ledgerEnvelope,
-- GRD-CM-11, INV-CM-02), DEC-BR-014 §4 (solo datos sintéticos), SEC-CNS-012 (P1-5).
--
-- Esquemas, función de tenant, privilegios por defecto y catálogo inmutable de la base.
-- El runner la ejecuta como consent_owner (SET LOCAL ROLE) en una sola transacción.
-- Aún NO crea tablas de agregado, ledger ni tenant_resolve.*: llegan en PR-B/PR-C/PR-D.

-- Nada de CREATE (ni uso implícito) para PUBLIC en el esquema public (P1-3: los roles de
-- runtime no crean objetos en ningún esquema).
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION consent_owner;
CREATE SCHEMA IF NOT EXISTS integrity AUTHORIZATION consent_owner;
CREATE SCHEMA IF NOT EXISTS ops AUTHORIZATION consent_owner;
CREATE SCHEMA IF NOT EXISTS tenant_resolve AUTHORIZATION tenant_resolve_owner;

-- P1-2: ninguna función nueva es ejecutable por PUBLIC; el EXECUTE se concede uno por uno.
ALTER DEFAULT PRIVILEGES FOR ROLE consent_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- P2-5: consent_owner solo puede SET ROLE tenant_resolve_owner (sin INHERIT), y ALTER DEFAULT
-- PRIVILEGES FOR ROLE exige herencia: se ejecuta como el propio dueno, sin FOR ROLE.
SET LOCAL ROLE tenant_resolve_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
SET LOCAL ROLE consent_owner;

-- Uso de esquemas (solo USAGE: ningún CREATE). tenant_resolve solo para app_rw, que llamará
-- a las funciones SECURITY DEFINER (P1-2); sin ningún grant sobre sus tablas.
GRANT USAGE ON SCHEMA app, integrity, ops TO app_rw, worker, platform_rw;
SET LOCAL ROLE tenant_resolve_owner;
GRANT USAGE ON SCHEMA tenant_resolve TO app_rw;
SET LOCAL ROLE consent_owner;

-- Tenant de la transacción: NULL (sin tenant) => las policies devuelven 0 filas y el WITH
-- CHECK falla. Lo fija unit-of-work.ts con set_config('app.tenant_id', $1, true).
CREATE FUNCTION app.current_tenant_id() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog, pg_temp
  AS $$ SELECT NULLIF(pg_catalog.current_setting('app.tenant_id', true), '')::uuid $$;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO app_rw, worker, platform_rw;

-- Catálogo de la base (GRD-CM-11, ADR-002 §8): fila única, inmutable, fijada al aprovisionar.
-- El servicio no arranca si no es SYNTHETIC / environment no permitido (startup-checks.ts).
-- environment: GUC consent.environment fijado por el runner (por defecto LOCAL; CI corre
-- como LOCAL, OPEN-CM-07). PRODUCTION está fuera del CHECK (NOT PROVISIONED, ADR-003 §2).
CREATE TABLE ops.db_catalog (
  id           boolean     PRIMARY KEY DEFAULT true CONSTRAINT db_catalog_single_row CHECK (id),
  data_class   text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT db_catalog_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  environment  text        NOT NULL CONSTRAINT db_catalog_environment_allowed CHECK (environment IN ('LOCAL', 'DEV', 'STAGING')),
  provisioned_at timestamptz NOT NULL DEFAULT pg_catalog.now()
);

INSERT INTO ops.db_catalog (environment)
VALUES (COALESCE(NULLIF(pg_catalog.current_setting('consent.environment', true), ''), 'LOCAL'));

CREATE FUNCTION ops.db_catalog_immutable() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  RAISE EXCEPTION 'ops.db_catalog es inmutable (GRD-CM-11, ADR-002 §8)' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER db_catalog_no_update_delete
  BEFORE UPDATE OR DELETE ON ops.db_catalog
  FOR EACH ROW EXECUTE FUNCTION ops.db_catalog_immutable();
CREATE TRIGGER db_catalog_no_truncate
  BEFORE TRUNCATE ON ops.db_catalog
  FOR EACH STATEMENT EXECUTE FUNCTION ops.db_catalog_immutable();
-- ENABLE ALWAYS: también bloquea con session_replication_role = replica. El dueño (NOLOGIN)
-- o un superusuario aún pueden quitarlos por DDL; por eso el dueño no hace login y el
-- migrador queda fuera del proceso web (diseño de CA-124, §3).
ALTER TABLE ops.db_catalog ENABLE ALWAYS TRIGGER db_catalog_no_update_delete;
ALTER TABLE ops.db_catalog ENABLE ALWAYS TRIGGER db_catalog_no_truncate;

GRANT SELECT ON ops.db_catalog TO app_rw, worker, platform_rw;
