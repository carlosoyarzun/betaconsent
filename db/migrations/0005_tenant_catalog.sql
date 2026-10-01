-- scope: database
-- Gobierna: CA-124 (H09), PR-C; src/server/ports/tenant-catalog.port.ts, tenant-context.spec.yaml
-- GRD-TC-03, invitation.spec.yaml GRD-IV-02, common.spec.yaml GRD-CM-03/INV-CM-02 (tenant_id unica
-- clave de aislamiento, DEC-BR-015: tenant = colegio), ADR-006 §1/§4-§6, DEC-BR-014 §4 (solo datos
-- sinteticos), SEC-CNS-012 (P1-5). Regla de Carlos (2026-10-01): las migraciones 0000-0004 no se
-- editan; todo cambio SQL nuevo va desde 0005.
--
-- Catalogo del tenant (lectura): app.subject y app.school_participation. El dominio NUNCA los crea
-- ni los modifica (FINDING P1 de CA-125): app_rw solo tiene SELECT; la siembra la hace el
-- aprovisionamiento (superusuario/fixture) fuera del proceso web. Solo refs opacas, cero PII.
--
-- Guarda de email (P1-5): app.is_reserved_email(text) es la unica forma admitida de CHECK sobre
-- columnas de email (dominios reservados .test/.invalid o example.com/.org/.net). Ninguna tabla de
-- PR-C guarda email (los puertos solo guardan refs); la usaran las tablas de PR-D (invitacion,
-- OTP, caso de derechos) y tests/integration/postgres/pr-c-schema.test.ts verifica por catalogo
-- que toda columna de email del esquema la use.

CREATE FUNCTION app.is_reserved_email(p_email text) RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, pg_temp
  AS $$
    SELECT p_email ~* '^[^@[:space:]]+@([a-z0-9-]+\.)*[a-z0-9-]+\.(test|invalid)$'
        OR p_email ~* '^[^@[:space:]]+@example\.(com|org|net)$'
  $$;
GRANT EXECUTE ON FUNCTION app.is_reserved_email(text) TO app_rw, worker, platform_rw;

CREATE TABLE app.subject (
  tenant_id   uuid        NOT NULL,
  subject_ref text        NOT NULL CONSTRAINT subject_ref_len CHECK (pg_catalog.length(subject_ref) BETWEEN 1 AND 100),
  data_class  text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT subject_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at  timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT subject_pkey PRIMARY KEY (tenant_id, subject_ref)
);

CREATE TABLE app.school_participation (
  tenant_id         uuid        NOT NULL,
  participation_ref text        NOT NULL CONSTRAINT school_participation_ref_len CHECK (pg_catalog.length(participation_ref) BETWEEN 1 AND 100),
  context_ref       text        NOT NULL CONSTRAINT school_participation_context_len CHECK (pg_catalog.length(context_ref) BETWEEN 1 AND 100),
  product_ref       text        NOT NULL CONSTRAINT school_participation_product_len CHECK (pg_catalog.length(product_ref) BETWEEN 1 AND 100),
  status            text        NOT NULL CONSTRAINT school_participation_status_enum CHECK (status IN ('PENDING_AUTHORIZATION', 'ACTIVE', 'SUSPENDED', 'CLOSED')),
  data_class        text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT school_participation_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at        timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT school_participation_pkey PRIMARY KEY (tenant_id, participation_ref)
);

ALTER TABLE app.subject ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.subject FORCE ROW LEVEL SECURITY;
CREATE POLICY subject_tenant_select ON app.subject FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());

ALTER TABLE app.school_participation ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.school_participation FORCE ROW LEVEL SECURITY;
CREATE POLICY school_participation_tenant_select ON app.school_participation FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());

-- Minimo privilegio: lectura por columna; ninguna escritura para runtime.
REVOKE ALL ON app.subject, app.school_participation FROM PUBLIC;
GRANT SELECT (tenant_id, subject_ref) ON app.subject TO app_rw;
GRANT SELECT (tenant_id, participation_ref, context_ref, product_ref, status) ON app.school_participation TO app_rw;
