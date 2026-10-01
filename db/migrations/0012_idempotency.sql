-- scope: database
-- Gobierna: CA-124 (H09), PR-E; specs/state-machines/common.spec.yaml GRD-CM-08 (idempotency_key) y
-- ERR-CM-07, src/server/ports/idempotency.port.ts, common.spec.yaml INV-CM-02 (tenant_id unica clave de
-- aislamiento), ADR-006 §1/§4-§6, DEC-BR-014 §4 (solo datos sinteticos), diseno postgres-design.md
-- rev. 2 §3 y §7 (PR-E). Regla de Carlos (2026-10-01): 0000-0011 no se editan; todo SQL nuevo desde 0012.
--
-- app.idempotency_key: respuesta almacenada de una operacion idempotente de la consola STAFF
--     (GRD-CM-08). La clave llega ya hasheada (scope_key_hash = sha256 de tenant+principal+operacion+
--     Idempotency-Key): la Idempotency-Key en claro nunca persiste. find + ejecutar + store corren en
--     la MISMA transaccion del tenant. El TTL (P-33) NO esta aprobado: expires_at lo fija el adaptador
--     con un valor de configuracion fail-closed (sin default de produccion); la base solo exige que
--     exista. Garantias de siempre: PK (tenant_id, ref), RLS ENABLE + FORCE por app.current_tenant_id(),
--     data_class = 'SYNTHETIC' (CHECK + DEFAULT, sin grant de columna), grants minimos por columna, sin
--     DELETE/TRUNCATE para runtime. Solo se guardan respuestas 2xx (CHECK).
--

CREATE TABLE app.idempotency_key (
  tenant_id      uuid        NOT NULL,
  scope_key_hash text        NOT NULL CONSTRAINT idempotency_scope_key_hash_shape CHECK (scope_key_hash ~ '^[0-9a-f]{64}$'),
  payload_hash   text        NOT NULL CONSTRAINT idempotency_payload_hash_shape CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  status         integer     NOT NULL CONSTRAINT idempotency_status_2xx CHECK (status BETWEEN 200 AND 299),
  body           jsonb       NOT NULL CONSTRAINT idempotency_body_object CHECK (pg_catalog.jsonb_typeof(body) = 'object'),
  expires_at     timestamptz NOT NULL,
  data_class     text        NOT NULL DEFAULT 'SYNTHETIC' CONSTRAINT idempotency_data_class_synthetic CHECK (data_class = 'SYNTHETIC'),
  created_at     timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT idempotency_key_pkey PRIMARY KEY (tenant_id, scope_key_hash)
);

ALTER TABLE app.idempotency_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.idempotency_key FORCE ROW LEVEL SECURITY;
CREATE POLICY idempotency_key_tenant_select ON app.idempotency_key FOR SELECT TO app_rw
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY idempotency_key_tenant_insert ON app.idempotency_key FOR INSERT TO app_rw
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY idempotency_key_tenant_update ON app.idempotency_key FOR UPDATE TO app_rw
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

REVOKE ALL ON app.idempotency_key FROM PUBLIC;
GRANT SELECT ON app.idempotency_key TO app_rw;
GRANT INSERT (tenant_id, scope_key_hash, payload_hash, status, body, expires_at) ON app.idempotency_key TO app_rw;
-- Una entrada vencida (TTL) se reemplaza al guardar; la identidad (tenant, scope_key_hash) no cambia.
GRANT UPDATE (payload_hash, status, body, expires_at) ON app.idempotency_key TO app_rw;
