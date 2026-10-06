-- scope: database
-- Gobierna: CA-141 (decision de Carlos, 2026-10-06, opcion (a): login/logout de staff en un registro de eventos de seguridad
-- nuevo, separado de ops.access_log; D-4: session_ref en app.staff_session y app.case_session), specs/session.spec.yaml (GRD-SE-14,
-- INV-SE-05), INV-CM-02 (tenant_id unica clave de aislamiento), ADR-006 §4-§6. 0000-0022 no se editan (regla de Carlos tras #34).
--
-- session_ref: referencia OPACA de la sesion (UUIDv4 que genera la base) para correlacionar login <-> logout en ops.security_event
-- (0025) SIN usar el sid ni su hash (sid_hash es la clave de busqueda de la cookie: no puede vivir en un registro con otra retencion).
--   * NO es derivable del sid; NO autentica (ninguna ruta lo acepta); nunca viaja en cookie, URL, cuerpo ni logs;
--   * sin grant de columna: app_rw no lo inserta ni lo actualiza (el DEFAULT lo fija la base); el SELECT de tabla ya existente permite RETURNING;
--   * UNIQUE (tenant_id, session_ref) (todo UNIQUE de tabla TENANT incluye tenant_id);
--   * CHECK UUIDv4: mismo CHECK que su proyeccion en ops.security_event.session_ref (invariante de session.spec: toda fila de sesion
--     se proyecta a un evento valido);
--   * inmutable: el trigger de revocacion de un solo sentido tambien rechaza cambiarlo (CREATE OR REPLACE; incluye al dueno).
-- Al purgar la sesion (24 h tras exp) desaparece el unico puente sid_hash <-> session_ref.

ALTER TABLE app.staff_session
  ADD COLUMN session_ref uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
  ADD CONSTRAINT staff_session_session_ref_uuidv4 CHECK (session_ref::pg_catalog.text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT staff_session_tenant_session_ref_key UNIQUE (tenant_id, session_ref);

ALTER TABLE app.case_session
  ADD COLUMN session_ref uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
  ADD CONSTRAINT case_session_session_ref_uuidv4 CHECK (session_ref::pg_catalog.text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT case_session_tenant_session_ref_key UNIQUE (tenant_id, session_ref);

-- P2-3: session_ref dentro del trigger de inmutabilidad. Los triggers (ENABLE ALWAYS) siguen ligados a la misma funcion.
CREATE OR REPLACE FUNCTION app.staff_session_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'app.staff_session: una sesion revocada no se reactiva (CA-138)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.session_ref IS DISTINCT FROM OLD.session_ref THEN
    RAISE EXCEPTION 'app.staff_session: session_ref es inmutable (CA-141)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION app.case_session_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'app.case_session: una sesion revocada no se reactiva (CA-139)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.session_ref IS DISTINCT FROM OLD.session_ref THEN
    RAISE EXCEPTION 'app.case_session: session_ref es inmutable (CA-141)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
