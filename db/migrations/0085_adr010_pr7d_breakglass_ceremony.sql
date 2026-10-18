-- scope: cluster-post
-- Gobierna: ADR-010 rev. 6 §4.5.4 / Q13 (breakglass.ceremony: registro de ceremonias sin purga ni personas), §4.5.3 (vigilancia, F-PR7-03), fila PR-7 de §10; decisiones de Carlos del 2026-10-16 (C-4, C-5: LEGAL DECISION sobre
-- retencion de logs de ceremonia; C-9); specs/db-roles.spec.yaml rev. 0.8 (breakglass_log_owner, integrity_chain_verifier). Regla de Carlos (2026-10-01): las migraciones mergeadas no se editan.
--
-- Esquema `breakglass` (dueño breakglass_log_owner) y `breakglass.ceremony`: UNA fila por ceremonia de break-glass (db/ceremonies/open.sql la inserta como superusuario del cluster; close.sql registra closed_at). Minimizacion: sin tenant_id, sin
-- personas, sin datos del dominio: solo una referencia opaca, la ventana, un codigo de motivo cerrado y el ticket (Jira CA). Sin purga (como el ledger; LEGAL DECISION C-5: Carlos la acepto como los logs de ceremonia).
-- Append-only (trigger ENABLE ALWAYS): solo se admite UN UPDATE por fila, el que fija closed_at (NULL -> instante, resto de columnas intacto); DELETE y TRUNCATE se rechazan. El superusuario del cluster puede deshabilitar el trigger: residual
-- root/superusuario (R-03/R-16), cubierto por la vigilancia (breakglass-watch) y por la ancla externa de PR-7f (aun no implementada); NO es una garantia contra root.
-- Ventana P-46 <= 60 min: CHECK en la tabla (valid_until > opened_at y <= opened_at + 60 min).
--
-- Corre como SUPERUSUARIO del deploy en la fase `cluster-post` (F-PR7D-08, revision de seguridad del PR #109): el esquema y la tabla los crea el superusuario con SET LOCAL ROLE breakglass_log_owner, SIN que consent_owner (el
-- migrador) sea miembro de ese rol en ningun momento. Antes (scope database) consent_owner recibia una membresia SET transitoria en CADA deploy y podia alterar breakglass.ceremony (DISABLE TRIGGER, DELETE/UPDATE, CREATE POLICY,
-- GRANT INSERT a si mismo); ahora no puede asumir el rol ni tiene USAGE/CREATE en el esquema. Idempotente (se re-ejecuta en cada deploy). Las aserciones exactas (dueño, tgenabled = 'A' en los 2 triggers, RLS forzada, UNA policy,
-- ACL exacta) las hace database-level.ts (checkDatabaseLevel: deploy, startup y vigilancia), no un bloque SQL de esta migracion. USAGE y SELECT por columnas de breakglass.ceremony para integrity_chain_verifier (vigilancia de
-- break-glass, T-8): solo opened_at, valid_until, closed_at y la referencia opaca; el rol no recibe ningun otro privilegio sobre el esquema.

CREATE SCHEMA IF NOT EXISTS breakglass AUTHORIZATION breakglass_log_owner;

SET LOCAL ROLE breakglass_log_owner;

CREATE TABLE IF NOT EXISTS breakglass.ceremony (
  ceremony_ref text        NOT NULL CONSTRAINT ceremony_pkey PRIMARY KEY
                           CONSTRAINT ceremony_ref_shape CHECK (ceremony_ref ~ '^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$'),
  opened_at    timestamptz NOT NULL DEFAULT pg_catalog.now(),
  valid_until  timestamptz NOT NULL,
  reason_code  text        NOT NULL CONSTRAINT ceremony_reason_code CHECK (reason_code IN ('DDL_LEDGER', 'DDL_SCHEMA', 'PRINCIPAL_BOOTSTRAP', 'INCIDENT_RECOVERY', 'REHEARSAL')),
  ticket_ref   text        NOT NULL CONSTRAINT ceremony_ticket_shape CHECK (ticket_ref ~ '^CA-[0-9]{1,6}$'),
  closed_at    timestamptz,
  CONSTRAINT ceremony_window CHECK (valid_until > opened_at AND valid_until <= opened_at + interval '60 minutes'),
  CONSTRAINT ceremony_closed_after_open CHECK (closed_at IS NULL OR closed_at >= opened_at)
);

CREATE OR REPLACE FUNCTION breakglass.ceremony_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $guard$
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.closed_at IS NULL AND NEW.closed_at IS NOT NULL
     AND NEW.ceremony_ref = OLD.ceremony_ref AND NEW.opened_at = OLD.opened_at AND NEW.valid_until = OLD.valid_until
     AND NEW.reason_code = OLD.reason_code AND NEW.ticket_ref = OLD.ticket_ref THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'breakglass.ceremony es append-only: solo se admite fijar closed_at una vez (ADR-010 §4.5.4, Q13)' USING ERRCODE = 'integrity_constraint_violation';
END
$guard$;
REVOKE ALL ON FUNCTION breakglass.ceremony_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS ceremony_guard ON breakglass.ceremony;
CREATE TRIGGER ceremony_guard BEFORE UPDATE OR DELETE ON breakglass.ceremony FOR EACH ROW EXECUTE FUNCTION breakglass.ceremony_guard();
DROP TRIGGER IF EXISTS ceremony_no_truncate ON breakglass.ceremony;
CREATE TRIGGER ceremony_no_truncate BEFORE TRUNCATE ON breakglass.ceremony FOR EACH STATEMENT EXECUTE FUNCTION breakglass.ceremony_guard();
ALTER TABLE breakglass.ceremony ENABLE ALWAYS TRIGGER ceremony_guard;
ALTER TABLE breakglass.ceremony ENABLE ALWAYS TRIGGER ceremony_no_truncate;

ALTER TABLE breakglass.ceremony ENABLE ROW LEVEL SECURITY;
ALTER TABLE breakglass.ceremony FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ceremony_watch_select ON breakglass.ceremony;
CREATE POLICY ceremony_watch_select ON breakglass.ceremony FOR SELECT TO integrity_chain_verifier USING (true);

REVOKE ALL ON SCHEMA breakglass FROM PUBLIC;
REVOKE ALL ON breakglass.ceremony FROM PUBLIC;
GRANT USAGE ON SCHEMA breakglass TO integrity_chain_verifier;
GRANT SELECT (ceremony_ref, opened_at, valid_until, closed_at) ON breakglass.ceremony TO integrity_chain_verifier;

RESET ROLE;
