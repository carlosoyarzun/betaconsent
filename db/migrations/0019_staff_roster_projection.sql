-- scope: database
-- Gobierna: API-CNS-116 (GET /staff/roster), REQ-CNS-036 AC-04..AC-09 (AC-05, AC-06), UX-CNS-005, DEC-BR-019
-- (Notion), diseno api-cns-116-staff-list-design.md rev. 2 §5/§6, SEC-CNS-018 rev. 2 (R1), invitation.spec
-- INV-IV-09, common.spec INV-CM-02 (tenant_id unica clave de aislamiento), GRD-CM-12/P-40 (reloj de la BD),
-- ADR-006 §1/§4-§6, DEC-BR-014 §4 (solo datos sinteticos). Regla de Carlos (2026-10-01): 0000-0017 no se editan.
-- Requiere 0018 (roles staff_roster_owner / staff_roster_reader, scope cluster).
--
-- Proyeccion del colegio: una fila por (alumno, contexto) con el estado OPERATIVO de la invitacion ya
-- COLAPSADO en la base (D1/D9: sin sentido de la decision, sin apertura ni verificacion):
--   * la vista pertenece a staff_roster_owner (security_invoker = false, security_barrier = true) y es lo
--     unico que el lector puede consultar; app_rw NO tiene SELECT sobre la vista ni sobre `state`
--     de las tablas que no sea por las policies de siempre: el SELECT del GET corre tras
--     SET LOCAL ROLE staff_roster_reader (src/infra/adapters/postgres/staff-roster.adapter.ts);
--   * columnas de la vista: subject_ref, context_ref, active_enrollment_participation_ref, staff_status. Nunca
--     invitation_ref, state, expires_at, recipient_channel_ref, token_hash, bound_decision_maker_ref,
--     consent_version ni timestamps;
--   * sin JOIN a consent_decision, receipt, revocation, rights_case, otp, ledger ni outbox: el camino SQL es el
--     mismo para GRANTED y DECLINED y una revocacion no cambia nada (el test lo verifica por pg_depend);
--   * reloj unico = pg_catalog.now() (instante de la tx del GET), nunca un parametro del llamador;
--   * staff_status = CASE sin rama ELSE (pg_get_viewdef lo muestra como ELSE NULL::text): un estado sin rama da NULL y el GET responde 503 (T-11 compara las ramas del
--     CASE con el CHECK invitation_state_enum; un estado nuevo hace fallar el test hasta actualizar la vista).
-- Prioridad por (alumno, contexto) [PC-2, Carlos 2026-10-02]: (1) manda la invitacion no terminal efectiva
-- (DRAFT, o READY/SENT/OPENED/VERIFIED no expirada); (2) si no, cualquier decision (COMPLETED/DECLINED);
-- (3) si no, la cerrada mas reciente. Desempate created_at DESC, invitation_ref COLLATE "C" DESC.
-- [PC-1, Carlos]: SUBJECT_MISMATCH_REPORTED se mostrara SENT hasta expires_at cuando CANCELLED persista (futuro).

GRANT USAGE ON SCHEMA app TO staff_roster_owner, staff_roster_reader;
-- Las tablas base se leen con los privilegios del dueno de la vista, pero las FUNCIONES del cuerpo de la vista y de las
-- policies se ejecutan con los privilegios de quien consulta: el lector tambien necesita EXECUTE (solo lee el GUC).
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO staff_roster_owner, staff_roster_reader;

-- SELECT por columna para el dueno de la vista (nunca recipient_channel_ref, token_hash,
-- bound_decision_maker_ref ni consent_version). participation_ref de school_participation solo se usa para
-- enlazar cada matricula activa con su contexto.
GRANT SELECT (tenant_id, invitation_ref, context_ref, subject_ref, state, expires_at, created_at)
  ON app.invitation TO staff_roster_owner;
GRANT SELECT (tenant_id, subject_ref) ON app.subject TO staff_roster_owner;
GRANT SELECT (tenant_id, subject_ref, participation_ref, state) ON app.enrollment TO staff_roster_owner;
GRANT SELECT (tenant_id, participation_ref, context_ref) ON app.school_participation TO staff_roster_owner;

-- FORCE RLS sigue activo en las cuatro tablas: una policy por tabla base, solo para el dueno de la vista.
CREATE POLICY invitation_roster_owner_select ON app.invitation FOR SELECT TO staff_roster_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY subject_roster_owner_select ON app.subject FOR SELECT TO staff_roster_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY enrollment_roster_owner_select ON app.enrollment FOR SELECT TO staff_roster_owner
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY school_participation_roster_owner_select ON app.school_participation FOR SELECT TO staff_roster_owner
  USING (tenant_id = app.current_tenant_id());

-- La vista se crea como consent_owner (dueno del esquema; el runner ya hizo SET ROLE) y luego se cede a
-- staff_roster_owner. ALTER ... OWNER TO exige CREATE del nuevo dueno sobre el esquema: se concede SOLO dentro de
-- esta tx y se revoca antes del COMMIT (el dueno de la vista no conserva CREATE sobre app).
CREATE VIEW app.staff_roster_invitation_status
  WITH (security_invoker = false, security_barrier = true) AS
SELECT
  s.subject_ref AS subject_ref,
  c.context_ref AS context_ref,
  en.participation_ref AS active_enrollment_participation_ref,
  CASE
    WHEN inv.invitation_ref IS NULL THEN 'NOT_INVITED'
    WHEN inv.state IN ('COMPLETED', 'DECLINED') THEN 'DECISION_RECORDED'
    WHEN inv.state = 'DRAFT' THEN 'PENDING_SEND'
    WHEN inv.state = 'READY' AND (inv.expires_at IS NULL OR inv.expires_at > pg_catalog.now()) THEN 'PENDING_SEND'
    WHEN inv.state IN ('SENT', 'OPENED', 'VERIFIED') AND inv.expires_at > pg_catalog.now() THEN 'SENT'
    WHEN inv.state IN ('READY', 'SENT', 'OPENED', 'VERIFIED') AND inv.expires_at <= pg_catalog.now() THEN 'CLOSED_WITHOUT_DECISION'
  END AS staff_status
FROM app.subject s
CROSS JOIN LATERAL (
  SELECT DISTINCT sp.context_ref
    FROM app.school_participation sp
   WHERE sp.tenant_id = s.tenant_id
     AND sp.tenant_id = app.current_tenant_id()
) c
LEFT JOIN LATERAL (
  SELECT i.invitation_ref, i.state, i.expires_at
    FROM app.invitation i
   WHERE i.tenant_id = s.tenant_id
     AND i.subject_ref = s.subject_ref
     AND i.context_ref = c.context_ref
     AND i.tenant_id = app.current_tenant_id()
   ORDER BY
     CASE
       WHEN i.state = 'DRAFT' THEN 0
       WHEN i.state = 'READY' AND (i.expires_at IS NULL OR i.expires_at > pg_catalog.now()) THEN 0
       WHEN i.state IN ('SENT', 'OPENED', 'VERIFIED') AND i.expires_at > pg_catalog.now() THEN 0
       WHEN i.state IN ('COMPLETED', 'DECLINED') THEN 1
       ELSE 2
     END,
     i.created_at DESC,
     i.invitation_ref COLLATE "C" DESC
   LIMIT 1
) inv ON true
LEFT JOIN LATERAL (
  SELECT e.participation_ref
    FROM app.enrollment e
    JOIN app.school_participation ep
      ON ep.tenant_id = e.tenant_id AND ep.participation_ref = e.participation_ref
   WHERE e.tenant_id = s.tenant_id
     AND e.subject_ref = s.subject_ref
     AND e.state = 'ACTIVE'
     AND ep.context_ref = c.context_ref
     AND e.tenant_id = app.current_tenant_id()
   ORDER BY e.participation_ref COLLATE "C"
   LIMIT 1
) en ON true
WHERE s.tenant_id = app.current_tenant_id();

GRANT CREATE ON SCHEMA app TO staff_roster_owner;
ALTER VIEW app.staff_roster_invitation_status OWNER TO staff_roster_owner;
REVOKE CREATE ON SCHEMA app FROM staff_roster_owner;

-- Desde aqui actua el nuevo dueno (consent_owner ya no es dueno de la vista): sin PUBLIC ni runtime, solo el lector.
SET LOCAL ROLE staff_roster_owner;
REVOKE ALL ON app.staff_roster_invitation_status FROM PUBLIC, app_rw, worker, platform_rw;
GRANT SELECT ON app.staff_roster_invitation_status TO staff_roster_reader;
-- El runner registra la migracion como consent_owner.
SET LOCAL ROLE consent_owner;
