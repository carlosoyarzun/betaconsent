-- scope: database
-- Gobierna: specs/state-machines/invitation.spec.yaml I9 (CancelInvitation, reasonCode SUBJECT_MISMATCH_REPORTED, habilitado en IT0; "pendingPersistence" PC-1 de la proyeccion
-- staffInvitationStatus), contracts/openapi/consent-it0.openapi.yaml API-CNS-128 (POST /decision/subject-mismatch), UX-CNS-003 (flujo del invitado v2: "No es mi estudiante"),
-- D-06 (Carlos, 2026-10-14: cablear "No es mi estudiante" a la ruta existente), migracion 0019 (vista app.staff_roster_invitation_status), TEST-CNS-1076 (CHECK == ramas del CASE).
-- 0010 y 0019 estan mergeadas y son inmutables (regla de Carlos, 2026-10-01): este cambio va en migracion nueva.
--
-- Que cambia:
--  1) CHECK invitation_state_enum admite 'CANCELLED' (estado terminal de I9). Ningun otro estado nuevo (EXPIRED sigue sin persistir: I8 perezosa).
--  2) La vista app.staff_roster_invitation_status (CREATE OR REPLACE, mismas columnas, mismo dueno staff_roster_owner, mismos grants/ACL) suma el estado CANCELLED con la regla
--     PC-1 (Carlos, opcion b): una invitacion CANCELLED se muestra SENT hasta expires_at y luego CLOSED_WITHOUT_DECISION (sin revelar que el apoderado reporto "no es mi estudiante");
--     sin expires_at (no ocurre: I2 lo fija) cae en CLOSED_WITHOUT_DECISION para no dar NULL (503). La prioridad por (alumno, contexto) trata CANCELLED vigente como no terminal efectiva
--     (prioridad 0, desempate created_at DESC: una invitacion nueva posterior manda) y CANCELLED vencida como cerrada (prioridad 2).
--     findActiveBySubject (GRD-IV-01) ya excluye CANCELLED: el colegio puede reinvitar al alumno correcto.
--  3) $assert$ final con el estado exacto resultante (CHECK y ramas del CASE).
-- Sin cambio de semantica de consentimiento/revocacion/elegibilidad ni de grants: la vista conserva dueno, security_barrier, columnas y SELECT solo para staff_roster_reader.
-- Idempotente: DROP CONSTRAINT IF EXISTS + ADD, CREATE OR REPLACE VIEW (preserva ACL y dueno).

-- 1. CHECK de estado (dueno: consent_owner) -------------------------------------------------------------------------------------------------
ALTER TABLE app.invitation DROP CONSTRAINT IF EXISTS invitation_state_enum;
ALTER TABLE app.invitation ADD CONSTRAINT invitation_state_enum
  CHECK (state IN ('DRAFT', 'READY', 'SENT', 'OPENED', 'VERIFIED', 'COMPLETED', 'DECLINED', 'CANCELLED'));

-- 2. Vista (dueno: staff_roster_owner). CREATE OR REPLACE exige ser dueno y CREATE sobre el esquema: se concede solo dentro de esta tx (igual que 0019). ----
GRANT CREATE ON SCHEMA app TO staff_roster_owner;
SET LOCAL ROLE staff_roster_owner;
CREATE OR REPLACE VIEW app.staff_roster_invitation_status
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
    WHEN inv.state IN ('SENT', 'OPENED', 'VERIFIED', 'CANCELLED') AND inv.expires_at > pg_catalog.now() THEN 'SENT'
    WHEN inv.state IN ('READY', 'SENT', 'OPENED', 'VERIFIED', 'CANCELLED') AND inv.expires_at <= pg_catalog.now() THEN 'CLOSED_WITHOUT_DECISION'
    WHEN inv.state = 'CANCELLED' AND inv.expires_at IS NULL THEN 'CLOSED_WITHOUT_DECISION'
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
       WHEN i.state IN ('SENT', 'OPENED', 'VERIFIED', 'CANCELLED') AND i.expires_at > pg_catalog.now() THEN 0
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
SET LOCAL ROLE consent_owner;
REVOKE CREATE ON SCHEMA app FROM staff_roster_owner;

-- 3. Aserciones del estado resultante --------------------------------------------------------------------------------------------------------
DO $assert$
DECLARE
  v_check text;
  v_view  text;
  v_owner name;
BEGIN
  SELECT pg_catalog.pg_get_constraintdef(oid) INTO v_check
    FROM pg_catalog.pg_constraint WHERE conname = 'invitation_state_enum' AND conrelid = 'app.invitation'::regclass;
  IF v_check IS NULL OR v_check NOT LIKE '%CANCELLED%' THEN
    RAISE EXCEPTION '0043: invitation_state_enum no admite CANCELLED';
  END IF;
  SELECT pg_catalog.pg_get_viewdef('app.staff_roster_invitation_status'::regclass, true) INTO v_view;
  IF v_view NOT LIKE '%CANCELLED%' THEN
    RAISE EXCEPTION '0043: la vista app.staff_roster_invitation_status no nombra CANCELLED';
  END IF;
  SELECT pg_catalog.pg_get_userbyid(c.relowner) INTO v_owner FROM pg_catalog.pg_class c WHERE c.oid = 'app.staff_roster_invitation_status'::regclass;
  IF v_owner <> 'staff_roster_owner' THEN
    RAISE EXCEPTION '0043: la vista debe seguir siendo de staff_roster_owner (es de %)', v_owner;
  END IF;
  IF pg_catalog.has_schema_privilege('staff_roster_owner', 'app', 'CREATE') THEN
    RAISE EXCEPTION '0043: staff_roster_owner conserva CREATE sobre app';
  END IF;
  IF pg_catalog.has_table_privilege('app_rw', 'app.staff_roster_invitation_status', 'SELECT')
     OR NOT pg_catalog.has_table_privilege('staff_roster_reader', 'app.staff_roster_invitation_status', 'SELECT') THEN
    RAISE EXCEPTION '0043: ACL de la vista alterada (solo staff_roster_reader puede leerla)';
  END IF;
END
$assert$;
