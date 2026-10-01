-- scope: database
-- Gobierna: CA-124 (H09), PR-C; SEC-CNS-013 P2-7 y P2-8 (heredados de PR-B), diseno
-- postgres-design.md rev. 2 §4 P1-2/P1-6, SEC-CNS-012 (P1-2, P1-6). Regla de Carlos (2026-10-01):
-- no se editan 0000-0004; esto corrige 0003/0004 solo con migraciones nuevas.
--
-- P2-7: outbox_claimer (dueno de app.outbox_claim) tambien revoca EXECUTE de PUBLIC por defecto en
--       sus funciones futuras (ALTER DEFAULT PRIVILEGES propio; el migrador hace SET ROLE sin heredar).
-- P2-8: la policy de SELECT del worker sobre app.outbox exige ademas status = 'CLAIMED': el worker
--       solo lee el sobre de eventos que el claim ya le entrego, nunca los PENDING/DELIVERED.

SET LOCAL ROLE outbox_claimer;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
SET LOCAL ROLE consent_owner;

DROP POLICY outbox_worker_select ON app.outbox;
CREATE POLICY outbox_worker_select ON app.outbox FOR SELECT TO worker
  USING (tenant_id = app.current_tenant_id() AND status = 'CLAIMED');
