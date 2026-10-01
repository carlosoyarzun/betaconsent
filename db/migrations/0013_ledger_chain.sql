-- scope: database
-- Gobierna: CA-128 / DEC-BR-014 rev. 8 §3 X6 (Carlos, 2026-10-01: aplicar X6 tal como esta escrito:
-- subconjunto IT0 de ADR-011 / S4-16 = triggers de inmutabilidad, recomputacion de la cadena
-- SHA-256 por tenant y lista blanca; HMAC y ancla quedan para ADR-011/DEC-BR-009),
-- common.spec.yaml ledgerEnvelope (payloadHash, previousEventHash, eventHash; payloadPolicy:
-- lista blanca por eventType), revocation.spec GRD-RV-19/ERR-RV-13, DEC-BR-017 §6, INV-CM-01.
-- No edita 0002 (mergeada): todo es ALTER.
--
-- Cadena por tenant. El ADAPTADOR calcula los hashes dentro de la tx de append, bajo un lock por
-- tenant (pg_advisory_xact_lock); la base los hace cumplir de forma estructural:
--   * chain_seq: orden total por tenant (1, 2, 3...), UNIQUE (tenant_id, chain_seq);
--   * UNIQUE (tenant_id, previous_event_hash): dos eslabones no pueden extender el mismo
--     predecesor (sin bifurcaciones aunque se saltee el lock);
--   * forma sha256 hex de los tres hashes y todo-o-nada de las cuatro columnas;
--   * lista blanca de event_type (espejo de src/server/modules/common/ledger-event-types.ts).
-- La recomputacion (verifyLedgerChain) esta en src/server/modules/common/ledger-chain.ts.
--
-- Filas previas a esta migracion (solo datos sinteticos LOCAL, DEC-BR-014 §4): NO se rellenan
-- (el trigger de inmutabilidad lo impide y una canonicalizacion en SQL duplicaria la del codigo).
-- Quedan con las cuatro columnas NULL y fuera de la cadena: la cadena de cada tenant arranca en su
-- primer append posterior (previous_event_hash = 64 ceros). El CHECK `audit_event_chain_required`
-- es NOT VALID a proposito: no se valida contra esas filas, pero SI rechaza todo INSERT nuevo sin
-- cadena, de modo que no se puede evadir el verificador insertando filas sin eslabon.

ALTER TABLE integrity.audit_event
  ADD COLUMN chain_seq           bigint,
  ADD COLUMN payload_hash        text,
  ADD COLUMN previous_event_hash text,
  ADD COLUMN event_hash          text;

ALTER TABLE integrity.audit_event
  ADD CONSTRAINT audit_event_chain_seq_positive CHECK (chain_seq >= 1),
  ADD CONSTRAINT audit_event_payload_hash_shape CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT audit_event_previous_hash_shape CHECK (previous_event_hash ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT audit_event_event_hash_shape CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT audit_event_chain_all_or_none CHECK (
    (chain_seq IS NULL) = (payload_hash IS NULL)
    AND (chain_seq IS NULL) = (previous_event_hash IS NULL)
    AND (chain_seq IS NULL) = (event_hash IS NULL)
  ),
  ADD CONSTRAINT audit_event_chain_required CHECK (chain_seq IS NOT NULL) NOT VALID,
  ADD CONSTRAINT audit_event_chain_seq_unique UNIQUE (tenant_id, chain_seq),
  ADD CONSTRAINT audit_event_previous_hash_unique UNIQUE (tenant_id, previous_event_hash);

-- Lista blanca de tipos de evento (X6). Fuera de la lista: 23514. Fuente: contracts/schemas/
-- ledger-event-payloads.schema.json ($defs menos x-disabled-in-it0 = CONSENT_EXPIRED, CONSENT_SUPERSEDED,
-- DECISION_CONTESTED) + TRANSITORIOS + seed LOCAL. Espejo de src/server/modules/common/ledger-event-types.ts.
--   * TRANSITORIOS (OTP_*, MANAGEMENT_TOKEN_ROTATED, RECOVERY_TOKEN_ISSUED): eventos del stream SECURITY
--     (security-event-payloads.schema.json) que hoy el dominio emite al ledger; common.spec.yaml:141 dice que
--     ese stream vive en ops.security_event y "no es ledger de consentimiento". Se migraran fuera del ledger
--     cuando exista esa tabla (migracion nueva); quitarlos hoy romperia OTP y recuperacion.
--   * Seed LOCAL (TENANT_SEEDED, SCHOOL_PARTICIPATION_SEEDED): sin $def en el contrato; solo con actor FIXTURE.
ALTER TABLE integrity.audit_event
  ADD CONSTRAINT audit_event_event_type_allowlist CHECK (event_type IN (
    'INVITATION_CREATED', 'INVITATION_READY', 'INVITATION_SENT', 'INVITATION_TOKEN_ROTATED', 'INVITATION_OPENED',
    'INVITATION_VERIFIED', 'INVITATION_COMPLETED', 'INVITATION_DECLINED', 'INVITATION_EXPIRED', 'INVITATION_CANCELLED',
    'DECISION_MAKER_CHANNEL_VERIFIED',
    'CONTEXT_INFORMATION_VIEWED', 'CONSENT_VERSION_VIEWED', 'DECISION_MAKER_AUTHORITY_DECLARED', 'SUBJECT_CONFIRMED',
    'PURPOSE_DECISION_RECORDED', 'CONSENT_GRANTED', 'CONSENT_DECLINED', 'RECEIPT_CREATED', 'CONSENT_REVOKED',
    'REVOCATION_REQUESTED', 'REVOCATION_VERIFIED', 'REVOCATION_CONFIRMED', 'REVOCATION_DOWNSTREAM_EMITTED',
    'REVOCATION_DELIVERED', 'DOWNSTREAM_ERASURE_ATTESTED', 'REVOCATION_FAILED', 'REVOCATION_ESCALATED',
    'RIGHTS_CASE_OPENED', 'RIGHTS_CASE_CONTACTING', 'RIGHTS_CASE_CLOSED',
    'TENANT_STATUS_CHANGED', 'SCHOOL_PARTICIPATION_STATUS_CHANGED', 'ENROLLMENT_STATUS_CHANGED',
    -- TRANSITORIOS (stream SECURITY)
    'OTP_ISSUED', 'OTP_FAILED', 'OTP_LOCKED', 'OTP_EXPIRED', 'OTP_BUDGET_EXHAUSTED',
    'MANAGEMENT_TOKEN_ROTATED', 'RECOVERY_TOKEN_ISSUED',
    -- Seed LOCAL
    'TENANT_SEEDED', 'SCHOOL_PARTICIPATION_SEEDED'
  )),
  ADD CONSTRAINT audit_event_seed_only_fixture CHECK (
    event_type NOT IN ('TENANT_SEEDED', 'SCHOOL_PARTICIPATION_SEEDED') OR actor_type = 'FIXTURE'
  );

-- El servicio aporta las cuatro columnas de la cadena (las calcula el adaptador); el resto de
-- columnas decididas por la base sigue sin grant. Los triggers de inmutabilidad de 0002 no se
-- tocan: siguen ENABLE ALWAYS y aplican tambien al dueno / consent_migrator y a superusuario.
GRANT INSERT (chain_seq, payload_hash, previous_event_hash, event_hash)
  ON integrity.audit_event TO app_rw;

-- P2-1: el eventHash (v=2) cubre occurred_at y environment. El adaptador los lee (now() de la tx y
-- ops.catalog_environment()) en la misma tx y los inserta explicitos; por eso app_rw recibe INSERT SOLO sobre
-- esas dos columnas, y la base fuerza que no se puedan falsear: environment = catalogo, occurred_at = now()
-- (inicio de la tx). NOT VALID: las filas previas a 0013 se crearon con el default y no se revalidan.
GRANT INSERT (occurred_at, environment) ON integrity.audit_event TO app_rw;
ALTER TABLE integrity.audit_event
  ADD CONSTRAINT audit_event_environment_is_catalog CHECK (environment = ops.catalog_environment()) NOT VALID,
  ADD CONSTRAINT audit_event_occurred_at_is_now CHECK (occurred_at = pg_catalog.now()) NOT VALID;
