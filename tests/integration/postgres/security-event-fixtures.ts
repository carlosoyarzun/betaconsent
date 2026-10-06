// Gobierna: CA-141. Apoyo de tests de Postgres (no es una migracion ni se usa fuera de tests): trigger de prueba que hace fallar el INSERT en
// ops.security_event mientras una bandera este activa, para verificar la atomicidad (TEST-CNS-1197) sobre una base desechable por archivo.

import type { Client } from "pg";

export async function installEventFailureTrigger(admin: Client): Promise<void> {
  await admin.query("CREATE TABLE IF NOT EXISTS ops.ca141_fail_flag (fail_on boolean NOT NULL)");
  const has = await admin.query("SELECT 1 FROM ops.ca141_fail_flag");
  if (has.rowCount === 0) await admin.query("INSERT INTO ops.ca141_fail_flag (fail_on) VALUES (false)");
  await admin.query("GRANT SELECT ON ops.ca141_fail_flag TO app_rw");
  await admin.query(`CREATE OR REPLACE FUNCTION ops.ca141_fail_event() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF (SELECT fail_on FROM ops.ca141_fail_flag) THEN RAISE EXCEPTION 'fallo inyectado (CA-141 test)' USING ERRCODE = 'XX000'; END IF;
      RETURN NEW;
    END $$`);
  await admin.query("DROP TRIGGER IF EXISTS ca141_fail_event ON ops.security_event");
  await admin.query("CREATE TRIGGER ca141_fail_event BEFORE INSERT ON ops.security_event FOR EACH ROW EXECUTE FUNCTION ops.ca141_fail_event()");
}
