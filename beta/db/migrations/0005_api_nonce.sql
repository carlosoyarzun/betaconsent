-- Gobierna: DEC de Carlos "Reconstrucción mínima" (2026-10-19), plan v2 H1-08 (API-CNS-001); DEC-BR-022 rev. 2 (b)/(c).
-- record_api_nonce: registra el nonce de una llamada firmada de LectorPro y purga los vencidos (acotado) en la misma transacción.
-- Devuelve true si el nonce era nuevo; false si ya se había visto (replay). La ventana de firma es ±60 s: un nonce de más de 5 minutos ya no puede reaparecer
-- con timestamp válido, así que purgarlo no abre un replay. consent_app no recibe DELETE: solo esta función (dueño) borra.

CREATE FUNCTION app.record_api_nonce(p_key_id text, p_nonce text)
  RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  DELETE FROM app.api_nonce n
   WHERE n.ctid IN (SELECT x.ctid FROM app.api_nonce x
                     WHERE x.tenant_id = app.current_tenant_id() AND x.seen_at < pg_catalog.now() - interval '5 minutes' LIMIT 200);
  INSERT INTO app.api_nonce (key_id, nonce) VALUES (p_key_id, p_nonce) ON CONFLICT (tenant_id, key_id, nonce) DO NOTHING;
  RETURN FOUND;
END
$fn$;

REVOKE ALL ON FUNCTION app.record_api_nonce(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.record_api_nonce(text, text) TO consent_app;
