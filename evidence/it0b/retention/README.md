# Evidencia de retencion P-34 (SEC-CNS-021 PR-3)

Estado: PENDIENTE de generar. El valor de 30 dias es un PLACEHOLDER (LD-15 abierta, LEGAL DECISION); no es un valor aprobado definitivo.

Cuando exista STAGING (IT0b), esta carpeta recibe, con datos sinteticos:
- Export de `ops.purge_run` (filas resumen, `tenant_id IS NULL`) de una corrida real de `retention-purge-cli.ts` por store.
- La consulta de post-condicion: `SELECT count(*) FROM ops.security_event WHERE occurred_at < now() - interval '<N> days'` = 0 (idem `app.otp_verification.expires_at`, `ops.purge_run.finished_at`).

La prueba de que la purga ocurrio son los conteos de `ops.purge_run` (`eligible_before = deleted_count`, `remaining_older_than_cutoff = 0`). Es verificable por conteo, no criptografica (R-21-2).
