# evidence/

Evidencia de runtime, append-only, sobre consentimiento, revocación y decisiones
críticas.

Gobierna: `SEC-CNS-###`, `PRIV-CNS-###`.

Estado: vacía de evidencia de dominio (pre-build; el ledger de integridad de
consentimiento/revocación llega con ADR-002 y el código de `src/`).

## Evidencia de test runs (CA-118/H03)

`tools/testing/run-tests.ts` escribe, por cada corrida de una capa (`unit`,
`integration`, `contract`), un archivo JSON Lines en `evidence/test-runs/`
(`<layer>-<runId>.jsonl`), formato `test-evidence/v1`: ver `specs/test-framework.spec.yaml`
(`evidenceFormat`) para el esquema completo. Cero PII: solo IDs de test, ruta relativa
del archivo, resultado, duración y, si falla, código de error + mensaje truncado.

**`evidence/test-runs/` NO se commitea** (está en `.gitignore`). Decisión y
justificación completas en `specs/test-framework.spec.yaml` (`evidenceFormat.storageDecision`);
en resumen: es evidencia de una corrida de CI/desarrollo, no la evidencia de runtime de
consentimiento/revocación que este directorio gobierna para producción, y commitear un
archivo por corrida de cada PR no aporta valor de auditoría a largo plazo frente al
riesgo de historial de git. En CI, cada job sube su archivo como artefacto de GitHub
Actions con retención de 30 días (`retention-days: 30` en `.github/workflows/tests.yml`,
no la retención por defecto del repositorio); en LOCAL queda en disco para depuración y
puede borrarse. Revisable por Carlos/lampone-security si G-IT0-EXIT necesita evidencia
commiteada.
