# Consent App (BetaConsent)

Plataforma standalone de consentimiento. Primer caso: Estudio Beta de LectorPro (`consent.lectorpro.cl`).

**Estado: pre-build.** Solo documentación gobernante y esqueleto ejecutable vacío. Sin código de producto, specs ejecutables ni contratos aún.

## Fuentes de verdad (DEC-BR-011, 2026-09-23)

1. **Notion "Consent App"** (hub 00–16): fuente de verdad del conocimiento humano — decisiones `DEC-BR-###`/`DEC-CNS-###`, ADRs, workstreams `BR-##`, gates G0–G9.
   https://app.notion.com/p/Consent-App-3e3ee09a7fbc80b1b87ee3f73de6f10c
2. **Jira `CA`**: backlog y estado de trabajo.
   https://carlos-oyarzun.atlassian.net/jira/software/projects/CA/boards/5/backlog
3. **Este repo**: fuente de verdad SOLO de lo ejecutable (specs, contratos, código, tests, evidencia). Ver `docs/SOURCE-OF-TRUTH.md`.

En caso de conflicto entre Notion y el repo, prevalece Notion y se emite un FINDING (Contradiction Protocol, Master Plan §36).

## Cómo se trabaja con Claude Code

La sesión principal es Supervisor/Orchestrator: no lee fuentes ni escribe código directamente, delega en 11 subagentes (`.claude/agents/`) según `docs/agentic/model-routing.md` (ADR-AI-001). Ver índice en `AGENTS.md` y reglas completas en `CLAUDE.md`.

## Estructura de carpetas

- `docs/` — Master Plan, protocolo del estudio, referencia legal, reglas de agentes.
- `design-system/` — Design System genérico de LectorPro.
- `agent/` — configuración de subagentes (`agents.yaml`) y logs locales.
- `specs/`, `contracts/`, `ai/`, `traceability/`, `registers/`, `evidence/`, `tests/`, `infra/`, `db/`, `src/` — esqueleto ejecutable, vacío en pre-build (ver README de cada una).

## Referencias

- `docs/SOURCE-OF-TRUTH.md`, `APP_MANIFEST.yaml`, `AGENTS.md`, `docs/agentic/model-routing.md`.
