# Subagentes

Índice de los 11 subagentes en `.claude/agents/`. Reglas completas: `CLAUDE.md`. Configuración de modelos/tiers: `agent/agents.yaml`. Routing: `docs/agentic/model-routing.md` (ADR-AI-001).

| Agente | Modelo | Cuándo usarlo |
|---|---|---|
| `medina-scout` | haiku | Buscar/inventariar hechos en repo, Notion o Jira; solo citas, nunca interpretación. |
| `medina-synth` | sonnet | Sintetizar evidencia de varias fuentes en reporte con supuestos y confianza. |
| `santos-product` | opus | Requisitos `REQ-CNS-###`, reglas de negocio `RULE-CNS-###`, borradores `DEC-CNS-###`/`DEC-BR-###`. |
| `ravena-ux` | sonnet | Flujos, estados, edge cases, copy en borrador, accesibilidad WCAG 2.2 AA, handoff Figma. |
| `gaona-measure` | sonnet | Plan de medición, taxonomía de eventos, guardrails de privacidad en analytics/observabilidad. |
| `lampone-architect` | opus | ADRs, contratos OpenAPI/AsyncAPI, JSON Schemas, state machines, decisiones de stack. |
| `lampone-security` | opus | Threat modeling, tenancy, OTP, ledger append-only, integridad criptográfica, secrets, código crítico. |
| `lampone-dev` | sonnet | Implementar código, specs YAML, contratos, migraciones a partir de spec/ADR aprobado. |
| `lampone-qa` | sonnet | Tests, test plans, evidencia de calidad (`TEST-CNS-###`). |
| `auditor-contradictions` | opus | Auditar contradicciones Master Plan/Notion/requisitos/specs/código (P0/P1/P2). |
| `scribe-sync` | haiku | Crear/actualizar tickets Jira `CA` o páginas Notion a partir de contenido ya redactado. |

Ningún agente decide sobre los límites de IA del Master Plan §32 (consentimiento, OTP, apoderado, tenant, revocación, base jurídica, aprobación legal, validez de evidencia): eso se marca `LEGAL DECISION` y va a revisión humana.
