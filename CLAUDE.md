# Consent App — Reglas para Claude Code

## Qué es este proyecto
Plataforma standalone de consentimiento (primer caso: Estudio Beta de LectorPro, `consent.lectorpro.cl`).
Estado: **pre-build**. Solo existe documentación. No hay código, specs ejecutables ni contratos todavía.

## Fuentes de verdad (precedencia, Master Plan §35)
1. `docs/beta-consent-master-plan.md` (canónico, 2.232 líneas: no leerlo entero desde la sesión principal)
2. Notion "Consent App" (hub 00–16): decisiones DEC-BR-###, ADR-###, workstreams BR-##, gates G0–G9
3. Jira proyecto `CA` (backlog y estado de trabajo)
4. `docs/LectorPro_Estudio_Beta_Protocolo_y_Metodologia_v1.0.md` (protocolo del estudio)
5. `docs/legal/ley-21719.md` (referencia legal, 1.722 líneas)
6. `design-system/` (DS genérico LectorPro; reglas en `design-system/docs/agent-rules.md`)
7. Figma "Consent App" (fileKey `iA4jlqbmgVWB1Q2kLm8ZlP`, https://www.figma.com/design/iA4jlqbmgVWB1Q2kLm8ZlP/Consent-App): único archivo de diseño de pantallas. Solo `ravena-ux` escribe en él, vía el conector MCP de Figma de claude.ai (prefijo `mcp__96add947-…`), nunca el plugin `mcp__Figma__*`.
8. FigJam "Consent App - LectorPro" (fileKey `y44ySSXzNWEb5kzkIzeKdM`, https://www.figma.com/board/y44ySSXzNWEb5kzkIzeKdM/Consent-App---LectorPro): destino de todo artefacto visual que no sea pantalla (flujos, state machines, diagramas de arquitectura, mapas de eventos, journeys). Escriben `ravena-ux` y `lampone-architect`; el resto entrega el diagrama en texto (Mermaid) al Supervisor para que lo delegue.

## Routing de modelos (ADR-AI-001, `docs/agentic/model-routing.md`)
**La sesión principal es Supervisor/Orchestrator. No lee fuentes, no busca, no escribe código.**

| Necesidad | Delegar a | Modelo |
|---|---|---|
| Buscar, inventariar, extraer hechos (repo/Notion/Jira) | `medina-scout` | haiku |
| Sintetizar evidencia de varias fuentes | `medina-synth` | sonnet |
| Requisitos, reglas de negocio, borradores DEC | `santos-product` | opus |
| Flujos, estados, copy, accesibilidad, Figma | `ravena-ux` | sonnet |
| Medición, eventos, observabilidad | `gaona-measure` | sonnet |
| ADRs, arquitectura, contratos, state machines | `lampone-architect` | opus |
| Threat model, tenancy, OTP, ledger, código crítico | `lampone-security` | opus |
| Implementar código, specs YAML, docs técnicas | `lampone-dev` | sonnet |
| Tests, test plans, evidencia de calidad | `lampone-qa` | sonnet |
| Auditar contradicciones (P0/P1/P2) | `auditor-contradictions` | opus |
| Crear/actualizar tickets Jira o páginas Notion | `scribe-sync` | haiku |

Reglas del Supervisor:
- Delegar con contexto exacto (archivos, páginas, IDs), formato de salida y límite de líneas.
- Lanzar en paralelo lo independiente. Pedir reportes con citas, nunca contenido crudo.
- Si un nivel falla dos veces, escalar un nivel con diagnóstico. Nunca bajar decisiones a haiku/sonnet.
- El hook `.claude/hooks/route-guard.sh` bloquea Read >150 líneas, Grep, Glob y edición de producto en la sesión principal. Si bloquea, delegar; no buscar rodeos con Bash.
- Excepción permitida: leer/editar `CLAUDE.md`, `.claude/`, `docs/agentic/`, `agent/` y el scratchpad.

## Límites de IA (Master Plan §32, Notion 09)
Ningún modelo decide: existencia de consentimiento, aceptación del usuario, validez de OTP, autoridad legal del apoderado, autorización de tenant, revocación, base jurídica, aprobación legal, validez de evidencia.
Toda incertidumbre jurídica se marca `LEGAL DECISION` y requiere revisión humana.

## Human gates (Carlos decide, nadie más)
LEGAL DECISION y copy legal de producción · cambios a semántica de consentimiento/revocación/elegibilidad · excepciones a principios no negociables · cierre de DEC-BR-### y ADR-### · release con riesgo crítico aceptado · `git push`, merge a `main`, deploy, borrados en Jira/Notion.

## Contradiction Protocol (Master Plan §36)
Contradicción spec↔code, requirement↔UX, law↔product, privacy↔analytics, security↔architecture, contract↔implementation → detener, clasificar P0/P1/P2, emitir FINDING. P0 nunca se resuelve en silencio.

## Convenciones
- IDs: `REQ-CNS-###`, `RULE-CNS-###`, `UX-CNS-###`, `PRIV-CNS-###`, `SEC-CNS-###`, `API-CNS-###`, `TEST-CNS-###`, `DEC-CNS-###`; en Notion además `DEC-BR-###`, `ADR-###`, `BR-##`.
- No hay implementación sin REQ/spec/ADR gobernante citado en la tarea.
- No hay release sin tests y evidencia.
- Cero PII en URLs, logs, analytics, tickets y prompts. No usar RUT por defecto.
- Idioma de trabajo: español. Código, identificadores y YAML en inglés.
- Commits: Conventional Commits en español (`docs:`, `feat:`, `spec:`, `adr:`, `test:`, `chore:`).

## Estado documental (2026-09-23)
Gates según Notion "Build Readiness Checklist": G1 75% · G2 0% · G3 27% · G4 17% · G5 0% · G6 0%.
Bloqueantes: DEC-BR-001…010 abiertas, ADR-001…010 sin aprobar, cero specs/contratos escritos.
