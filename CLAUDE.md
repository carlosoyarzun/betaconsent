# Consent App — Reglas para Claude Code

## Qué es este proyecto
Plataforma standalone de consentimiento (primer caso: Estudio Beta de LectorPro, `consent.lectorpro.cl`).
Estado: **pre-build**. Solo existe documentación. No hay código, specs ejecutables ni contratos todavía.

## Fuentes de verdad (precedencia, Master Plan §35; DEC-BR-011 del 2026-09-23 resuelve R8/CA-82)
1. Notion "Consent App" (hub 00–16): fuente de verdad de todo el conocimiento humano: Master Plan, decisiones DEC-BR-###, ADR-###, reglas, requisitos, workstreams BR-##, gates G0–G9. Ante conflicto con cualquier copia en el repo prevalece Notion y se emite FINDING.
2. `docs/beta-consent-master-plan.md` (2.232 líneas: no leerlo entero desde la sesión principal) y `docs/LectorPro_Estudio_Beta_Protocolo_y_Metodologia_v1.0.md` (v1.1): texto íntegro autoritativo de ambos hasta importarlos a Notion (precisión DEC-BR-011, 2026-09-23); toda enmienda nace como DEC-BR en Notion y se aplica al archivo con nota de versión. Fuera de eso, el repo es fuente de verdad solo de lo ejecutable: `specs/`, `contracts/`, `agent/`, `ai/`, `traceability/`, `registers/`, `evidence/`, `tests/`, `infra/`, `db/`, `src/`. Los 34 subdominios `docs/` del §56 no se replican en el repo.
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
LEGAL DECISION y copy legal de producción · cambios a semántica de consentimiento/revocación/elegibilidad · excepciones a principios no negociables · cierre de DEC-BR-### y ADR-### · release con riesgo crítico aceptado · merge de ramas a `main`, deploy, borrados en Jira/Notion.
Excepción (Carlos, 2026-09-23): `git push` de commits de docs/config a `main` no requiere confirmación; se reporta el hash. Nunca force-push.

## Contradiction Protocol (Master Plan §36)
Contradicción spec↔code, requirement↔UX, law↔product, privacy↔analytics, security↔architecture, contract↔implementation → detener, clasificar P0/P1/P2, emitir FINDING. P0 nunca se resuelve en silencio.

## Convenciones
- IDs: `REQ-CNS-###`, `RULE-CNS-###`, `UX-CNS-###`, `PRIV-CNS-###`, `SEC-CNS-###`, `API-CNS-###`, `TEST-CNS-###`, `DEC-CNS-###`; en Notion además `DEC-BR-###`, `ADR-###`, `BR-##`.
- No hay implementación sin REQ/spec/ADR gobernante citado en la tarea.
- No hay release sin tests y evidencia.
- Cero PII en URLs, logs, analytics, tickets y prompts. No usar RUT por defecto.
- Idioma de trabajo: español. Código, identificadores y YAML en inglés.
- Commits: Conventional Commits en español (`docs:`, `feat:`, `spec:`, `adr:`, `test:`, `chore:`).

## Estado documental (2026-09-25)
Gates según Notion "Build Readiness Checklist" (medición del 2026-09-23; G4 pasó a REOPENED el 2026-09-25): G1 75% · G2 0% · G3 27% · G4 REOPENED · G5 0% · G6 0%.
Aceptadas por Carlos el 2026-09-25: DEC-BR-014 (Iteración 0), DEC-BR-015 (tenant = colegio), DEC-BR-016 (boundaries, partes IT0), DEC-BR-017 (revocation & recovery); ADR-001/002/006 "ACCEPTED — scope IT0 sintético" y ADR-003 aceptado como comparación sin proveedor elegido (PRODUCTION NOT PROVISIONED), en revisión por Carlos: deployment target de IT0 = infraestructura propia (patrón studio.lectorpro.cl), proveedor cloud diferido (FINDING P1, 2026-09-25). No asumir AWS ni ningún proveedor; SM-CNS-001 v6, SEC-CNS-005, SEC-CNS-006.
Iteración 0 (DEC-BR-014): etapa de producto no canónica, solo datos sintéticos; G-IT0-ENTRY (E1–E6) y G-IT0-EXIT (X1–X8). Épica Jira CA-115 (historias CA-116…CA-135).
Invariantes vigentes: `tenant_id` es la única clave de aislamiento (nunca `organization_*`); `eligibility_to_participate != eligibility_to_revoke`.
Bloqueantes: P0 del enlace (DEC-BR-003) bloquea todo uso de datos personales reales; LD-17 bloquea staging (X2); las DEC-BR-001…013 que siguen abiertas en Notion Open Decisions (p.ej. DEC-BR-003, DEC-BR-008) y ADR-004/005/007…011 sin aprobar; cero specs/contratos escritos.
