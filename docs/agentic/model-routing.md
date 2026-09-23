# Model Routing — Consent App

**ID:** ADR-AI-001
**Estado:** PROPUESTO (requiere aprobación de Carlos Oyarzún)
**Fecha:** 2026-09-23
**Cumple:** Notion 09 → "AI Engineering & Evals" (documentar model selection, routing, prompts, tools, MCP strategy, fallback, cost/latency).
**Gobernado por:** Master Plan §32 (IA), §33 (Modelo Agentic), §36 (Contradiction Protocol); Notion 09 (AI Boundaries, Agent Guardrails & Human Gates, Agent Audit).

---

## 1. Problema

El desarrollo de Consent App es AI-native. Sin una política de routing, todo el trabajo (leer documentos, buscar en el repo, redactar specs, escribir código, crear tickets) lo ejecuta el modelo más caro de la sesión. Con Fable 5.1 como modelo de sesión, cada lectura de un archivo de 2.000 líneas cuesta 5x lo que costaría en Sonnet 5 y 10x lo que costaría en Haiku 4.5.

## 2. Decisión

**Fable 5.1 actúa exclusivamente como Supervisor/Orchestrator.** No lee documentación extensa, no busca en el repo, no escribe código, no redacta tickets. Recibe la intención del usuario, descompone, delega a subagentes con el modelo mínimo suficiente, revisa los reportes (no las fuentes) y decide.

Todo trabajo de lectura, búsqueda, redacción y ejecución se enruta a tres niveles inferiores según la naturaleza de la tarea, no según su tamaño.

## 3. Niveles de routing

| Nivel | Modelo | Precio (in/out por MTok, API) | Rol | Qué hace | Qué NO hace |
|---|---|---|---|---|---|
| T0 Supervisor | Fable 5.1 | $10 / $50 | Orchestrator | Entender intención, planificar, delegar, revisar reportes, detectar contradicciones P0, decidir, responder al usuario | Leer fuentes >150 líneas, grep/glob, editar código, redactar tickets, crear páginas |
| T1 Reasoning | Opus 5 | $5 / $25 | Diseño y juicio | ADRs, drafts de DEC/LEGAL DECISION, threat model, auditoría de contradicciones, review de código crítico (ledger, integridad, tenancy, OTP), diseño de specs | Trabajo mecánico o de volumen |
| T2 Execution | Sonnet 5 | $2 / $10 | Producción | Implementación, tests, specs YAML, contratos OpenAPI/AsyncAPI, docs, creación de tickets Jira, páginas Notion, Figma via MCP, code review rutinario | Decisiones de arquitectura o legales |
| T3 Retrieval | Haiku 4.5 | $1 / $5 | Mecánico | Inventarios, búsqueda en repo/Notion/Jira, resúmenes con citas, lint/format, verificación de docs, sincronización de estados | Síntesis con juicio, redacción final |

Regla de selección: **empezar por el nivel más bajo que pueda completar la tarea con evidencia verificable**; subir un nivel solo si el reporte del nivel inferior es insuficiente o contradictorio. Nunca bajar decisiones de T1 a T2/T3.

## 4. Mapeo a roles del Modelo Agentic (Master Plan §33 / Notion 09)

| Rol Master Plan | Subagente(s) `.claude/agents/` | Modelo | Effort |
|---|---|---|---|
| MEDINA — Research / evidence | `medina-scout` (retrieval), `medina-synth` (síntesis) | Haiku 4.5 / Sonnet 5 | low / medium |
| SANTOS — Product / requirements / decisions | `santos-product` | Opus 5 | high |
| RAVENA — UX / flows / Figma / a11y | `ravena-ux` | Sonnet 5 | medium |
| GAONA — Measurement / observability | `gaona-measure` | Sonnet 5 | medium |
| LAMPONE — Architecture / implementation / security / QA | `lampone-architect`, `lampone-security`, `lampone-dev`, `lampone-qa` | Opus 5 / Opus 5 / Sonnet 5 / Sonnet 5 | high / high / medium / medium |
| Transversal — Contradiction Protocol | `auditor-contradictions` | Opus 5 | high |
| Transversal — Sincronización Jira/Notion | `scribe-sync` | Haiku 4.5 (escala a Sonnet 5 si redacta) | low |

Los nombres MEDINA/SANTOS/RAVENA/GAONA/LAMPONE son dominios de responsabilidad y gates (Notion 09: "no requieren cinco procesos separados"); aquí se materializan como subagentes con modelo, herramientas y effort fijos.

## 5. Reglas de delegación del Supervisor

1. **Toda lectura de fuente pasa por T3.** El Supervisor recibe reportes con citas (`archivo:línea`, URL Notion, clave Jira), nunca el contenido crudo.
2. **Contexto mínimo por subagente.** Cada delegación indica archivos/páginas exactas, formato de salida y límite de líneas del reporte. Nada de "lee todo el repo".
3. **Paralelizar lo independiente.** Reconocimiento, inventarios y verificaciones se lanzan en una sola ronda.
4. **Un subagente, un dominio.** No mezclar legal con implementación en la misma tarea.
5. **Reportes, no transcripciones.** Los subagentes escriben resultados en `scratchpad/` o los devuelven como reporte estructurado; el Supervisor no abre transcripciones.
6. **Verificación cruzada barata.** Antes de aceptar un artefacto de T1/T2, un agente T3 verifica hechos (IDs, rutas, existencia de páginas) cuando el costo del error es alto.
7. **Escalada, no repetición.** Si T2 falla dos veces, escala a T1 con el diagnóstico; no reintentar en el mismo nivel.

## 6. Human gates (no delegables a ningún modelo)

Heredados de Notion 09 "Agent Guardrails & Human Gates" y Master Plan §32:

- Toda `LEGAL DECISION` y todo copy legal de producción.
- Cambios a la semántica de consentimiento, revocación, elegibilidad.
- Excepciones a principios no negociables.
- Releases con riesgo residual crítico aceptado.
- Cierre de cualquier DEC-BR-### o ADR-###.
- Cualquier `push`, merge a `main`, deploy, o borrado en Jira/Notion.

Ningún subagente puede cerrar estos ítems. El Supervisor los presenta con opciones y recomendación; Carlos decide.

## 7. Enforcement técnico

| Mecanismo | Archivo | Efecto |
|---|---|---|
| Definición de subagentes con `model`, `effort`, `tools`, `maxTurns` | `.claude/agents/*.md` | Cada rol corre en su nivel; no puede escalar por sí mismo |
| Reglas de routing en contexto | `CLAUDE.md` | El Supervisor conoce la matriz en cada sesión |
| Hook `PreToolUse` | `.claude/hooks/route-guard.sh` + `.claude/settings.json` | Bloquea en la sesión principal `Read` de archivos >150 líneas, `Grep`, `Glob`, `Edit`/`Write` fuera de `.claude/`, `CLAUDE.md`, `docs/agentic/`; devuelve al modelo el subagente al que delegar |
| Hook `SubagentStop` | idem | Registra en `agent/audit.log` agente, tarea, tokens y duración (Notion 09: Agent Audit & Traceability) |
| Tabla machine-readable | `agent/agents.yaml` | Contrato de configuración de agentes (Notion 16: `agent/agents.yaml`); la política humana prevalece sobre el YAML |

Limitación conocida: el hook distingue sesión principal de subagente por los campos de entrada del hook; si una versión de Claude Code no los expone, el guard degrada a modo advertencia (no bloquea) y lo registra.

## 8. Costo estimado

Referencia: sesión de organización de proyecto como la de 2026-09-23 (lectura de ~6.000 líneas locales + 42 páginas Notion + verificación de docs + diseño).

| Escenario | Tokens aprox. | Costo aprox. (API) |
|---|---|---|
| Todo en Fable 5.1 | ~500k in / ~40k out | ~$7.0 |
| Con routing (Fable orquesta ~60k in / 15k out; Sonnet ~250k/30k; Haiku ~200k/15k) | igual volumen | ~$2.2 |

Ahorro esperado en sesiones de lectura/organización: 60–70%. En sesiones de implementación (M10) el ahorro sube porque el código lo escribe Sonnet 5 y lo revisa Opus 5 solo en rutas críticas. Las cifras son estimaciones con precios API; en planes de suscripción el ahorro se traduce en cuota, no en dólares.

## 9. Fallback y evals

- **Fallback:** si un subagente T2 devuelve un reporte sin citas verificables o con contradicción, el Supervisor lo reenvía a T1 con el diagnóstico. Si T1 falla, la tarea vuelve al humano con finding.
- **Evals (Notion 09):** no hay IA en runtime del producto para el beta, por lo que no se requieren evals de producto. Para el proceso de desarrollo se registra por sesión: tareas delegadas, nivel usado, reintentos y escaladas (`agent/audit.log`). Revisión mensual: si más del 20% de tareas T2 escalan a T1, ajustar la matriz.

## 10. Consecuencias

- El Supervisor pierde acceso directo a fuentes; gana consistencia y presupuesto.
- Aumenta la latencia por delegación (una ronda de subagentes tarda 30–350 s); se compensa con paralelismo.
- Cada sesión deja rastro auditable, requisito de Notion 09.
- Requiere disciplina en los prompts de delegación (contexto exacto, formato de salida).

## 11. Pendientes para cerrar este ADR

- [ ] Aprobación de Carlos.
- [ ] Ticket CA para completar `agent/roles.yaml`, `permissions.yaml`, `tools.yaml`, `escalation.yaml` (Notion 16).
- [ ] Medir una sesión real con y sin routing y reemplazar las estimaciones de §8.
