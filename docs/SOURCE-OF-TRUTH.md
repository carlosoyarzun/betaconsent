# Source of Truth

Estado: VIGENTE (DEC-BR-011, 2026-09-23)

## DEC-BR-011

Notion "Consent App" es la fuente de verdad del **conocimiento humano** del proyecto (decisiones, requisitos discutidos, contexto, reglas de negocio en discusión). Este repositorio es fuente de verdad **solo de lo ejecutable**: specs, contratos, código, tests y evidencia de runtime. Los 34 subdominios `docs/` descritos en Master Plan §56 **no se crean** en el repo; ese conocimiento vive en Notion.

## Qué vive en Notion

Hub "Consent App" (páginas 00–16): decisiones `DEC-BR-###`, ADRs en discusión, workstreams `BR-##`, gates G0–G9, contexto, research, estrategia, producto, experiencia, contenido, accesibilidad, dominio, datos, privacidad, legal-compliance, identity-trust, medición, calidad, release, pilot, learning, governance.

## Qué vive en el repo (ejecutable)

`specs/`, `contracts/`, `ai/`, `traceability/`, `registers/`, `evidence/`, `tests/`, `infra/`, `db/`, `src/`, más `agent/` (config de subagentes) y `docs/` reducido a: Master Plan, protocolo del estudio, referencia legal (`docs/legal/ley-21719.md`), reglas de agentes (`docs/agentic/`).

## Precedencia (Master Plan §35)

```text
MASTER PLAN
  ↓
DECISIONS
  ↓
LEGAL / PRODUCT / PRIVACY / DOMAIN RULES
  ↓
REQUIREMENTS
  ↓
EXECUTABLE SPECS
  ↓
CONTRACTS
  ↓
CODE
  ↓
TESTS
  ↓
RUNTIME EVIDENCE
```

El código nunca redefine silenciosamente una regla de producto.

## Regla de conflicto

Si el repo y Notion se contradicen, prevalece Notion. Se detiene la implementación y se emite un FINDING clasificado P0/P1/P2 (Contradiction Protocol, Master Plan §36) al Supervisor; no se resuelve en silencio.
