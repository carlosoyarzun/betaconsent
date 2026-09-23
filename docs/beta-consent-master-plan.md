# Consent App — Master Plan

> Copia de referencia. Fuente de verdad: Notion (DEC-BR-011). Enmiendas registradas en Notion y no reflejadas aquí salvo P08 (DEC-BR-007) y la nota de §56 (DEC-BR-011).

**Producto:** LectorPro Consent App
**Dominio:** `consent.lectorpro.cl`
**Estado inicial:** Pre-pilot / construcción
**Modelo:** Standalone, privacy-first, spec-driven, AI-native, agent-ready
**Ámbito inicial:** Beta de LectorPro en Chile
**Usuarios principales:** apoderados/tutores, establecimientos educacionales y administradores autorizados.

---

## 1. Propósito

Consent App existe para resolver una sola pregunta de forma confiable:

> **¿Existe una autorización válida, vigente, específica, comprensible y trazable para que este estudiante participe en este estudio y para las finalidades correspondientes?**

No debe transformarse en:

* portal del estudiante;
* portal general del apoderado;
* plataforma de evaluación;
* repositorio de audio;
* sistema pedagógico;
* CRM de colegios;
* motor de IA;
* sistema de research;
* sistema académico.

La especialización es deliberada.

---

# 2. Principio arquitectónico fundamental

Consent App será **totalmente independiente de LectorPro**.

```text
LectorPro
     │
     │ API / events
     ▼
┌─────────────────────────────┐
│     CONSENT APP             │
│ consent.lectorpro.cl        │
│                             │
│ Frontend                    │
│ Backend                     │
│ Database                    │
│ Evidence Ledger             │
│ Email / OTP                 │
│ Rights Management           │
│ Audit                       │
└─────────────────────────────┘
```

Tendrá:

```text
Repositorio independiente
Base de datos independiente
Deployment independiente
Secrets independientes
Auth/verificación independiente
Observabilidad independiente
Backups independientes
Lifecycle independiente
```

No existirá:

```text
LectorPro → direct DB access → Consent App
Consent App → direct DB access → LectorPro
```

La integración será exclusivamente mediante contratos versionados.

---

# 3. Objetivos

### Objetivo primario

Obtener y mantener evidencia confiable de decisiones de consentimiento relacionadas con un estudiante y un estudio determinado.

### Objetivos secundarios

Consent App deberá permitir:

* invitar al apoderado;
* verificar su canal de contacto;
* identificar claramente al estudiante;
* explicar el estudio;
* presentar finalidades separadas;
* registrar decisiones;
* generar comprobante;
* consultar estado;
* revocar;
* gestionar solicitudes de derechos;
* demostrar históricamente qué ocurrió;
* comunicar cambios relevantes a sistemas consumidores.

---

# 4. Principios no negociables

```text
P01  Minimize before protecting.

P02  No RUT unless a documented necessity
     and legal decision explicitly require it.

P03  Email verification ≠ identity verification
     ≠ authority verification.

P04  Pseudonymized ≠ anonymous.

P05  Consent must be specific and traceable.

P06  No preselected consent choices.

P07  Revocation must be possible.

P08  Historical evidence is append-only. (precisión DEC-BR-007, 2026-09-23: aplica a la capa de integridad, sin PII directa; la capa de PII tiene supresión verificable)

P09  Current state is derived from evidence.

P10  No PII in URLs.

P11  No unnecessary PII in logs or analytics.

P12  No cross-tenant data access.

P13  No shared database with LectorPro.

P14  Critical consent decisions are deterministic.

P15  AI cannot infer consent.

P16  Security fails closed.

P17  Legal uncertainty becomes an explicit decision.

P18  No implementation without governing requirements/specs.

P19  No release without tests and evidence.

P20  Privacy Policy ≠ legal basis for every processing activity.
```

El último principio incorpora explícitamente una de las buenas prácticas que identificaste en INTEGRITIC/Letrapps.

---

# 5. Marco regulatorio

A fecha **22 de septiembre de 2026**, la Ley 21.719 está publicada pero su entrada en vigencia general está fijada para el **1 de diciembre de 2026**. ([Biblioteca del Congreso de Chile][1])

Consent App debe diseñarse desde ahora para operar bajo el régimen reformado. La nueva regulación incorpora derechos como acceso, rectificación, supresión, oposición, portabilidad y bloqueo, además de obligaciones especiales relacionadas con datos personales de niños, niñas y adolescentes. ([Biblioteca del Congreso de Chile][2])

La ley reformada establece además reglas específicas para datos de NNA y exige atender al interés superior y autonomía progresiva; para niños y niñas contempla consentimiento de padres, representantes legales o quien tenga a cargo su cuidado personal, salvo habilitación legal distinta. ([Biblioteca del Congreso de Chile][3])

Esto se traducirá en:

```text
Ley
 ↓
Legal requirements
 ↓
Product requirements
 ↓
Controls
 ↓
Specifications
 ↓
Implementation
 ↓
Tests
 ↓
Evidence
```

Toda interpretación específica debe pasar por revisión jurídica antes de producción.

---

# 6. Modelo Responsable / Encargado

No se asumirá que LectorPro, Consent App o el colegio son siempre Responsable o siempre Encargado.

Debe analizarse **por actividad de tratamiento**.

Ejemplo conceptual:

| Tratamiento            | Responsable | Encargado | Estado       |
| ---------------------- | ----------- | --------- | ------------ |
| Invitación del colegio | TBD         | TBD       | Legal review |
| Gestión de Consent App | TBD         | TBD       | Legal review |
| Evaluación de lectura  | TBD         | TBD       | Legal review |
| Procesamiento IA       | TBD         | TBD       | Legal review |
| Investigación          | TBD         | TBD       | Legal review |
| Entrenamiento futuro   | TBD         | TBD       | Legal review |

Debe existir:

```text
CONTROLLER-PROCESSOR-ROLE-MATRIX.md
LEGAL-BASIS-MATRIX.md
PROCESSING-ACTIVITIES-REGISTER.md
DATA-PROCESSING-AGREEMENT-TEMPLATE.md
```

---

# 7. Modelo de estudios

El consentimiento nunca será “para LectorPro en general”.

Debe estar ligado a un `Study`.

```text
Study
├── studyRef
├── name
├── organizationRef
├── description
├── status
├── version
├── consentTemplateRef
├── privacyNoticeVersion
├── startsAt
└── endsAt
```

Estados:

```text
DRAFT
READY
ACTIVE
PAUSED
CLOSED
ARCHIVED
```

Ejemplo:

```text
studyRef = BETA_2026_01
```

Una autorización para:

```text
BETA_2026_01
```

no debe convertirse automáticamente en autorización para:

```text
BETA_2026_02
```

---

# 8. Modelo de organización

Debe existir separación explícita entre organizaciones.

```text
Organization
     │
     ├── Studies
     │
     ├── Invitations
     │
     └── Consent Records
```

Todas las operaciones deben ocurrir dentro de contexto de tenant.

```text
authentication
      ↓
tenant resolution
      ↓
authorization
      ↓
service
      ↓
database isolation
```

Debe existir test automatizado que intente deliberadamente violar esta separación.

Objetivo:

> **0 accesos cross-tenant exitosos.**

---

# 9. Modelo de estudiante

No utilizar RUT como identificador técnico.

El colegio deberá entregar, idealmente:

```json
{
  "studyRef": "BETA_2026_01",
  "schoolRef": "SCH_83C2",
  "studentRef": "STD_7F91",
  "studentFirstName": "Martina",
  "grade": "4° básico"
}
```

Obligatorio:

```text
studyRef
schoolRef
studentRef
```

Opcional según UX/legal:

```text
studentFirstName
grade
```

No solicitar por defecto:

```text
RUT
dirección
fecha de nacimiento
diagnósticos
PIE
notas
historial académico
fotografía
documento de identidad
```

---

# 10. Modelo de apoderado

Consent App podrá solicitar directamente:

```text
Nombre
Apellidos
Email
Relación con el estudiante
Declaración de autoridad
```

Relaciones posibles:

```text
Madre
Padre
Representante legal
Persona con cuidado personal
Otro
```

El caso `Otro` puede requerir tratamiento especial.

Debe registrarse explícitamente:

> “Declaro que estoy facultado/a para autorizar la participación de este estudiante.”

Pero técnicamente:

```text
OTP verified
      ≠
civil identity proven
      ≠
legal authority proven
```

Esto debe aparecer en `TRUST-MODEL.md`.

---

# 11. Invitación

El modelo preferido para beta será:

```text
Colegio
   ↓
envía invitación
   ↓
Apoderado
   ↓
https://consent.lectorpro.cl/i/<random-token>
```

El colegio no necesita entregar inicialmente el email del apoderado a LectorPro.

El token debe ser:

* criptográficamente aleatorio;
* no predecible;
* expirable;
* revocable;
* single-purpose;
* asociado al estudio;
* asociado a una referencia pseudónima de estudiante.

Nunca:

```text
?student=Martina
?rut=12...
?email=...
```

---

# 12. Verificación de email

Flujo:

```text
Invitation
   ↓
Email entry
   ↓
OTP
   ↓
Email verified
```

Debe existir:

```text
OTP expiration
attempt limit
resend throttling
rate limiting
anti-enumeration
generic errors
audit event
```

El sistema no debe revelar si determinado email ya existe.

---

# 13. Golden Path del apoderado

```text
1 Invitation Landing
        ↓
2 Email
        ↓
3 OTP
        ↓
4 Guardian information
        ↓
5 Student confirmation
        ↓
6 Study information
        ↓
7 Consent purposes
        ↓
8 Review
        ↓
9 Decision
        ↓
10 Receipt
```

Posteriormente:

```text
Receipt
   ↓
Manage Consent
   ├── View
   ├── Rights
   └── Revoke
```

---

# 14. Pantallas mínimas

En Figma, M4 deberá cubrir como mínimo:

```text
Invitation Landing
Guardian Email
OTP Verification
Guardian Information
Student Confirmation
Student Mismatch
Study Information
Consent Overview
Purpose Details
Purpose Decisions
Review Decision
Consent Granted
Consent Declined
Consent Receipt
Existing Consent
Revocation Verification
Revocation Confirmation
Consent Revoked
Invitation Expired
Recoverable Error
Fatal Error
```

Admin:

```text
Studies
Consent Templates
Consent Versions
Invitations
Consent Status
Revocations
Rights Requests
Audit Lookup
Integrity Verification
```

---

# 15. Consentimiento

El modelo será granular.

Conceptualmente:

```text
Consent
├── participation
├── recording
├── processing
├── humanReview
├── research
└── productImprovement
```

**Estos propósitos son candidatos, no el texto legal definitivo.**

Antes del piloto deben definirse exactamente:

```text
Purpose
Legal basis
Required / optional
Data involved
Processor
Retention
Downstream consumer
Consequences of declining
```

No debe existir una finalidad sin consumidor o tratamiento claramente definido.

Particularmente:

```text
AI_TRAINING
HUMAN_REVIEW
```

no deben activarse simplemente “por si acaso”.

---

# 16. Versionado de consentimiento

Todo consentimiento debe poder reconstruirse históricamente.

```text
ConsentVersion
├── version
├── canonicalContent
├── contentHash
├── purposes
├── privacyNoticeVersion
├── approvedAt
├── approvedBy
├── legalReviewStatus
└── effectiveFrom
```

Una versión en uso se vuelve inmutable.

---

# 17. Consent Decision

Conceptualmente:

```text
ConsentDecision
├── consentId
├── organizationRef
├── studyRef
├── studentRef
├── guardianRef
├── consentVersion
├── privacyNoticeVersion
├── consentTextHash
├── purposes[]
├── authorityDeclaration
├── decidedAt
└── revokedAt?
```

---

# 18. Evidencia como dominio de primera clase

Consent App no debe almacenar únicamente:

```text
consent = true
```

Debe generar un historial de evidencia.

```text
INVITATION_CREATED
INVITATION_OPENED
GUARDIAN_EMAIL_VERIFIED
STUDENT_CONFIRMED
STUDY_INFORMATION_VIEWED
CONSENT_VERSION_VIEWED
PURPOSE_DECISION_RECORDED
CONSENT_GRANTED
CONSENT_DECLINED
RECEIPT_CREATED
CONSENT_REVOKED
RIGHTS_REQUEST_CREATED
RIGHTS_REQUEST_RESOLVED
```

---

# 19. Ledger append-only

Principio:

> **Consent records are not mutable state. They are derived state over an append-only evidence history.**

Conceptualmente:

```text
AuditEvent
├── eventId
├── eventType
├── schemaVersion
├── organizationRef
├── studyRef
├── studentRef
├── guardianRef
├── payloadHash
├── previousEventHash
├── eventHash
├── occurredAt
└── actor
```

---

# 20. Integridad criptográfica

Cadena conceptual:

```text
Canonical Event
      ↓
SHA-256
      ↓
Previous Hash
      ↓
Hash Chain
      ↓
Signature / HMAC
      ↓
Key outside DB
      ↓
KMS
      ↓
Immutable periodic anchor
```

Un hash chain solo no basta frente a un atacante con control total de la base de datos.

Debe existir:

```text
POST /internal/audit/verify-integrity
```

Resultado:

```text
VALID
```

o:

```text
INTEGRITY_FAILURE
```

---

# 21. Consent Receipt

Después de aceptar o rechazar se debe producir un comprobante.

Debe indicar:

```text
Study
Student reference/context
Consent version
Privacy notice version
Purposes
Decision per purpose
Date/time
Receipt reference
How to revoke
How to exercise rights
```

No necesita exponer IDs internos sensibles.

---

# 22. Revocación

Nunca:

```text
UPDATE consent
SET granted = false
```

como única evidencia.

Debe ocurrir:

```text
CONSENT_GRANTED
      ↓
CONSENT_REVOKED
```

con nuevo evento.

Posteriormente:

```text
Consent App
      ↓
consent.revoked
      ↓
LectorPro
      ↓
downstream remediation
```

Consent App registra la decisión; el sistema consumidor realiza las acciones sobre los datos que mantiene.

---

# 23. Derechos de titulares

Debe existir un workflow operacional de derechos.

```text
Request
 ↓
Verification
 ↓
Classification
 ↓
Processing
 ↓
Resolution
 ↓
Evidence
 ↓
Communication
```

La ley reformada contempla acceso, rectificación, supresión, oposición, portabilidad y bloqueo. También establece un procedimiento ante el responsable y reglas específicas para solicitudes de bloqueo temporal. ([Biblioteca del Congreso de Chile][4])

Esto debe convertirse en producto real y no solamente en un email publicado en una política.

---

# 24. Privacy by Design

Cada dato debe justificar:

```text
WHY
↓
PURPOSE
↓
LEGAL BASIS
↓
MINIMUM DATA
↓
RETENTION
↓
ACCESS
↓
DELETION
```

Debe existir inventario completo:

```text
Data element
Classification
Purpose
Source
Controller
Processor
Storage
Recipients
Retention
Deletion
Legal basis
```

---

# 25. Pseudonimización

Usar:

```text
studentRef
guardianRef
organizationRef
invitationRef
studyRef
```

como referencias técnicas.

Estas referencias siguen siendo datos personales cuando es posible reidentificar al titular.

Por lo tanto:

```text
Pseudonymization
≠
Anonymization
```

La tabla de correspondencias debe estar separada cuando sea viable y sometida a controles más estrictos.

---

# 26. Anonimización

Solo podrán declararse datos “anónimos” después de evaluar riesgo razonable de reidentificación.

Evaluar:

```text
School
Grade
Study
Timestamp
Rare attributes
Cross-dataset linkage
Combination uniqueness
```

Eliminar el nombre no basta.

---

# 27. Analytics

Consent App tendrá analítica extremadamente restrictiva.

Permitido:

```text
Invitation completion rate
OTP failure rate
Consent flow abandonment
Time to complete
Error rate
Revocation rate
Technical performance
```

No permitido por defecto:

```text
session replay containing consent
marketing pixels
cross-site tracking
PII analytics
full email
student name
consent text values
```

Cada evento debe pasar por:

```text
PRIVACY-SAFE-ANALYTICS.md
```

---

# 28. Seguridad

Security is Definition of Done.

Baseline:

```text
TLS
Encryption at rest
KMS
Least privilege IAM
MFA admin
Secret Manager
Token expiration
OTP throttling
Rate limiting
CSRF protection
XSS protection
CSP
HSTS
Secure cookies
Schema validation
Server-side authorization
Tenant isolation
PII redaction
Dependency scanning
SAST
Secret scanning
Container scanning
Backups
Restore tests
Incident detection
Audit logging
```

---

# 29. Fail closed

Ante ausencia o corrupción de configuraciones críticas:

```text
missing signing key
missing encryption key
invalid tenant context
invalid consent version
integrity failure
```

el sistema debe detener la operación segura, no continuar degradado silenciosamente.

---

# 30. Quality Model

Consent App se diseñará para alinearse con:

```text
ISO/IEC 25010
        ↓
software quality model

ISO/IEC 27001
        ↓
information security management readiness

ISO/IEC 27701
        ↓
privacy management alignment

ISO/IEC 29134
        ↓
privacy impact assessment

WCAG 2.2 AA
        ↓
accessibility

OWASP ASVS
        ↓
application security
```

No se declarará certificación ISO mientras no exista auditoría/certificación formal.

---

# 31. ISO 27001 readiness

Desde el comienzo se generará evidencia compatible con un futuro SGSI.

```text
ISMS/
├── ISMS-SCOPE.md
├── INFORMATION-SECURITY-POLICY.md
├── RISK-METHODOLOGY.md
├── RISK-REGISTER.md
├── RISK-TREATMENT-PLAN.md
├── STATEMENT-OF-APPLICABILITY.md
├── SECURITY-OBJECTIVES.md
├── INTERNAL-AUDIT.md
├── MANAGEMENT-REVIEW.md
└── CORRECTIVE-ACTIONS.md
```

El beta no requiere certificación formal como condición de lanzamiento.

---

# 32. IA

Consent App será **AI-native en su desarrollo**, no AI-dependent en su consentimiento.

IA puede ayudar en:

```text
Spec generation
Contradiction detection
Threat analysis
Test generation
Code review
Impact analysis
Documentation
Observability analysis
Compliance mapping
```

IA no podrá decidir:

```text
whether consent exists
whether user accepted
OTP validity
guardian legal authority
tenant authorization
revocation
legal basis
legal approval
evidence validity
```

---

# 33. Modelo Agentic

```text
MEDINA
Research / evidence
        ↓
SANTOS
Product / requirements / decisions
        ↓
RAVENA
UX / flows / Figma / accessibility
        ↓
GAONA
Measurement planning
        ↓
LAMPONE
Architecture / implementation
        ↓
Pilot
        ↓
GAONA
Measurement / findings
        ↓
SANTOS
Continue / Iterate / Stop
```

Los agentes no son autoridades jurídicas.

Cualquier `LEGAL DECISION` requiere aprobación humana.

---

# 34. Spec-Driven Development

Cadena obligatoria:

```text
Evidence
 ↓
Decision
 ↓
Requirement
 ↓
Business Rule
 ↓
UX
 ↓
Executable Spec
 ↓
Contract
 ↓
Code
 ↓
Test
 ↓
Runtime Evidence
```

IDs:

```text
REQ-CNS-###
RULE-CNS-###
UX-CNS-###
PRIV-CNS-###
SEC-CNS-###
API-CNS-###
TEST-CNS-###
DEC-CNS-###
```

Ejemplo:

```text
REQ-CNS-021
      ↓
RULE-CNS-008
      ↓
UX-CNS-014
      ↓
consent.spec.yaml
      ↓
openapi.yaml
      ↓
implementation
      ↓
TEST-CNS-092
      ↓
test evidence
```

---

# 35. Source of Truth

Precedencia:

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

El código nunca puede redefinir silenciosamente una regla del producto.

---

# 36. Contradiction Protocol

Cuando Claude o un agente detecte:

```text
spec ↔ code
requirement ↔ UX
law ↔ product
privacy ↔ analytics
security ↔ architecture
contract ↔ implementation
```

debe detener la modificación relevante y generar finding.

Clasificación:

```text
P0 — legal/privacy/security/data-integrity
P1 — product/architecture/critical UX
P2 — documentation/noncritical discrepancy
```

No resolver silenciosamente P0.

---

# 37. Integración con LectorPro

Contrato mínimo:

```text
LectorPro
    ↓
GET consent status
```

Ejemplo conceptual:

```json
{
  "studyRef": "BETA_2026_01",
  "studentRef": "STD_7F91",
  "status": "GRANTED",
  "consentVersion": "1.0",
  "purposes": {
    "evaluation": true,
    "humanReview": false,
    "aiTraining": false
  },
  "grantedAt": "..."
}
```

No retornar por defecto:

```text
guardian name
guardian email
guardian identity details
```

---

# 38. Eventos hacia LectorPro

Por ejemplo:

```text
consent.granted
consent.changed
consent.revoked
rights.requested
study.closed
```

Deben incluir:

```text
schemaVersion
eventId
organizationRef
studyRef
studentRef
occurredAt
```

más el mínimo payload necesario.

---

# 39. Idempotencia

Toda operación crítica debe soportar repetición segura.

Especialmente:

```text
Create invitation
Submit consent
Generate receipt
Revoke consent
Process webhook
Rights request
```

Un retry no debe producir doble consentimiento ni doble revocación.

---

# 40. Observabilidad

Tres capas:

```text
Technical observability
Business observability
Security observability
```

Medir:

```text
availability
latency
errors
OTP delivery
email delivery
invitation conversions
consent state transitions
webhook failures
integrity verification
tenant violations
security alerts
```

Sin exponer PII.

---

# 41. Admin

MVP administrativo:

```text
Organization
Study
Consent Template
Consent Version
Invitation
Consent Status
Revocation
Rights Request
Audit Event
Integrity Verification
```

No construir:

```text
CRM
marketing platform
school management
student management suite
```

---

# 42. Figma / Experience Design

Figma ocurre principalmente durante **M4**.

Secuencia:

```text
Requirements
 ↓
Business Rules
 ↓
Legal / Privacy constraints
 ↓
Journey
 ↓
Flows
 ↓
States
 ↓
Wireframes
 ↓
Prototype
 ↓
Usability Test
 ↓
High Fidelity
 ↓
Responsive
 ↓
Accessibility
 ↓
Design System
 ↓
Handoff
```

No comenzar por high-fidelity.

---

# 43. Accessibility

Baseline:

> **WCAG 2.2 AA**

Testear como mínimo:

```text
Keyboard
Focus
Screen reader
Labels
Errors
Contrast
Zoom
Responsive
Reduced motion
OTP entry
Consent choices
Confirmation
Revocation
```

---

# 44. Research

Medina deberá validar como mínimo:

```text
¿El apoderado entiende qué está autorizando?
¿Reconoce claramente al estudiante?
¿Distingue propósitos obligatorios y opcionales?
¿Comprende qué ocurre si rechaza?
¿Comprende cómo revocar?
¿Confía en que el mensaje proviene del colegio/LectorPro?
¿Puede completar el flujo sin ayuda?
¿Hay lenguaje legal incomprensible?
```

---

# 45. Métricas de experiencia

No optimizar “consent rate”.

Eso podría incentivar dark patterns.

Success metrics:

```text
Flow completion
Comprehension
Error-free completion
OTP success
Median completion time
Support contacts
Student mismatch incidence
Revocation usability
Accessibility success
Technical failure rate
```

Guardrails:

```text
No forced consent
No preselection
No misleading hierarchy
No unnecessary data collection
No consent manipulation
```

---

# 46. Threat Model prioritario

Escenarios obligatorios:

```text
Invitation token theft
OTP brute force
Email enumeration
Cross-tenant access
IDOR
Admin privilege escalation
PII leakage
Log leakage
Replay attacks
Webhook forgery
Consent manipulation
Historical evidence rewriting
Secret compromise
Database compromise
Malicious administrator
Vendor breach
Dependency compromise
Backup exposure
```

---

# 47. Supply Chain

Generar:

```text
SBOM
Dependency inventory
Build provenance
Signed artifacts
Container provenance
Release provenance
```

Dependencias críticas deben tener owner y proceso de actualización.

---

# 48. Vendors

Registrar:

```text
Cloud
Email provider
DNS
CDN
Monitoring
Analytics
Error reporting
Repositories
CI/CD
AI tooling
```

Para cada proveedor:

```text
Data accessed
Purpose
Region
Subprocessors
Contract
Risk
Exit strategy
```

---

# 49. Environment Strategy

```text
DEV
 ↓
STAGING
 ↓
PRODUCTION
```

Separados:

```text
DB
Secrets
Keys
Email configuration
Storage
Observability
```

No reutilizar PII de producción en development.

---

# 50. Testing mínimo

Antes de pilot:

```text
Unit
Integration
Contract
E2E
Security
Privacy
Accessibility
Tenant isolation
Evidence integrity
OTP abuse
Resilience
Backup / restore
```

Golden-path E2E:

```text
Invitation
→ Email
→ OTP
→ Guardian
→ Student
→ Study
→ Consent
→ Granted
→ Receipt
```

Y obligatoriamente:

```text
Invalid OTP
Expired OTP
Expired invitation
Rate limit
Wrong student
Decline
Partial consent
Existing consent
New consent version
Revocation
Webhook retry
Duplicate webhook
Unauthorized lookup
Cross-tenant attack
Keyboard-only flow
Screen-reader flow
```

---

# 51. Definition of Done del producto

Consent App estará lista para pilot cuando un colegio pueda:

```text
invite
   ↓
guardian verifies
   ↓
guardian identifies student
   ↓
understands study
   ↓
makes explicit decisions
   ↓
receives receipt
   ↓
can later consult/revoke
```

y simultáneamente:

```text
decision linked to study
decision version known
legal text reconstructable
evidence append-only
integrity verifiable
tenant isolation verified
rights process operational
downstream integration minimal
audit available
```

---

# 52. Zero-tolerance Pilot Gate

Antes de pilot:

```text
0 unresolved P0 security findings
0 unresolved P0 privacy findings
0 cross-tenant leaks
0 evidence integrity failures
0 unapproved production legal copy
0 undocumented critical decisions
0 critical accessibility blockers
0 uncontrolled PII logging
0 missing critical backups
```

---

# 53. Roadmap maestro

## M0 — Foundation

Crear:

```text
README
MASTER-PLAN
PRODUCT-BLUEPRINT
SOURCE-OF-TRUTH
AGENTS
CLAUDE
APP_MANIFEST
decision system
documentation map
```

**Gate G0 — Context Ready**

---

## M1 — Product Definition

Definir:

```text
Problem
Purpose
Scope
Actors
Outcomes
Requirements
Business Rules
Success Criteria
Study model
Consent model
```

**Gate G1 — Product Ready**

---

## M2 — Privacy + Legal

Definir:

```text
Data inventory
Processing activities
Legal basis matrix
Controller/processor roles
NNA rules
Guardian authority
Purpose model
Retention
Rights
Privacy notices
DPO/compliance governance
PIA
```

Todo texto legal:

```text
DRAFT — LEGAL REVIEW REQUIRED
```

hasta aprobación.

**Gate G2 — Privacy/Legal Ready**

---

## M3 — Evidence Architecture

Definir:

```text
Audit events
Append-only ledger
Hash chain
Key management
Anchoring
Integrity verification
Receipts
Revocation evidence
Audit export
```

**Gate G3 — Evidence Ready**

---

## M4 — Experience Design

Ravena produce:

```text
Information Architecture
Journey
Golden Path
Flows
State model
Wireframes
Figma
Prototype
UX validation
High fidelity
Responsive
Accessibility
Design System
```

**Gate G4 — Experience Ready**

---

## M5 — Domain Design

Formalizar:

```text
Organization
Study
Invitation
Guardian
StudentRef
Consent
ConsentVersion
ConsentDecision
Purpose
Receipt
Revocation
RightsRequest
AuditEvent
```

más:

```text
state machines
domain events
invariants
lifecycle rules
```

**Gate G5 — Domain Ready**

---

## M6 — Architecture + Security

Definir:

```text
System architecture
Data architecture
API
Identity
Tenant isolation
OTP
Email
Authorization
Infrastructure
Threat model
Security controls
Observability
Backups
DR
```

**Gate G6 — Architecture Ready**

---

## M7 — AI / Agentic Governance

Crear:

```text
AI boundaries
Agent responsibilities
Agent permissions
Agent tools
Agent handoffs
Human approval gates
Agent audit
AI evals
AI risk model
```

**Gate G7 — Agent System Ready**

---

## M8 — Executable Specs + Contracts

Convertir decisiones en:

```text
specs/*.yaml
contracts/openapi.yaml
contracts/asyncapi.yaml
JSON schemas
traceability YAML
```

**Gate G8 — Build Ready**

---

## M9 — Quality First

Crear tests antes/durante la implementación.

```text
Test strategy
Fixtures
Contract tests
Security tests
Privacy tests
E2E
Tenant tests
Integrity tests
Accessibility tests
```

**Gate G9 — Quality Baseline Ready**

---

## M10 — Implementation

Implementación por **vertical slices**, no por capas gigantes.

Ejemplo:

```text
Slice 1
Study + Invitation

Slice 2
Email + OTP

Slice 3
Guardian + Student

Slice 4
Consent presentation

Slice 5
Consent decision

Slice 6
Evidence + Receipt

Slice 7
Consent query API

Slice 8
Revocation

Slice 9
Rights

Slice 10
Admin
```

Cada slice:

```text
Requirement
→ Spec
→ UX
→ Contract
→ Code
→ Test
→ Evidence
```

---

## M11 — Infrastructure + Operations

```text
AWS/cloud deployment
DNS
TLS
KMS
Secrets
Monitoring
CI/CD
Backups
Runbooks
Support
Incident response
```

**Gate G10 — Operational Ready**

---

## M12 — Hardening

```text
Threat testing
Pen testing
ASVS
Dependency review
Tenant adversarial testing
PII leakage review
Backup restore
Disaster simulation
Evidence manipulation tests
Rate-limit abuse
```

**Gate G11 — Security/Privacy Ready**

---

## M13 — Pilot Readiness

Revisar:

```text
Product
UX
Legal
Privacy
Security
Accessibility
Operations
Support
Measurement
Evidence
Integration
```

**Gate G12 — Pilot Ready**

---

## M14 — Pilot

Ejecutar con población limitada.

```text
Observe
Measure
Support
Log
Investigate
Learn
```

No ampliar automáticamente.

---

## M15 — Learning

Gaona convierte:

```text
Signals
 ↓
Patterns
 ↓
Findings
 ↓
Insights
 ↓
Recommendations
```

Santos decide:

```text
CONTINUE
ITERATE
STOP
```

**Gate G13 — Learning Captured**

---

# 54. Antes de Production

Después del beta:

```text
Pilot findings resolved
Legal review final
PIA updated
Threat model updated
Load testing
Operational readiness
DPA/contracts
Vendor review
Security review
Incident exercise
Restore exercise
Monitoring proven
Release evidence complete
```

Entonces:

**Gate G14 — Production Ready**

---

# 55. Cinco decisiones que no conviene postergar

Antes de pasar M2 deberían estar resueltas:

| Decisión                                             | Owner principal               |
| ---------------------------------------------------- | ----------------------------- |
| Finalidades exactas del consentimiento               | Product + Legal               |
| Responsable/Encargado por tratamiento                | Legal                         |
| Nivel requerido de prueba de autoridad del apoderado | Legal + Product               |
| Datos mínimos entregados por el colegio              | Privacy + Product             |
| Consecuencia exacta de revocación en LectorPro       | Product + Legal + Engineering |

---

# 56. Arquitectura documental

> DEC-BR-011 (2026-09-23): los 34 subdominios `docs/` no se replican en el repo; viven en Notion. Solo aplican las carpetas ejecutables.

El repositorio seguirá los dominios que ya definimos:

```text
docs/
├── context
├── research
├── strategy
├── product
├── experience
├── content
├── accessibility
├── design-system
├── domain
├── data
├── privacy
├── legal-compliance
├── evidence
├── identity-trust
├── architecture
├── frontend
├── backend
├── api
├── security
├── tenancy
├── ai
├── agentic
├── ai-engineering
├── ai-quality
├── ai-governance
├── measurement
├── quality
├── testing
├── reliability
├── observability
├── infrastructure
├── cicd
├── engineering
├── operations
├── release
├── pilot
├── learning
└── governance
```

Además:

```text
specs/
contracts/
agent/
ai/
traceability/
registers/
evidence/
tests/
infra/
db/
src/
```

---

# 57. Norte arquitectónico final

La arquitectura debe terminar siendo conceptualmente así:

```text
                   COLEGIO
                      │
                Secure invite
                      │
                      ▼
        ┌──────────────────────────┐
        │      CONSENT APP         │
        │ consent.lectorpro.cl     │
        │                          │
        │ Invitation               │
        │ Guardian Verification    │
        │ Study                    │
        │ Consent                  │
        │ Rights                   │
        │ Revocation               │
        │ Receipt                  │
        │ Evidence Ledger          │
        │ Audit                    │
        └────────────┬─────────────┘
                     │
             Versioned contract
                     │
             API / signed events
                     │
                     ▼
              ┌─────────────┐
              │  LectorPro  │
              └─────────────┘

NO SHARED DATABASE
NO SHARED AUTH STATE
MINIMUM DATA CONTRACT
```

# 58. Definición de éxito

El proyecto habrá cumplido su objetivo cuando podamos demostrar, para cualquier autorización:

> **Quién tomó la decisión, respecto de qué estudiante, para qué estudio, con qué información disponible, bajo qué versión, para qué finalidades, cuándo ocurrió, cuál es su estado actual, si fue revocada y que el historial no ha sido alterado sin detección.**

Y podamos hacerlo **sin recolectar más información personal de la necesaria**.

Ese es el núcleo de `consent.lectorpro.cl`: no una pantalla con checkboxes, sino un **sistema especializado de autorización, privacidad, evidencia y confianza** que LectorPro consume a través de un contrato mínimo.
