# PRODUCT-BLUEPRINT: Consent App

Estado: BORRADOR (M0, CA-17) · Fuente de verdad: Notion "Consent App" (DEC-BR-011); este archivo es copia de referencia.

> Documento exigido en M0 Foundation (Master Plan §53). Su contenido anticipa entregables de M1 (Problem, Purpose, Scope, Actors) cuyo cierre corresponde a Gate G1 (Master Plan §53). No crea requisitos nuevos: cada afirmación cita su fuente.

## 1. Propósito

- Consent App existe para responder una sola pregunta de forma confiable: ¿existe una autorización válida, vigente, específica, comprensible y trazable para que este estudiante participe en este estudio y para las finalidades correspondientes? (Master Plan §1).
- Objetivo primario: obtener y mantener evidencia confiable de las decisiones de consentimiento sobre un estudiante y un estudio determinado (Master Plan §3).
- La especialización es deliberada (Master Plan §1). Es un sistema especializado de autorización, privacidad, evidencia y confianza que LectorPro consume mediante un contrato mínimo (Master Plan §58).

## 2. Problema

- Hay que poder demostrar, para cualquier autorización, quién decidió, sobre qué estudiante, para qué estudio, con qué información disponible, bajo qué versión, para qué finalidades, cuándo, cuál es su estado actual, si fue revocada y que el historial no se alteró sin que se detecte (Master Plan §58).
- Todo eso sin recolectar más información personal de la necesaria (Master Plan §58; P01).
- Contexto regulatorio: la Ley 21.719 impone reglas específicas para datos de NNA, con consentimiento de padres, representantes legales o quien tenga el cuidado personal, salvo que la ley habilite otra cosa (Master Plan §5). `LEGAL DECISION`: toda interpretación específica requiere revisión jurídica antes de producción (Master Plan §5).
- En el Estudio Beta, el funcionamiento real de consentimiento, revocación, aislamiento y eliminación es un resultado que el estudio debe evidenciar (Protocolo §1).

## 3. Alcance

### Dentro
- Invitar al apoderado, verificar su canal de contacto, identificar al estudiante, explicar el estudio, presentar finalidades separadas, registrar decisiones, generar comprobante, consultar estado, revocar, gestionar solicitudes de derechos, demostrar qué ocurrió históricamente y comunicar cambios a sistemas consumidores (Master Plan §3).
- Golden Path del apoderado: Invitation Landing, Email, OTP, Guardian information, Student confirmation, Study information, Consent purposes, Review, Decision, Receipt. Después: Manage Consent (View, Rights, Revoke) (Master Plan §13).
- Admin MVP: Organization, Study, Consent Template, Consent Version, Invitation, Consent Status, Revocation, Rights Request, Audit Event, Integrity Verification (Master Plan §41).
- Consentimiento siempre ligado a un `Study`, nunca "para LectorPro en general" (Master Plan §7).
- Integración con LectorPro solo por contratos versionados (API / eventos). No hay acceso directo a la base de datos en ninguna dirección (Master Plan §2, §37, §38).

### Fuera
- Portal del estudiante, portal general del apoderado, plataforma de evaluación, repositorio de audio, sistema pedagógico, CRM de colegios, motor de IA, sistema de research, sistema académico (Master Plan §1).
- CRM, plataforma de marketing, gestión escolar, suite de gestión de estudiantes (Master Plan §41).
- Remediación de datos aguas abajo: Consent App registra la decisión y el sistema consumidor actúa sobre los datos que mantiene (Master Plan §22).
- Por defecto no se solicita: RUT, dirección, fecha de nacimiento, diagnósticos, PIE, notas, historial académico, fotografía, documento de identidad (Master Plan §9).
- Canal de familias individuales en el primer beta (DEC-BR-013, 2026-09-23).

## 4. Actores

| Actor | Rol en Consent App | Fuente |
|---|---|---|
| Apoderado / tutor | Usuario principal. Verifica email, declara su relación y su autoridad, decide, revoca y ejerce derechos | Master Plan encabezado, §10, §13 |
| Estudiante (titular, NNA) | Sujeto de la autorización. Se identifica con una referencia pseudónima (`studentRef`), no con RUT | Master Plan §9 |
| Establecimiento educacional (Organization / tenant) | Envía la invitación y entrega los datos mínimos del estudiante. Aislado por tenant | Master Plan §8, §9, §11 |
| Administrador autorizado | Opera el Admin MVP | Master Plan encabezado, §41 |
| LectorPro (sistema consumidor) | Consulta el estado del consentimiento y recibe eventos. No recibe identidad del apoderado por defecto | Master Plan §37, §38 |

- Relaciones declarables: Madre, Padre, Representante legal, Persona con cuidado personal, Otro. El caso "Otro" puede requerir tratamiento especial (Master Plan §10). `LEGAL DECISION`.
- Responsable/Encargado se define por actividad de tratamiento y hoy está en TBD / Legal review (Master Plan §6). `LEGAL DECISION`.
- Canal único del primer beta: colegio (DEC-BR-013).

## 5. Principios no negociables (Master Plan §4)

P01 Minimizar antes de proteger · P02 Sin RUT, salvo necesidad documentada y decisión legal explícita · P03 Verificación de email ≠ verificación de identidad ≠ verificación de autoridad · P04 Pseudonimizado ≠ anónimo · P05 Consentimiento específico y trazable · P06 Sin opciones preseleccionadas · P07 La revocación debe ser posible · P08 Evidencia histórica append-only · P09 El estado actual se deriva de la evidencia · P10 Sin PII en URLs · P11 Sin PII innecesaria en logs ni analytics · P12 Sin acceso cross-tenant · P13 Sin base de datos compartida con LectorPro · P14 Decisiones críticas de consentimiento deterministas · P15 La IA no puede inferir consentimiento · P16 La seguridad falla cerrada · P17 La incertidumbre legal se convierte en decisión explícita · P18 Sin implementación sin requisitos/specs gobernantes · P19 Sin release sin tests y evidencia · P20 Política de Privacidad ≠ base jurídica de cada tratamiento.

Cualquier excepción a estos principios es un human gate.

## 6. Primer caso de uso: Estudio Beta LectorPro (`consent.lectorpro.cl`)

- Ámbito inicial: beta de LectorPro en Chile (Master Plan encabezado). Estudio de ejemplo: `studyRef = BETA_2026_01`. Autorizar ese estudio no autoriza `BETA_2026_02` (Master Plan §7).
- Objetivo del estudio: determinar si LectorPro puede operar un beta cerrado seguro, comprensible y técnicamente confiable, con protección adecuada de los datos de estudiantes (Protocolo §3). Objetivo específico que depende de Consent App: verificar consentimiento, revocación, retención, permisos y aislamiento entre colegios (Protocolo §3).
- RQ5: el 100% de las sesiones debe corresponder a un consentimiento vigente (Protocolo §3).
- Población: estudiantes de 1° a 7° básico en una cohorte autorizada. Apoderado verificado por email y código, con decisiones vigentes por estudiante (Protocolo §4).
- Participan estudiantes, apoderados, docentes, colegios y el equipo LectorPro (Protocolo §4). Solo apoderados, colegios y administradores son actores de Consent App (Master Plan encabezado).
- Olas: 0 Calibración (12 a 20 sesiones), 1 Colegio inicial (20 a 30 estudiantes), 2 Beta cerrado (60 a 100), 3 Expansión (150 a 250 acumulados) (Protocolo §4).
- Finalidades del estudio: participación, grabación de audio y análisis automatizado son obligatorias. Los usos opcionales nunca condicionan el beta. Rechazar o revocar una finalidad indispensable implica que el estudiante no participa o deja de participar (Protocolo §4, §10).
- Las finalidades candidatas de Consent App (participation, recording, processing, humanReview, research, productImprovement) no son texto legal definitivo. Antes del piloto, cada una necesita base jurídica, obligatoriedad, datos, encargado, retención, consumidor y consecuencia de rechazo (Master Plan §15). `LEGAL DECISION`.
- Invitación: el colegio la envía con un enlace de token aleatorio, expirable, revocable y de un solo propósito. El colegio no necesita entregar inicialmente el email del apoderado (Master Plan §11).
- Datos obligatorios del colegio: `studyRef`, `schoolRef`, `studentRef`. Nombre y curso son opcionales según UX/legal (Master Plan §9). `LEGAL DECISION`.
- Todo texto legal lleva la marca `DRAFT — LEGAL REVIEW REQUIRED` hasta su aprobación (Master Plan §53, M2).
- Revisión ética: hay que resolver por escrito si corresponde un Comité Ético Científico (Protocolo §10). `LEGAL DECISION`.

## 7. Límites de IA (Master Plan §32)

- Consent App es AI-native en su desarrollo, no AI-dependent en su consentimiento (Master Plan §32).
- La IA puede ayudar en: generación de specs, detección de contradicciones, análisis de amenazas, generación de tests, code review, análisis de impacto, documentación, análisis de observabilidad, mapeo de cumplimiento (Master Plan §32).
- La IA no puede decidir: si existe consentimiento, si el usuario aceptó, la validez del OTP, la autoridad legal del apoderado, la autorización de tenant, la revocación, la base jurídica, la aprobación legal ni la validez de la evidencia (Master Plan §32; P14, P15).

## 8. Decisiones abiertas que condicionan el producto

Registro canónico: Notion "14 — Decisions & Registers / Open Decisions — Build Blockers". Estados al 2026-09-23.

| ID | Tema | Estado | Master Plan §55 |
|---|---|---|---|
| DEC-BR-001 | Optional purposes for LectorPro Beta | OPEN | Finalidades exactas del consentimiento. `LEGAL DECISION` |
| DEC-BR-002 | Controller / Processor by processing activity | LEGAL REVIEW · ampliación ACEPTADA 2026-09-23 como hipótesis (R1) | Responsable/Encargado por tratamiento. `LEGAL DECISION` (finding R1) |
| DEC-BR-003 | DecisionMaker authority assurance | LEGAL REVIEW | Nivel de prueba de autoridad del apoderado. `LEGAL DECISION` |
| DEC-BR-004 | Minimum Subject recognition data | OPEN | Datos mínimos que entrega el colegio |
| DEC-BR-005 | Eligibility ownership | OPEN | — |
| DEC-BR-006 | Revocation downstream behavior | OPEN / LEGAL REVIEW | Consecuencia exacta de la revocación en LectorPro. `LEGAL DECISION` |
| DEC-BR-007 | Consent App retention schedule | LEGAL REVIEW · ampliación ACEPTADA 2026-09-23 como dirección: dos capas (R5) | — (finding R5) |
| DEC-BR-008 | Architecture stack | OPEN | — |
| DEC-BR-009 | Evidence integrity construction | OPEN | — |
| DEC-BR-010 | PIA readiness | OPEN | — (historia CA-85) |
| DEC-BR-011 | Documentary source of truth: Notion para conocimiento humano, repo solo ejecutable | ACCEPTED (2026-09-23) | — |
| DEC-BR-012 | Revisión ética: dueño y gate | ACCEPTED (2026-09-23): Study Lead dueño, gate en G2 | — |
| DEC-BR-013 | First beta channel scope: solo canal colegio | ACCEPTED (2026-09-23) | — |

El Master Plan §55 exige resolver las cinco decisiones de la última columna antes de pasar M2.
