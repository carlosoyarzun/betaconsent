# **Estudio beta de LectorPro**

## *Protocolo metodología benchmarks y plan de análisis*

Versión 1.0 de trabajo  
16 de septiembre de 2026  
Chile

&nbsp;

**Decisión central** Ejecutar un beta cerrado, prospectivo, mixto y progresivo para validar seguridad operacional, experiencia, utilidad pedagógica y desempeño del motor antes de ampliar el producto.

El estudio no busca diagnosticar trastornos, reemplazar la evaluación docente ni fijar consecuencias académicas. Produce evidencia para decidir si LectorPro puede pasar a una siguiente ola, necesita modificaciones o debe detenerse.

Los benchmarks incluidos son umbrales iniciales de producto e investigación. Deben revisarse después de la primera ola sin reinterpretar retrospectivamente los resultados ya observados.

# **Control del documento**

| Campo | Definición |
| :---- | :---- |
| Sponsor | \[Entidad legal o representante\] |
| Responsable del estudio | \[Nombre y rol\] |
| Responsable del tratamiento | Por determinar por actividad de tratamiento (DEC-BR-002, Notion). Canal colegio: hipótesis en revisión jurídica |
| Estado | Borrador para revisión |
| Población | Estudiantes de 1° a 7° básico con autorización válida |
| Canales | Colegios participantes. El canal de familias individuales queda fuera del primer beta (DEC-BR-013, 2026-09-23) |
| Producto | LectorPro y aplicación independiente de consentimiento |
| Duración propuesta | 8 semanas por ciclo completo de beta |

&nbsp;

# **Contenido**

* Resumen ejecutivo y fundamento  
* Objetivos preguntas e hipótesis  
* Diseño población y muestra  
* Metodología y procedimiento  
* Métricas y benchmarks  
* Validación de inteligencia artificial  
* Plan de análisis  
* Experiencia accesibilidad y bienestar  
* Privacidad ética y seguridad  
* Gobernanza cronograma y decisiones  
* Referencias y anexos operativos

# **1 Resumen ejecutivo**

LectorPro es una plataforma de apoyo a la evaluación formativa de lectura oral y comprensión. El beta cerrado evaluará el recorrido completo desde la invitación y el consentimiento del apoderado hasta la captura de audio, el análisis automatizado, la revisión de resultados y la comunicación de información útil para adultos responsables.

El diseño combina telemetría de producto, pruebas técnicas, comparación con revisión humana, observación de sesiones, encuestas e entrevistas. La unidad primaria de análisis es la sesión de lectura; el estudiante es una unidad agrupadora y el colegio constituye un nivel organizacional. Los resultados se reportarán de manera agregada y por segmentos suficientemente amplios.

## **Resultado que debe producir el estudio**

* Una decisión GO, CONDITIONAL GO o NO GO para cada ola.  
* Una estimación transparente del desempeño del motor por tipo de error y contexto.  
* Evidencia de que consentimiento, revocación, aislamiento y eliminación funcionan realmente.  
* Hallazgos de experiencia para estudiantes, apoderados, docentes y colegios.  
* Una lista priorizada de defectos y cambios necesarios antes del piloto.

## **Principios**

| Principio | Aplicación en el estudio |
| :---- | :---- |
| Formativo | Sin nota, sanción ni diagnóstico; orienta mejoras de producto y apoyo pedagógico. |
| Progresivo | La exposición aumenta solo cuando los gates anteriores están cerrados. |
| Humano en el circuito | La IA se compara con evidencia humana y los casos inciertos se revisan. |
| Privacidad desde el diseño | Datos mínimos, consentimiento por estudiante, finalidad separada y retención limitada. |
| Interés superior | El bienestar del estudiante prevalece sobre completar una sesión o conseguir datos. |
| Trazabilidad | Cada conclusión enlaza hipótesis, datos, análisis, limitaciones y decisión. |

&nbsp;

# **2 Fundamento y contexto**

La lectura oral permite observar precisión, ritmo, continuidad y prosodia, mientras que la comprensión requiere evidencia separada. Automatizar parte de esta observación puede reducir carga operativa y entregar señales oportunas, pero introduce riesgos de error, sesgo, sobreinterpretación y tratamiento de datos de menores.

Como referencia de contexto chileno, la evaluación Impulso Lector de la Agencia de Calidad de la Educación utiliza registro de voz para fluidez, presenta la evaluación como formativa y sin nota, informa previamente a las familias y ha seguido una progresión desde pilotaje hasta aplicación ampliada. LectorPro no replica ese instrumento ni sus resultados, pero adopta los principios de aplicación breve, comunicación clara, uso pedagógico y validación progresiva.

## **Problema de investigación**

No existe todavía evidencia suficiente para afirmar que el recorrido completo de LectorPro funcione de forma confiable y segura en diversidad de cursos, dispositivos, condiciones acústicas y contextos escolares, ni que sus resultados automatizados sean suficientemente concordantes con revisión humana para el uso declarado.

## **Teoría de cambio**

| Etapa | Supuesto | Evidencia requerida |
| :---- | :---- | :---- |
| Entrada | Apoderado y estudiante comprenden la participación | Consentimiento válido, comprensión y voluntad de continuar |
| Captura | La sesión genera audio utilizable | Calidad, completitud y baja tasa de reintentos |
| Procesamiento | El motor representa la lectura con error acotado | Comparación con pauta humana y corpus de regresión |
| Interpretación | Los resultados se entienden sin sobreafirmar | Usabilidad, entrevistas y ausencia de confusión diagnóstica |
| Uso | La evidencia ayuda a orientar apoyo | Valor percibido y decisiones justificables |

&nbsp;

## **Alcance**

* Lectura oral de textos definidos para el estudio y preguntas de comprensión asociadas.  
* Flujo independiente de consentimiento, captura, procesamiento, revisión y resultados.  
* Cohortes escolares e individuales, diferenciadas en el análisis.  
* Evaluación técnica de ASR, alineamiento CTC, reconciliación y reglas posteriores según versión activa.

## **Fuera de alcance**

* Diagnóstico clínico, fonoaudiológico o psicopedagógico.  
* Calificaciones, promoción, sanciones o decisiones significativas automatizadas.  
* Comparación pública entre estudiantes, docentes o colegios.  
* ReaderLab y módulos clínicos no incluidos expresamente en el beta.  
* Entrenamiento general de modelos de terceros con datos del estudio.

# **3 Objetivos preguntas e hipótesis**

## **Objetivo general**

Determinar si LectorPro puede operar un beta cerrado seguro, comprensible y técnicamente confiable que produzca señales formativas útiles sobre lectura, con error conocido, control humano y protección adecuada de los datos de estudiantes.

## **Objetivos específicos**

* Validar el recorrido completo y la capacidad de recuperación ante errores.  
* Medir calidad de captura y desempeño del motor por familia de fenómenos de lectura.  
* Estimar concordancia entre resultados automatizados y revisión humana.  
* Evaluar comprensibilidad, esfuerzo, confianza y bienestar de participantes.  
* Verificar consentimiento, revocación, retención, permisos y aislamiento entre colegios.  
* Identificar sesgos o diferencias de desempeño que exijan rediseño o más evidencia.

## **Preguntas e hipótesis**

| ID | Pregunta | Hipótesis inicial | Evidencia |
| :---- | :---- | :---- | :---- |
| RQ1 | ¿Se completa el flujo sin ayuda? | Al menos 90% completa la sesión válida | Funnel, errores y observación |
| RQ2 | ¿El audio es utilizable? | Al menos 95% de sesiones genera audio procesable | QA de audio y reintentos |
| RQ3 | ¿El motor coincide con revisión humana? | Concordancia sustancial en métricas y eventos definidos | Pauta ciega y métricas de error |
| RQ4 | ¿Los resultados se comprenden? | Adultos distinguen señal formativa de diagnóstico | Tareas de comprensión e entrevistas |
| RQ5 | ¿Los controles de privacidad operan? | 100% de sesiones corresponde a consentimiento vigente | Auditoría y pruebas negativas |
| RQ6 | ¿Hay diferencias materiales por contexto? | Ningún segmento presenta degradación sin explicación y mitigación | Análisis estratificado |

&nbsp;

# **4 Diseño población y muestra**

## **Diseño**

Estudio prospectivo de métodos mixtos, sin grupo de control, organizado en olas secuenciales. Cada ola utiliza una versión identificada del producto, un conjunto de textos definido y criterios de decisión cerrados antes de analizar resultados. Los cambios de motor, interfaz o reglas se registran y no se mezclan silenciosamente en el mismo análisis.

## **Población**

| Actor | Participación |
| :---- | :---- |
| Estudiantes | Lectura, comprensión, percepción de la experiencia y derecho a detenerse. |
| Apoderados | Información, consentimiento, encuesta y entrevistas opcionales. |
| Docentes | Coordinación, observación, interpretación y utilidad pedagógica. |
| Colegios | Gobernanza, habilitación, soporte e información agregada. |
| Equipo LectorPro | Operación, revisión, soporte, seguridad y análisis. |

&nbsp;

## **Criterios de inclusión**

* Estudiante de 1° a 7° básico dentro de una cohorte autorizada.  
* Apoderado verificado por email y código, con decisiones vigentes por estudiante.  
* Autorizaciones obligatorias de participación, audio y análisis automatizado.  
* Información y voluntad del estudiante adecuadas a su edad.  
* Dispositivo, conectividad y entorno dentro de los escenarios declarados por la ola.

## **Criterios de exclusión o pausa**

* Revocación, consentimiento vencido o discrepancia de identidad/estudiante.  
* Incomodidad, fatiga, frustración o deseo de detenerse.  
* Condición acústica o técnica que impida interpretar la sesión.  
* Incidente de privacidad, seguridad o aislamiento que afecte el flujo.  
* Cambio no aprobado de texto, modelo, instrumento o finalidad.

## **Plan de olas propuesto**

| Ola | Participantes propuestos | Propósito | Gate |
| :---- | :---- | :---- | :---- |
| 0 Calibración | 12 a 20 sesiones supervisadas | Estabilizar audio, eventos y revisión humana | Sin fallos críticos; replay cerrado |
| 1 Colegio inicial | 20 a 30 estudiantes; 1 colegio | Validar operación real y UX | Consentimiento, seguridad y calidad cumplen |
| 2 Beta cerrado | 60 a 100 estudiantes; 2 a 3 colegios | Estimar desempeño y variabilidad | Benchmarks primarios o plan correctivo acotado |
| 3 Expansión | 150 a 250 acumulados; 3 a 5 colegios y familias individuales | Robustez, segmentos y operación | GO formal para piloto |

&nbsp;

**Nota de muestra** Los rangos son una propuesta operacional, no un cálculo de potencia para eficacia pedagógica. Con 100 sesiones y una proporción observada cercana a 95%, el margen aproximado de un intervalo de confianza de 95% es ±4,3 puntos porcentuales; con 200, cerca de ±3 puntos.

## **Muestreo**

Se utilizará muestreo intencional estratificado por ciclo escolar y contexto de uso. La cobertura mínima debe incluir tres bandas —1° a 2°, 3° a 4° y 5° a 7°—, más diversidad de dispositivos y condiciones acústicas previstas. No se recogerán variables sensibles solo para completar cuotas; cualquier atributo adicional exige finalidad y justificación de minimización.

# **5 Metodología y procedimiento**

## **Enfoque mixto**

| Componente | Método | Salida |
| :---- | :---- | :---- |
| Producto | Funnel, eventos, tiempos, errores y reintentos | Tasas de éxito y puntos de abandono |
| Audio | QA automático y revisión muestral | Usabilidad de señal y causas de descarte |
| Motor | Replay, comparación con pauta y corpus de regresión | Errores por familia y versión |
| Experiencia | Observación, encuesta e entrevista | Esfuerzo, comprensión, confianza y fricción |
| Privacidad | Auditoría de estados y pruebas negativas | Cumplimiento operacional |
| Operación | Registro de soporte e incidentes | Carga, tiempos y capacidad de respuesta |

&nbsp;

## **Procedimiento por participante**

1. Crear invitación asociada a estudio, cohorte y estudiante seudónimo.  
2. Enviar invitación al apoderado desde LectorPro y verificar control del email mediante código de un solo uso.  
3. Presentar información y decisiones separadas para participación, audio, análisis automatizado y usos opcionales.  
4. Emitir estado mínimo de elegibilidad; colegio y profesor no reciben el detalle de decisiones opcionales.  
5. Explicar la actividad al estudiante y confirmar que desea continuar.  
6. Ejecutar chequeo de dispositivo, micrófono, ruido y conectividad.  
7. Realizar lectura y comprensión con capacidad visible de pausar o detener.  
8. Procesar la sesión, registrar versión del motor y producir resultado con indicadores de confianza.  
9. Derivar casos inciertos o muestreados a revisión humana.  
10. Aplicar encuesta breve y registrar incidentes o eventos inesperados.

## **Sesión de lectura**

La aplicación debe ser breve, predecible y adecuada a la edad. Como benchmark externo de experiencia, Impulso Lector informa un tiempo promedio cercano a tres minutos para su módulo individual de fluidez. Para LectorPro se propone separar el tiempo de lectura del tiempo total del flujo, porque incluye chequeo técnico y comprensión.

| Fase | Duración objetivo | Condición |
| :---- | :---- | :---- |
| Preparación | 1 a 2 minutos | Dispositivo, audio, instrucciones y voluntad |
| Lectura | 2 a 5 minutos | Depende de texto, grado y regla de detención |
| Comprensión | 3 a 5 minutos | Preguntas definidas para el texto |
| Cierre | Menos de 1 minuto | Confirmación y encuesta breve |
| Total | 7 a 12 minutos | Objetivo de UX, no límite pedagógico rígido |

&nbsp;

## **Investigación cualitativa**

Se observará una muestra diversa de sesiones y se realizarán entrevistas semiestructuradas con aproximadamente 6 a 8 docentes y 6 a 10 apoderados. Con estudiantes se utilizarán preguntas breves, apropiadas a la edad y centradas en comprensión de instrucciones, comodidad y capacidad de detenerse, sin convertir la sesión en interrogatorio.

# **6 Métricas y benchmarks**

Los siguientes umbrales son benchmarks propuestos para el beta. No son resultados observados ni estándares clínicos. Un gate bloqueante no puede compensarse con un promedio favorable en otra dimensión.

## **Benchmarks primarios**

| Dimensión | Métrica | Umbral propuesto | Decisión |
| :---- | :---- | :---- | :---- |
| Consentimiento | Sesiones iniciadas con consentimiento vigente | 100% | Cualquier incumplimiento pausa el beta |
| Aislamiento | Exposición cruzada entre colegios | 0 casos | S0 y NO GO |
| Seguridad | Incidentes críticos o altos abiertos | 0 | NO GO |
| Bienestar | Solicitudes de detenerse respetadas | 100% | Incumplimiento bloqueante |
| Recorrido | Sesiones válidas completadas | ≥90% | Investigar por segmento si no cumple |
| Audio | Audio procesable sin repetir sesión completa | ≥95% | Corregir captura o entorno |
| Estabilidad | Fallos técnicos que impiden completar | ≤3% | Conditional GO o NO GO |
| Comprensión UX | Apoderados que identifican propósito y revocación | ≥90% | Reescribir y repetir prueba |
| Accesibilidad | Bloqueadores WCAG AA en flujo crítico | 0 | NO GO para público afectado |

&nbsp;

## **Benchmarks del motor**

| Métrica | Umbral inicial | Lectura |
| :---- | :---- | :---- |
| Error absoluto de palabras por minuto | Mediana ≤5; percentil 90 ≤10 | Diferencia respecto de pauta humana |
| Precisión en eventos de lectura | ≥0,95 global | Reduce falsos positivos |
| Recall en eventos de lectura | ≥0,85 global | Reduce omisiones |
| Precisión mínima por familia | ≥0,80 | Evita ocultar una categoría débil en el promedio |
| Falsos positivos en etiquetas de mayor impacto | ≤2% | Gate conservador |
| Concordancia entre jueces | Kappa ponderado o equivalente ≥0,75 | Valida la pauta humana |
| Corpus de regresión crítico | 0 regresiones bloqueantes | Incluye errores conocidos y casos límite |
| Respuestas cerradas de comprensión | 100% de scoring determinista | No depende de IA generativa |

&nbsp;

**Regla de interpretación** Si los jueces humanos no alcanzan concordancia suficiente, el caso no puede usarse para declarar error del motor hasta adjudicar la pauta. La incertidumbre humana se reporta, no se esconde.

## **Referencias internas de velocidad**

LectorPro utiliza actualmente las siguientes metas internas por curso. Se incluyen para segmentar y probar el producto, no como puntos de corte diagnósticos ni como equivalentes a una norma oficial. El estudio deberá documentar su fuente pedagógica y revisar su validez antes de comunicarlas externamente.

| Curso | Referencia interna PPM |
| :---- | :---- |
| 1° básico | 38 |
| 2° básico | 64 |
| 3° básico | 88 |
| 4° básico | 111 |
| 5° básico | 136 |
| 6° básico | 161 |
| 7° básico | 182 |

&nbsp;

## **Métricas secundarias**

* Tiempo mediano y percentil 90 por paso y por sesión.  
* Tasa de reintento, permisos de micrófono denegados y abandono por etapa.  
* Satisfacción, esfuerzo percibido, confianza y comprensión de resultados.  
* Tickets de soporte por 100 sesiones y tiempo de resolución.  
* Cobertura de revisión humana, proporción de baja confianza y causas de derivación.  
* Diferencias descriptivas por curso, dispositivo, entorno y canal de reclutamiento.

# **7 Validación del motor y revisión humana**

## **Unidad de evaluación**

La unidad mínima será palabra o evento temporalmente alineado; la sesión constituye la unidad para métricas agregadas. Cada resultado conserva versión del texto, motor, configuración, dispositivo y transformaciones relevantes.

## **Pauta humana**

* El juez recibe instrucciones, ejemplos positivos/negativos y criterios de exclusión.  
* La revisión se realiza sin conocer la predicción del motor cuando el objetivo es construir ground truth.  
* Al menos 20% de la muestra de validación recibe doble anotación; 100% para familias críticas o nuevas.  
* Los desacuerdos se adjudican por un tercer criterio o consenso documentado.  
* Las hojas o registros se sellan antes de comparar con el motor para evitar contaminación retrospectiva.

## **Familias de error**

| Familia | Ejemplos | Métrica principal |
| :---- | :---- | :---- |
| Reconocimiento léxico | Sustitución, omisión, inserción | Precisión, recall y WER como apoyo |
| Segmentación | Palabras pegadas o separadas | Exactitud por evento y análisis de vecino |
| Prolongaciones | Sonidos extendidos e intensidad | Acuerdo humano y F1 |
| Repeticiones | Palabra o fragmento repetido | Precisión y recall |
| Autocorrecciones | Error seguido de corrección | Secuencia correcta y latencia |
| Ritmo | Pausas, continuidad y velocidad | Error PPM y distribución de pausas |
| Prosodia | Entonación y expresividad | Solo exploratorio hasta pauta robusta |

&nbsp;

## **Conjuntos de datos**

| Conjunto | Uso | Regla |
| :---- | :---- | :---- |
| Desarrollo | Ajustar reglas y corregir errores | No se usa para declarar desempeño final |
| Regresión | Evitar reaparición de defectos | Versionado e inmutable por release |
| Validación beta | Estimar desempeño real | Pauta sellada antes de comparación |
| Holdout | Comprobación final | No visible durante tuning |

&nbsp;

## **Incertidumbre y escalamiento**

Las salidas de baja confianza, fuera de distribución o con conflicto entre motores se marcan como no concluyentes y se derivan a revisión. El producto no debe convertir ausencia de certeza en una etiqueta categórica. Las correcciones humanas quedan separadas de la predicción original para conservar auditabilidad.

# **8 Plan de análisis**

## **Preparación**

* Congelar versión del plan antes de abrir cada ola.  
* Validar integridad, duplicados, zonas horarias, versiones y denominadores.  
* Excluir únicamente mediante reglas predefinidas y reportar el flujo de exclusión.  
* No unir el registro identificable de participantes con el dataset analítico salvo procedimiento controlado.

## **Análisis cuantitativo**

Se reportarán conteos, tasas, medianas, percentiles e intervalos de confianza de 95%. Las métricas se calcularán por sesión y, cuando corresponda, con intervalos que reconozcan sesiones repetidas por estudiante. Los resultados se estratificarán por banda de curso, dispositivo, ambiente y ola cuando el tamaño permita una lectura responsable.

| Pregunta | Análisis |
| :---- | :---- |
| Flujo | Funnel, abandono, tiempo por paso, errores y reintentos |
| Calidad técnica | Tasas de audio utilizable y fallos con intervalos |
| Motor | Matriz de confusión, precision, recall, F1, error PPM y distribución |
| Concordancia | Kappa ponderado o ICC según escala; acuerdo por familia |
| Segmentos | Diferencias absolutas con incertidumbre; no rankings |
| Incidentes | Frecuencia, severidad, tiempo de contención y recurrencia |

&nbsp;

## **Análisis cualitativo**

Las notas y entrevistas se codificarán con un esquema inicial —comprensión, confianza, esfuerzo, fricción, bienestar, utilidad y expectativas— abierto a temas emergentes. Cada hallazgo incluirá evidencia, frecuencia/contexto, interpretación, contradicciones y decisión. Una cita aislada no se convertirá por sí sola en conclusión general.

## **Sesgos y datos faltantes**

* Separar ausencia de lectura, audio inválido, abandono y fallo del sistema.  
* Reportar quién quedó fuera y por qué; no asumir que faltantes son aleatorios.  
* Evitar declarar equidad a partir de muestras pequeñas; usar hallazgos como señales para ampliar evidencia.  
* Mantener resultados por versión para no atribuir mejoras de producto a diferencias de cohorte.

## **Jerarquía de decisiones**

| Decisión | Condición |
| :---- | :---- |
| GO | Todos los gates bloqueantes y benchmarks primarios cumplen. |
| CONDITIONAL GO | Brechas acotadas, mitigación verificable y sin riesgo alto residual. |
| INCONCLUSIVE | Datos insuficientes, pauta humana débil o instrumentación inválida. |
| NO GO | Fuga, daño, consentimiento inválido, riesgo alto o desempeño incompatible con el uso. |

&nbsp;

# **9 Experiencia accesibilidad y bienestar**

## **Criterios de experiencia**

* El estudiante entiende que no es una prueba con nota.  
* Las instrucciones están adaptadas al curso y se presentan una por vez.  
* La interfaz muestra claramente cómo iniciar, pausar, repetir o detener.  
* Un error técnico no se presenta como fracaso del estudiante.  
* El adulto recibe resultados con límites, contexto y acciones posibles.  
* El flujo completo funciona en mobile y no depende de precisión motora fina.

## **Accesibilidad**

El objetivo es WCAG 2.2 nivel AA en los flujos web críticos, con pruebas de teclado, lectores de pantalla, contraste, zoom, foco, mensajes de error y reflow. Las necesidades de apoyo deben planificarse con el colegio sin alterar el constructo que se desea observar. Ayudas habituales del estudiante pueden mantenerse cuando no invaliden la actividad.

## **Protocolo de bienestar**

| Señal | Respuesta inmediata | Registro |
| :---- | :---- | :---- |
| Duda o confusión | Aclarar instrucción sin sugerir respuesta | Tipo de ayuda |
| Frustración leve | Pausa y ofrecer continuar o terminar | Evento sin detalle sensible |
| Deseo de detenerse | Finalizar inmediatamente | Retiro voluntario |
| Malestar persistente | Informar al adulto responsable y activar protocolo | Incidente restringido |
| Error del sistema | Asumir responsabilidad y no culpabilizar | Issue técnico |

&nbsp;

# **10 Privacidad ética y seguridad**

## **Consentimiento y autorización**

El apoderado se verifica mediante email y código de un solo uso. Las decisiones se registran por estudiante y por finalidad: participación, grabación de audio, análisis automatizado y usos opcionales. Si se rechaza o revoca una finalidad indispensable, el estudiante no participa o deja de participar. Los usos opcionales nunca condicionan el beta.

## **Datos previstos**

| Categoría | Finalidad | Regla |
| :---- | :---- | :---- |
| Identificadores | Invitación y relación con cohorte | Seudonimizar; no solicitar RUT por defecto |
| Consentimiento | Demostrar decisión y vigencia | Versión, hash, fecha, canal y verificación. Dos capas según DEC-BR-007: ledger de integridad sin PII directa (plazo en LEGAL DECISION) y capa PII con supresión verificable. La eliminación de cierre (§ del cierre) incluye backups dentro de las 8 semanas |
| Audio | Ejecutar y validar la evaluación | Máximo 12 meses desde la grabación |
| Derivados | Transcripción, alineación y métricas | Plazo igual o menor al audio identificable |
| Telemetría | Calidad y UX | Eventos mínimos y sin contenido innecesario |
| Investigación | Encuestas, observación y entrevistas | Separar identidad del análisis |

&nbsp;

## **Marco regulatorio**

A la fecha de este documento, la Ley 21.719 mantiene una entrada en vigencia prevista para el 1 de diciembre de 2026\. Existe un proyecto de ley —Boletín 18.623-07— que propone postergarla al 1 de diciembre de 2027 y cuya tramitación debe revisarse antes de iniciar el estudio. Independientemente de la fecha, el beta adoptará desde su diseño el estándar más exigente de transparencia, derechos, seguridad, protección de NNA, contratos con encargados y evaluación de impacto.

La voz no se tratará como identificador biométrico por defecto. Debe documentarse si el procesamiento técnico permite o confirma identificación única; si el propósito, proveedor o modelo cambia, la evaluación biométrica se repite antes del cambio.

## **Controles de seguridad bloqueantes**

* Aislamiento tenant server-side en API, archivos, jobs, cache, exportaciones y analítica.  
* Cifrado en tránsito y reposo, secretos administrados y mínimo privilegio.  
* Auditoría de accesos administrativos con motivo, alcance y caducidad.  
* Pruebas negativas de acceso entre colegios y eliminación de cualquier fuga activa antes del beta.  
* Contratos y evaluación de proveedores, incluyendo prohibición de entrenamiento no autorizado.  
* Plan de incidentes, backups probados, restauración y eliminación verificable.

## **Revisión ética**

Debe resolverse por escrito si corresponde revisión por un Comité Ético Científico según las instituciones participantes, la participación de menores, el tipo de intervención, la publicación prevista y los convenios. La ausencia de una obligación general no equivale a una exención automática.

# **11 Gobernanza operación y cronograma**

## **Responsabilidades**

| Rol | Responsabilidad |
| :---- | :---- |
| Sponsor | Autoriza recursos, riesgo residual y continuidad. |
| Study Lead | Mantiene protocolo, ejecución, desviaciones y cierre. Revisión ética: determinación escrita de si corresponde Comité Ético Científico y, si aplica, gestión de su aprobación (DEC-BR-012). |
| Research Lead | Instrumentos, pauta humana, análisis y evidencia. |
| Product Engineering | Versión, eventos, estabilidad y correcciones. |
| Privacy Legal | Bases, textos, DPIA, contratos y derechos. |
| Security | Threat model, pruebas, incidentes y gate. |
| School Champion | Coordinación local sin sustituir consentimientos. |
| Teacher | Acompañamiento y soporte sin inducir respuestas. |

&nbsp;

## **Cronograma propuesto**

| Periodo | Actividad | Salida |
| :---- | :---- | :---- |
| Semana 0 | Gates legales, éticos, seguridad, instrumentos y capacitación | GO para ola 0 |
| Semana 1 | Calibración supervisada | Defectos y replay |
| Semana 2 | Ola 1 en colegio inicial | Reporte rápido |
| Semana 3 | Análisis, fixes y revalidación | GO o NO GO |
| Semanas 4 y 5 | Ola 2 beta cerrado | Dataset de validación |
| Semana 6 | Análisis mixto y entrevistas | Hallazgos integrados |
| Semanas 7 y 8 | Cierre, eliminación, reportes y decisión | Readiness para piloto |

&nbsp;

## **Cadencia**

* Chequeo diario de incidentes, consentimiento, fallos y calidad de captura.  
* Revisión semanal de scorecard, riesgos, issues y capacidad de soporte.  
* Gate formal entre olas con evidencia firmada.  
* Congelamiento del dataset y del plan antes del informe final.

## **Artefactos de salida**

* Reporte de operación y experiencia.  
* Reporte de desempeño del motor.  
* Reporte de privacidad y seguridad.  
* Registro de limitaciones y sesgos.  
* Memo de decisión del beta.  
* Evaluación de preparación para piloto.  
* Registro de archivo, anonimización y destrucción.

# **12 Anexos operativos**

## **Diccionario mínimo de eventos**

| Evento | Momento | Propiedades mínimas |
| :---- | :---- | :---- |
| invitation\_opened | Se abre enlace válido | study\_id, cohort\_id, channel |
| email\_verified | Código correcto | method, attempt\_count |
| consent\_decided | Decisión por finalidad | purpose, decision, version |
| eligibility\_checked | Antes de iniciar | result, reason\_code |
| audio\_check\_completed | Chequeo previo | device\_class, result, reason |
| session\_started | Inicio de actividad | grade\_band, text\_version |
| recording\_completed | Fin de captura | duration\_bucket, retry\_count |
| processing\_completed | Resultado del motor | engine\_version, confidence\_band |
| human\_review\_completed | Cierre de revisión | review\_type, adjudicated |
| session\_completed | Cierre válido | duration\_bucket, outcome |
| session\_stopped | Detención | actor, stage, non\_sensitive\_reason |
| consent\_revoked | Revocación efectiva | purpose, effective\_at |

&nbsp;

## **Scorecard de ola**

| Dominio | Resultado | Umbral | Estado | Evidencia |
| :---- | :---- | :---- | :---- | :---- |
| Consentimiento | \[ \] | 100% vigente | \[ \] | \[ \] |
| Seguridad | \[ \] | 0 críticos | \[ \] | \[ \] |
| Recorrido | \[ \] | ≥90% | \[ \] | \[ \] |
| Audio | \[ \] | ≥95% | \[ \] | \[ \] |
| Motor | \[ \] | Ver benchmarks | \[ \] | \[ \] |
| Bienestar | \[ \] | 0 incumplimientos | \[ \] | \[ \] |
| Accesibilidad | \[ \] | 0 bloqueadores | \[ \] | \[ \] |

&nbsp;

## **Registro de decisión**

| Campo | Contenido |
| :---- | :---- |
| Ola y versión | \[ \] |
| Decisión | GO / CONDITIONAL GO / INCONCLUSIVE / NO GO |
| Evidencia principal | \[ \] |
| Riesgo residual | \[ \] |
| Condiciones | \[ \] |
| Owner y plazo | \[ \] |
| Aprobadores | \[ \] |

&nbsp;

## **Fuentes de referencia**

* Biblioteca del Congreso Nacional. Ley 21.719. https://www.bcn.cl/leychile/Navegar?idNorma=1209272  
* Biblioteca del Congreso Nacional. Ley 19.628. https://www.bcn.cl/leychile/Navegar?idNorma=141599  
* Senado de Chile. Boletín 18.623-07 sobre modificación de la entrada en vigencia de la Ley 21.719. https://tramitacion.senado.cl/  
* Agencia de Calidad de la Educación. Impulso Lector 2026\. https://www.agenciaeducacion.cl/impulso-lector/  
* Agencia de Calidad de la Educación. Evaluación para la Reactivación de la Lectura y DIA. https://diagnosticointegral.agenciaeducacion.cl/  
* Agencia de Calidad de la Educación. Orientaciones de comprensión lectora. https://archivos.agenciaeducacion.cl/evaluacion\_progresiva2018/descargas/orientaciones/estrategias\_pedagogicas\_lectura.pdf

## **Aprobación**

| Rol | Nombre | Decisión | Fecha | Evidencia |
| :---- | :---- | :---- | :---- | :---- |
| Sponsor | \[ \] | \[ \] | \[ \] | \[ \] |
| Study Lead | \[ \] | \[ \] | \[ \] | \[ \] |
| Privacy Legal | \[ \] | \[ \] | \[ \] | \[ \] |
| Security | \[ \] | \[ \] | \[ \] | \[ \] |
| Research | \[ \] | \[ \] | \[ \] | \[ \] |
| Determinación ética escrita (y aprobación de comité si aplica) | Study Lead | \[ \] | \[ \] | Previa a la emisión de invitaciones (DEC-BR-012) |

&nbsp;

## **Control de versiones**

v1.1 — 2026-09-23 — Cambios por DEC-BR-002, DEC-BR-007, DEC-BR-012 y DEC-BR-013 (Notion, Open Decisions — Build Blockers). Ediciones puntuales en §2 (responsable, canales), §10 (retención), §11 (responsabilidades, semana 0, aprobaciones).