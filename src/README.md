# src/

Código de producto de la Consent App.

Gobierna: `REQ-CNS-###`, `API-CNS-###`, `RULE-CNS-###`.

Estado: primeros slices verticales de dominio IT0 (CA-116), sin HTTP ni Postgres reales —
solo puertos e implementaciones in-memory (ADR-003 rev. 7: sin infraestructura hasta la
historia correspondiente). Capas: `server/modules` (dominio), `server/ports` (interfaces),
`infra/adapters` (in-memory IT0), siguiendo el guardrail de `tools/guardrails/ports-adapters/`.

## Servidor de desarrollo (LOCAL)

`CNS_ENVIRONMENT=LOCAL node src/server/entrypoints/dev.ts` (PORT opcional, default 3000; aborta
fuera de LOCAL, GRD-CM-13). Imprime el enlace de invitación sintético (`GET /i/{token}`,
API-CNS-101) y cómo leer el OTP. Solo en LOCAL expone `GET /__dev/otp-sink` (sink en memoria,
cero PII, dominios `example.invalid`).

## Consola del colegio (REQ-CNS-036 / UX-CNS-005, DEC-BR-019)

Pantallas HTML server-rendered (sin JS, CSP estricta) activadas con la opción `staffUi` de `createConsentFlowHttpServer` (dev.ts la pasa). Sin ella las rutas no existen (404).

| Ruta | Qué hace |
|---|---|
| `GET /staff` | Entrada (acceso real pendiente de APR-IDP: botón deshabilitado). Con sesión redirige a la lista. |
| `GET /staff/students` | Lista de alumnos y estado; usa la misma lógica que `GET /staff/roster` (API-CNS-116), una fila en access_log por GET. Exige Sec-Fetch-Site `same-origin`, o `none` con Mode=navigate y Dest=document. |
| `POST /staff/students/invite` · `/review` · `/send` | Formulario, resumen y envío (EN0→I1→I2→I3) con CSRF + Origin; las refs van en campos ocultos, nunca en la URL. |
| `GET /staff/students/sent` | Confirmación tras PRG (cookie flash con solo la etiqueta del alumno). |
| `POST /staff/logout` | Borra las cookies de sesión. |
| `POST /staff/dev-login` | Botón "Entrar (solo desarrollo)" en `/staff`: existe SOLO con `CNS_ENVIRONMENT=LOCAL` y fixture dev; usa el mismo login dev, sin ampliar privilegios. Fuera de LOCAL responde 404 y el botón no se renderiza. |

La consola `/__dev/staff-console` se mantiene. El copy legal es un marcador (`COPY LEGAL PENDIENTE — Carlos`).
