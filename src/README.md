# src/

Código de producto de la Consent App.

Gobierna: `REQ-CNS-###`, `API-CNS-###`, `RULE-CNS-###`.

Estado: slices verticales de dominio IT0 con servidor HTTP real (`node:http`, un solo proceso;
HTML server-rendered sin JS; desvíos AD-1…AD-4 de ADR-001, ver `registers/findings-register-IT0.md`)
y adaptadores Postgres reales (`infra/adapters/postgres`, migraciones en `db/`) además de los
in-memory. Solo datos sintéticos (IT0, DEC-BR-014). Capas: `server/modules` (dominio),
`server/ports` (interfaces), `infra/adapters` (in-memory y Postgres), siguiendo el guardrail de
`tools/guardrails/ports-adapters/`.

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
| `POST /staff/logout` | Revoca el sid en servidor (la cookie robada deja de servir) y borra las cookies. Con `Content-Type: application/json` y `X-CSRF-Token` es el equivalente de API (200 `{}`). |
| `POST /staff/dev-login` | Botón "Entrar (solo desarrollo)" en `/staff`: existe SOLO con `CNS_ENVIRONMENT=LOCAL` y fixture dev; usa el mismo login dev, sin ampliar privilegios. Fuera de LOCAL responde 404 y el botón no se renderiza. |

### Sesión STAFF (CA-138, SEC-CNS-018 rev. 2 D-3, SEC-CNS-020 P2-3)

La cookie `__Host-cns-staff` lleva `sid` (32 bytes aleatorios), `iat` y `exp` firmados (`entrypoints/http/staff-session.ts`) y cada request se valida además contra el registro del servidor (`ports/staff-session-store.port.ts`; adaptadores in-memory y Postgres `app.staff_session`, migración `0021`, RLS FORCE por tenant, solo el hash del sid). Fallo de cualquier tipo (firma, `exp`, revocada, inactividad, otro tenant/principal/rol) = el mismo 404 uniforme. Logout revoca el sid; cada login emite un sid nuevo y revoca el previo del navegador. El token CSRF de la consola es `HMAC(clave HKDF propia, sid)`, y el cursor de `GET /staff/roster` (AAD) y la cookie flash quedan ligados al sid. El dev-login LOCAL usa el mismo `issueStaffSession` (sin privilegios extra). Las sesiones expiradas se limpian al iniciar sesión (solo las ya vencidas y fuera de retención; la policy de DELETE lo impone).

Parámetros aprobados por Carlos el 2026-10-05 (`server/modules/common/approved-parameters.ts`, prefijo `APPROVED_STAFF_SESSION_`): vida absoluta 8 h, inactividad 30 min, retención de filas expiradas 24 h.

### Sesión CASE (CA-139, SEC-CNS-018 rev. 2 D-3; P1-1 de la revisión de CA-138)

Misma mecánica para `__Host-cns-case` (RIGHTS_OPERATOR/APPROVER), con la ligadura al `caseRef` conservada: `entrypoints/http/case-session.ts` (sid/iat/exp firmados, CSRF `HMAC(clave HKDF propia, sid)`, `issueCaseSession`, `revokeCaseSessionCookie`), puerto `ports/case-session-store.port.ts`, adaptadores in-memory y Postgres `app.case_session` (migración `0022`, RLS FORCE por tenant, solo hash del sid, `case_ref` en el registro). Diseño: tabla y puerto propios (no se generalizó `app.staff_session` con `session_kind`) para no tocar `0021` ni el código STAFF ya mergeado. Validación por request en `case-confirmation.handler.ts` (`authenticateCaseSession`): firma + `exp`, caseRef del path, registro servidor (tenant/caso/principal/rol, no revocada, inactividad) y CSRF del sid; cualquier fallo = 404 uniforme (el CSRF ajeno, 403). `POST /platform/case-session/logout` (API-CNS-193) revoca el sid y borra las cookies. `storeMode=postgres` exige inyectar `caseSessions` (fail-closed). Parámetros aprobados por Carlos el 2026-10-06 (`APPROVED_CASE_SESSION_*`): 8 h absoluta, 30 min de inactividad, 24 h de retención.

La consola `/__dev/staff-console` se mantiene. El copy legal es un marcador (`COPY LEGAL PENDIENTE — Carlos`).

CA-141: login, logout y rotación de las sesiones STAFF y CASE se registran en `ops.security_event` (migración `0025`, append-only, RLS FORCE, `app_rw` solo INSERT; puerto `ports/security-event.port.ts`, adaptadores Postgres e in-memory) en la MISMA transacción que crea o revoca la sesión (`session_ref` UUIDv4 de la base, migración `0023`). Si el evento no se puede escribir: 503 sin Set-Cookie ni borrado de cookies (fail-closed). Retención LD-15 PENDING; sin purga en IT0. Ver `specs/session.spec.yaml` GRD-SE-14.
