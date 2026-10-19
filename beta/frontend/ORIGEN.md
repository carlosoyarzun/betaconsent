# Origen de beta/frontend/

Gobierna: DEC "Reconstrucción mínima" (Carlos, 2026-10-19), plan v2 tarea H1-10.
Copiado de `frontend/` @ 9345b78 (React 19.3 + TS strict + Vite 8 + vitest 5, router propio, `api/client.ts`, tokens del DS).

## Archivos modificados respecto del origen
- `vite.config.ts`: `fs.allow` apunta a `${here}/../../design-system` (el DS sigue en la raíz del repo). `outDir: "../dist"` ahora resuelve a `beta/dist/` (manifest, `index.html`, assets con hash: mismo esquema).
- `src/styles/index.css`: `@import "../../../../design-system/index.css"` (un nivel más). Dependencia externa a `beta/`: solo `design-system/` (CSS), no se copia; el CSS se inlinea en el bundle `dist/assets/style-*.css`.
- `src/components/b/verify-screen.tsx` y `src/components/c/rights-verify.tsx`: la vía "Abrir caso con soporte humano" (`POST /rights-case/open`) pasa a botón "Contactar al colegio" que muestra un mensaje estático en `#rights-locked-feedback` (role=status). Sin red. Copy BORRADOR (pendiente de Carlos): "Si no puedes recibir el código, contacta al colegio. El colegio verificará tu identidad y te indicará cómo continuar." Se conserva el id `open-human-case-btn`.
- `src/api/pages-c.ts`: se elimina `openHumanCase`.
- `tests/pages/verify.test.tsx`, `tests/pages/rights-verify.test.tsx`, `tests/api/pages-c.test.ts`: adaptados a lo anterior (sin llamada a `/rights-case/open`).
- `README.md`, `src/pages/README.md`: sin cambios (describen el origen; comandos válidos desde `beta/`).
- Fuera de la carpeta: `beta/package.json` (scripts `typecheck:frontend`, `build:frontend`, `test:frontend`, `dev:frontend`, `check:dist` + deps react/vitest/vite/testing-library con las mismas versiones fijas del origen), `beta/scripts/check-dist.ts`, job `beta-frontend` en `.github/workflows/beta.yml`.
- Sin `/recover` (es H2-01). El botón "Enviar enlace de recuperación" y la ruta `/recovery/confirm` siguen como en el origen.

## Endpoints que el backend `beta/` (H1-05) debe implementar
Contrato: `contracts/openapi/consent-it0.openapi.yaml` (línea del path). POST: JSON, cookie `__Host-cns-csrf` + header `x-csrf-token` (double-submit, `credentials: same-origin`, `content-type: application/json`; body `{}` salvo indicación). GET page-state: sin CSRF, `accept: application/json`.

| Método y ruta | Línea | Payload / respuesta que lee la SPA |
|---|---|---|
| GET `/decision/page-state` | 872 | `{relationshipRefs: string[], servedVersion:{consentVersion,privacyNoticeVersion,text}, subjectLabel?}`; 404/uniforme -> pantalla de error uniforme |
| GET `/manage/page-state` | 899 | `{variant: "entry"\|"status"\|"revoked"}` |
| POST `/invitation/open` | 589 | `{}`; (welcome) |
| POST `/otp/request` | 623 | `{}`; 202 uniforme; 404 -> uniforme |
| POST `/otp/submit` | 653 | `{code}`; 200 ok; 422 `OTP_CODE_REJECTED`; 423/409 `OTP_LOCKED`, `OTP_BUDGET_EXHAUSTED_DECISION\|RIGHTS`; devuelve `{result?,scope?}` |
| POST `/otp/resend` | 698 | `{}`; 202; 409 `OTP_RESEND_LIMIT`; 404 |
| POST `/decision/steps` | 755 | `{stepKind:"CONTEXT_INFORMATION_VIEWED"\|"CONSENT_VERSION_VIEWED"}`, `{stepKind:"DECISION_MAKER_AUTHORITY_DECLARED",relationshipRef,authorityDeclared:true}`, `{stepKind:"SUBJECT_CONFIRMED",subjectConfirmed:true}` |
| POST `/decision/submit` | 787 | `{purposes: ...}` (ver `decision.tsx:277`) |
| POST `/decision/subject-mismatch` | 832 | `{}`; 200 |
| POST `/manage/revocation` | 928 | `{}` |
| POST `/manage/revocation/verify` | 959 | `{}`; idempotente |
| POST `/manage/revocation/confirm` | 990 | `{}`; responde `{revocationRef?}` |
| POST `/manage/revocation/withdraw` | 1023 | `{}` |
| POST `/manage/recovery-link` | 1054 | `{}`; 202 uniforme (la SPA lo llama desde el bloqueo; H1 puede responder 202 sin enviar) |
| POST `/recovery/revoke` | 1087 | `{confirmTotalWithdrawal:true}`; responde `{state?,revocationRef?,result?}` |

Ya NO se llama: `POST /rights-case/open` (1200), `/decision/start` (726).
Shell HTML (GET, 8 rutas, sirven `dist/index.html`): `/welcome /verify /decision /manage /manage/verify /manage/revocation/verify /manage/revocation/confirm /recovery/confirm`. El servidor debe fijar la cookie CSRF en cada GET de página y reescribir `<meta name="cns-page-state" content="ready">` a `uniform-error` cuando corresponda (404 uniforme). Canjes 303 `/i /m /r` los hace el backend. Lee `dist/.vite/manifest.json` al arrancar.
