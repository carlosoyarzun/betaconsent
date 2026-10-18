# E2E Playwright: línea base de la UI de titulares (ADR-001 F1)
Oráculo de equivalencia SSR -> SPA. Selectores semánticos (roles, nombres accesibles, texto); sin clases `lp-*`.
Solo datos sintéticos (dominio example.invalid), cero PII. IDs `E2E-CNS-001..088` = `TEST-CNS-(1965+n)` en
`traceability/test-matrix.csv` (capa `e2e`).

## Correr
    npm ci && npx playwright install chromium
    npm run test:e2e                      # = playwright test -c e2e/playwright.config.ts
    npx playwright test -c e2e/playwright.config.ts e2e/specs/05-revocation.spec.ts
Reporte HTML en `e2e/report/`, trazas en `e2e/test-results/` (ambos gitignored).

## Modos
- Por defecto: cada test arranca su `dev.ts` (LOCAL, store en memoria, puerto libre) y lo apaga. Sin Postgres ni Docker.
- Externo: `E2E_BASE_URL=http://127.0.0.1:3000 npm run test:e2e` contra un servidor ya levantado, p. ej.
  `CNS_ENVIRONMENT=LOCAL CNS_UI_MODE=spa node src/server/entrypoints/dev.ts` (la SPA se sirve desde el mismo dev.ts).
  Un servidor compartido tiene 6 alumnos sintéticos: usar `--workers=1` y filtrar por spec.
- `E2E_START_SERVER=1`: Playwright levanta un `dev.ts` compartido en :3000. `CNS_UI_MODE` se hereda del entorno.
- `E2E_DEBUG=1`: reenvía stderr de `dev.ts`.

## Fixtures (`e2e/fixtures`)
`app.readLatestOtp()`, `app.createInvitation()`, `app.createManagementLink(page)`, `app.createRecoveryLink(page)`,
`app.forceApplyFailure(page, ruta)` (503 simulado en el navegador). Buzones: `/__dev/otp-sink`, `message-sink`, `recovery-sink`.

## Sin hook de servidor (skips)
E2E-CNS-058 y 070: 503 real del apply-guard y token/OTP no consumido tras 503. No existe `CNS_TEST_*` en el proceso web.

## Hallazgos conocidos (tests `test.fail`: se invierten al corregirse)
F-E2E-01 (P1 LOCAL) enlace de gestión sembrado: OTP submit 500 (047) · F-E2E-02 (P2) sin nosniff (076) ·
F-E2E-03 (P2) sin frame-ancestors en 7/8 páginas: CORREGIDO por #114 (075 ahora es aserción normal) · F-E2E-04 (P2) axe target-size (088).
Observaciones: O-1 reapertura de invitación OPENED (008) · O-2 marcadores `[N]`/P-xx en /verify (011) ·
O-3 reenvío de OTP responde límite al primer clic (018) · O-4 marca de agua distinta decisión vs revocación.
