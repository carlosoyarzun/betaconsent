# frontend/ — SPA React (ADR-001 rev. 8 F1)

React 19 + TypeScript `strict` + Vite 8. Build estático a `dist/` (raíz del repo), que el web sirve con `CNS_UI_MODE=spa`.
Ningún dato real: solo sintéticos (DEC-BR-014). Patrón para migrar pantallas: `src/pages/README.md`.

| Comando | Qué hace |
|---|---|
| `npm run build:frontend` | typecheck estricto + `vite build` -> `dist/` (archivos con hash, sin inline) |
| `npm run test:frontend` | Vitest + Testing Library + jsdom |
| `npm run dev:frontend` | Vite en `http://127.0.0.1:5173` con proxy al backend `127.0.0.1:3000` |
| `node tools/guardrails/dist-csp-check.ts` | valida que `dist/` no trae `<style>`, `style=`, `on*=` ni `<script>` inline |

Servir con el backend: `npm run build:frontend && CNS_ENVIRONMENT=LOCAL CNS_UI_MODE=spa node src/server/entrypoints/dev.ts`.
`CNS_UI_MODE=ssr` (default) mantiene el HTML renderizado por el servidor. En `spa`, hasta migrar las 7 pantallas restantes,
solo `/welcome` es funcional (las demás muestran un esqueleto): no usar `spa` fuera de pruebas de la migración.

## Limitaciones de `dev:frontend`
- El guard CSRF/Origin (GRD-CM-10) compara `Origin` con `CNS_ALLOWED_ORIGIN` (default de `dev.ts`: `http://127.0.0.1:3000`).
  El navegador enviaría `http://127.0.0.1:5173`; el proxy de Vite **reescribe `Origin` al del backend** (`CNS_DEV_BACKEND`,
  default `http://127.0.0.1:3000`) en los POST proxeados. Si arrancas el backend con otro `CNS_ALLOWED_ORIGIN` o puerto,
  define `CNS_DEV_BACKEND` con ese mismo valor exacto. No se relaja el guard del servidor.
- En dev las 8 rutas HTML las sirve Vite (siempre `cns-page-state=ready`): **no** se ejecuta la lógica de sesión/404 uniforme
  del servidor. Para verificar sesión, cookies y estado uniforme usa el build con `CNS_UI_MODE=spa`.
- Las cookies `__Host-*` son `Secure`: en `http://127.0.0.1` funcionan en Chromium/Firefox, no en Safari.
- Los canjes `/i/{token}`, `/m/{token}`, `/r/{token}` se proxean y devuelven `Location` relativo a Vite.

## Frontera (guardrail)
`frontend/src` y `frontend/tests` no importan nada fuera de `frontend/` (ni `src/`, `db/`, `tools/`); solo `import type`
de `contracts/**`. Única excepción: `styles/index.css` enlaza `design-system/index.css` y el `app.css` que hoy sirve el SSR
(se moverá a `frontend/src/styles/` al retirar el SSR). Ver `tools/guardrails/frontend-boundary.ts`.
