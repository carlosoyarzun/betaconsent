# pages/ — patrón para migrar una pantalla (ADR-001 F1)

`welcome.tsx` es la referencia. Para migrar otra pantalla (solo se edita SU archivo `pages/<ruta>.tsx`;
`routes.ts` ya la registra, así no hay conflictos entre ramas):

1. Fuente: `*-page.ts` (copy, clases `lp-*`, ARIA, ids) + `assets/<x>.js` (comportamiento) en
   `src/server/entrypoints/http/`. Mismo copy, mismas clases, mismos atributos; no se reescriben estilos.
2. Estructura: el componente devuelve el `<main>` (la cabecera de marca la pone `app.tsx`). Piezas
   compartidas en `components/` (`Stepper`, `AlertHead`, `HelpLink`, `usePageTitle`); si falta una, créala
   allí con su test y cita la función de `guest-layout.ts` que replica.
3. Red: solo `postJson` de `api/client.ts` (CSRF, `credentials`, errores `{ok:false,error:{kind,status,code,correlationId}}`).
   Nada de `fetch` directo. Misma semántica de códigos que el `.js` (p. ej. 404 -> texto uniforme, 503 -> aviso).
4. Navegación entre pantallas: `navigation.assign(ruta)` (recarga completa, igual que `window.location.assign`).
5. Estado uniforme (404 INV-CM-05): `props.pageState === "uniform-error"` -> render del `render*UniformErrorPage`
   equivalente. Los hooks van ANTES del `return` temprano.
6. Elementos ocultos del SSR (`hidden`): renderízalos siempre con `hidden={...}` para conservar el comportamiento de
   los `role="alert"` / `aria-live`; foco: replica exactamente `.focus()` del `.js` (con `useRef`/`useEffect`).
7. Datos que hoy se interpolan en el servidor (`/decision`: relaciones, versión servida, etiqueta; `/manage`: variante
   entrada/estado/revocada) NO están en el HTML de `spa`: requieren un endpoint JSON GET nuevo (decisión de contrato,
   consultar a `lampone-architect`); no inventes uno sin ID gobernante.
8. Test en `frontend/tests/pages/<ruta>.test.tsx` con el DOM real (`role`, foco, cabeceras de la petición mock).
9. No importes nada de `src/` ni de `db/` (regla de guardrail); copy legal pendiente = `LEGAL DECISION`, no se redacta.
