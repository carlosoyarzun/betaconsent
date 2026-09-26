# Guardrail Ports & Adapters

Gobierna: `ADR-001 §11` (Ports & Adapters, rev. 7, ACCEPTED 2026-09-26) · Jira `CA-136` (H21).
Spec: `specs/guardrail-ports-adapters.spec.yaml`.

Falla el build si:

1. Un archivo fuera de `src/infra/adapters/**` importa (import estático, `export ... from`,
   `import()` con literal, `require()` o `<x>.createRequire(...)(...)` con literal) un módulo
   de la lista de denegación de SDKs de proveedor (`deny-list.json`), incluidos subpaths
   (`aws-sdk/clients/s3`) y scopes con wildcard (`@aws-sdk/*`).
2. `src/server/modules/**`, `src/server/platform/**` o `src/server/ports/**` importan
   (de forma relativa) `src/infra/**`.
3. `src/client/**` importa (de forma relativa) `src/server/**` o `src/infra/**`.
4. `package.json` declara un paquete de la lista de denegación sin que ningún archivo
   bajo `src/infra/adapters/**` lo importe (SDK "fantasma" sin adaptador consumidor).

## Uso

```bash
npm run guardrail:ports-adapters          # corre contra el repo (root = cwd)
node tools/guardrails/ports-adapters/check.ts <root>   # corre contra un árbol arbitrario
npm test                                   # tests unitarios + fixtures negativas/positivas
npm run typecheck                          # tipos estrictos del guardrail y sus tests
```

Sale con código `0` si no hay violaciones, `1` si hay al menos una (con detalle en stderr).
Se ejecuta en CI en `.github/workflows/guardrails.yml` en cada PR y push a `main`.

## Cómo se cambia la lista de denegación

`deny-list.json` está versionado y tiene CODEOWNERS (`.github/CODEOWNERS`): Carlos
(`@carlosoyarzun`) y, cuando se designe, un revisor humano de seguridad. Ningún agente
IA es code owner. Todo cambio a la lista (agregar, quitar o modificar una entrada) requiere
esa revisión antes de mergear. La lista actual es una **propuesta inicial** (ADR-001 §11);
`lampone-security` debe fijarla como versión final antes del primer commit en `src/`.

Formato de una entrada:

```json
{ "package": "@aws-sdk/*", "note": "AWS SDK v3, todos los paquetes con scope @aws-sdk" }
```

- Nombre exacto de paquete (`"aws-sdk"`) o scope completo con wildcard (`"@scope/*"`).
- Los subpaths del paquete (`aws-sdk/clients/s3`) se cubren automáticamente: el guardrail
  extrae el nombre de paquete del especificador antes de comparar.

## Limitaciones conocidas (ver `openItems` en la spec)

- Solo se resuelven especificadores de import **relativos** (`./`, `../`) para las reglas
  de capa (2) y (3). Alias de paquete no relativos (p. ej. `tsconfig` `paths` o workspaces)
  no se resuelven en esta versión.
- `import()`/`require()` con especificador **no literal** no se evalúan aquí (ya están
  prohibidos por otra regla de lint, ADR-001 §6.1); este guardrail solo puede verificar
  literales de cadena contra la lista de denegación.
- El patrón `createRequire` solo se detecta como llamada encadenada (`x.createRequire(...)(...)`)
  o como llamada a un identificador literalmente llamado `require`; no se hace seguimiento
  de flujo de datos de variables con otro nombre.

## Dependencias

Solo `devDependencies`, versiones exactas, sin scripts de ciclo de vida:

- `typescript` (TypeScript compiler API para parsear el AST de los archivos escaneados)
- `@types/node`

Sin dependencias nuevas en runtime de producto.
