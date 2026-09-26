# Guardrail Ports & Adapters

Gobierna: `ADR-001 §11` (Ports & Adapters, rev. 7, ACCEPTED 2026-09-26) · Jira `CA-136` (H21) ·
`SEC-CNS-010` (SEC-review-CA136, lampone-security: BLOQUEADO con 9 P1, corregido P1-01..P1-08).
Spec: `specs/guardrail-ports-adapters.spec.yaml`.

Falla el build si:

1. **Deny-list, modo `adapters-only`**: un archivo fuera de `src/infra/adapters/**` importa
   (import estático, `export ... from`, `import()`/`require()`/`createRequire(...)(...)` con
   literal, `declare module "pkg"`, `/// <reference types="pkg" />`, o `import("pkg").Tipo`
   en posición de tipo) un módulo de la deny-list en modo `adapters-only` (`deny-list.json`),
   incluidos subpaths (`aws-sdk/clients/s3`), scopes con wildcard (`@aws-sdk/*`) y variantes
   de mayúsculas/minúsculas.
2. **Deny-list, modo `forbidden`**: lo mismo que (1), pero en **cualquier parte de `src/**`,
   incluidos los adaptadores** — y también en `package.json`/`package-lock.json`. No hay
   ubicación válida para estos SDKs durante IT0 (email/SMS de proveedor, telemetría SaaS,
   analytics/flags, LLM SaaS: ver `deny-list.json`).
3. **Primitivas peligrosas** (en todo `src/**`, incluidos los adaptadores): `import()`/
   `require()`/`createRequire(...)(...)` con argumento no literal; cualquier referencia a
   `require` que no sea `require('literal')` directo (alias, `.call`, `.apply`, paso como
   valor), salvo `require.resolve('literal')`; cualquier `<x>.require` (`module.require`,
   `process.mainModule.require`, `globalThis`/`global`/`window.require`, `Module._load`, o
   cualquier otra propiedad `.require`); `eval(...)`, `Function(...)`/`new Function(...)`;
   `import.meta.resolve(...)`. **Fuera de `src/infra/adapters/**` además**: cualquier import
   de `module`/`vm`/`child_process` (con o sin prefijo `node:`); cualquier identificador o
   propiedad `createRequire`, como referencia (se llame o no de inmediato).
4. **Capas — allowlist**: solo `src/server/entrypoints/**` y `src/infra/**` pueden importar
   (de forma relativa) `src/infra/**`. Cualquier otro directorio (existente o nuevo) que lo
   haga, falla.
5. **Capas — cliente**: `src/client/**` nunca importa `src/server/**` ni `src/infra/**`.
6. **Especificador no resoluble**: todo import que no sea relativo-y-resoluble dentro de la
   raíz, un builtin de Node, o el nombre exacto de un paquete declarado en `package.json` →
   falla (cubre alias de tsconfig, `#subpath` imports, rutas absolutas, `file://`, y rutas
   "peladas" que imitan una interna como `src/infra/...`).
7. **Configuración de alias no soportada**: cualquier `tsconfig*.json` con `paths`/`baseUrl`,
   o `package.json` con `imports`/`workspaces` — el guardrail no los resuelve, así que su
   sola presencia es una violación.
8. **Manifiesto**: SDK `adapters-only` sin adaptador consumidor; alias `npm:` que resuelve a
   un SDK de la deny-list; dependencia no-registry (`file:`/`link:`/`git...`/URL); SDK
   `forbidden` como transitivo en `package-lock.json` (lockfile v3).
9. **Estructura del árbol**: cualquier symlink bajo `src/` (no se sigue); cualquier
   `node_modules`/`dist`/`build`/`coverage` bajo `src/` (se recorre igual, fail-closed); un
   error de lectura del árbol distinto de "no existe `src/`" se propaga.

## Uso

```bash
node tools/guardrails/ports-adapters/check.ts <root>   # corre contra un árbol arbitrario (root = cwd si se omite)
npm run guardrail:ports-adapters                        # atajo de npm equivalente (no usar en CI, ver abajo)
npm test                                                 # tests unitarios + fixtures negativas/positivas
npm run typecheck                                        # tipos estrictos del guardrail y sus tests
```

Sale con código `0` si no hay violaciones, `1` si hay al menos una (con detalle en stderr).
Se ejecuta en CI en `.github/workflows/guardrails.yml` en cada PR y push a `main`, invocando
`check.ts` **directamente** (no vía script de npm): el veredicto no depende de lo que
`package.json` defina en `"scripts"` (SEC-CNS-010 P1-08).

## Cómo se cambia la lista de denegación

`deny-list.json` está versionado y tiene CODEOWNERS (`.github/CODEOWNERS`), que también
cubre `package.json`, `package-lock.json`, `tsconfig.json` y `tests/guardrails/` (estos
tres últimos porque pueden cambiar qué corre CI o cómo se resuelven los especificadores,
SEC-CNS-010 P1-08): Carlos (`@carlosoyarzun`) y, cuando se designe, un revisor humano de
seguridad. Ningún agente IA es code owner. La lista es **FINAL_IT0** (fijada por
`lampone-security` en SEC-CNS-010); quitar una entrada `forbidden` requiere DEC y
CODEOWNERS.

Formato de una entrada:

```json
{ "package": "@aws-sdk/*", "mode": "adapters-only", "category": "cloud-aws" }
```

- Nombre exacto de paquete (`"aws-sdk"`) o scope completo con wildcard (`"@scope/*"`).
- `mode`: `"adapters-only"` (solo importable desde `src/infra/adapters/**`) o `"forbidden"`
  (prohibido en todo `src/**`, incluidos los adaptadores, y en el manifiesto/lockfile).
- Los subpaths del paquete (`aws-sdk/clients/s3`) y las variantes de mayúsculas/minúsculas
  se cubren automáticamente.

## Limitaciones conocidas (ver `openItems` en la spec)

- Solo se resuelven especificadores de import **relativos** (`./`, `../`) contra archivos
  reales de la raíz escaneada. Alias no relativos (tsconfig `paths`/`baseUrl`, package.json
  `imports`/`workspaces`) no se resuelven: su sola presencia en la configuración es, en
  cambio, una violación (`CONFIG_ALIAS_NOT_SUPPORTED`).
- La allowlist de dependencias con owner de ADR-001 §5/§11 (regla 3) no está implementada
  aquí; queda diferida a H03.
- El seguimiento de "createRequire asignado a una variable con nombre arbitrario y llamado
  después" no hace análisis de flujo de datos completo; se detecta por la **referencia** al
  identificador/propiedad `createRequire` (import, alias, member access), que cubre los
  patrones idiomáticos conocidos, no cualquier ofuscación posible.
- `.vue`/`.svelte` se escanean como JS genérico (best-effort): no hay soporte real de SFC.
  El stack de Consent App es React + TS (ADR-001 §1); estas extensiones no tienen lugar
  legítimo en el repo.

## Corpus de evasión (SEC-CNS-010)

`tests/guardrails/ports-adapters/fixtures/evasion-corpus-sec-cns-010/` contiene el corpus de
28 técnicas de evasión usado por `lampone-security` para bloquear la primera versión, más 2
puntos estructurales (symlinks, `node_modules` vendorizado). El test
`corpus de evasión SEC-CNS-010: todos los puntos de evasión fallan cerrado` (en
`guardrail.test.ts`) verifica que **todos** producen al menos una violación.

## Dependencias

Solo `devDependencies`, versiones exactas, sin scripts de ciclo de vida:

- `typescript` (TypeScript compiler API para parsear el AST de los archivos escaneados)
- `@types/node`

Sin dependencias nuevas en runtime de producto. Node fijado en `24.21.0` (`engines.node` y
`actions/setup-node`; SEC-CNS-010 P1-07).
