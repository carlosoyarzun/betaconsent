# Guardrail Ports & Adapters

Gobierna: `ADR-001 §11` (Ports & Adapters, rev. 7, ACCEPTED 2026-09-26) · Jira `CA-136` (H21) ·
`SEC-CNS-010` (SEC-review-CA136, lampone-security: ronda 1 BLOQUEADO con 9 P1, corregido
P1-01..P1-08; ronda 2 re-verificación BLOQUEADO con residuo R-01..R-03 + P2, corregido).
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
3. **Primitivas peligrosas, como REFERENCIA (no solo llamada)**:
   - **En todo `src/**`, incluidos los adaptadores**: `import()`/`require()`/
     `createRequire(...)(...)` con argumento no literal; cualquier referencia a `require`
     que no sea `require('literal')` directo (alias, `.call`, `.apply`, paso como valor),
     salvo `require.resolve('literal')`; cualquier propiedad `.require` de un identificador
     distinto de `module`/`require` (p.ej. `process.mainModule.require`,
     `globalThis.require`); `import.meta.resolve(...)`; cualquier referencia a `eval`
     (llamada directa, `(0, eval)`, `globalThis.eval`, `const e = eval`,
     `Reflect.apply(eval, ...)`).
   - **Fuera de `src/infra/adapters/**` además**: cualquier import de `module`/`vm`/
     `child_process`/`worker_threads`/`inspector` (con o sin prefijo `node:`); cualquier
     identificador o propiedad `Function`, `createRequire`, `getBuiltinModule`, `_load`,
     `binding`, `_linkedBinding`, `dlopen`, `mainModule` o `constructor`, como referencia
     (identificador libre, propiedad por nombre o computada con literal, import/alias,
     destructuring, o como primer argumento de `Reflect.apply`/`Reflect.construct`);
     cualquier acceso a propiedad (`.x` o `[...]`) de un identificador literalmente llamado
     `module` o `require`, sea cual sea la propiedad.
4. **Capas — allowlist**: solo `src/server/entrypoints/**` y `src/infra/**` pueden importar
   (de forma relativa) `src/infra/**`. Cualquier otro directorio (existente o nuevo) que lo
   haga, falla.
5. **Capas — cliente**: `src/client/**` nunca importa `src/server/**` ni `src/infra/**`.
6. **Especificador no resoluble**: todo import que no sea relativo-y-resoluble **dentro de
   `src/`** (comparado por segmentos de ruta, no por prefijo de cadena), un builtin de Node,
   o el nombre exacto de un paquete declarado en `package.json` → falla. Cubre alias de
   tsconfig, `#subpath` imports, rutas absolutas, `file://`, rutas "peladas" que imitan una
   interna (`src/infra/...`), y relativos que escapan de `src/` (`../../../tools/x.ts`) o
   pasan por un segmento `node_modules` en cualquier posición.
7. **Configuración de alias no soportada**: cualquier `tsconfig*.json` (leído como JSONC con
   `ts.readConfigFile`, siguiendo `extends` con `ts.parseJsonConfigFileContent`) con
   `paths`/`baseUrl` (directo o heredado), o con un error de parseo/resolución; o
   `package.json` con `imports`/`workspaces` — el guardrail no resuelve alias, así que su
   sola presencia (o un tsconfig que no pudo leerse) es una violación.
8. **Manifiesto**: SDK `adapters-only` sin adaptador consumidor; alias `npm:` que resuelve a
   un SDK de la deny-list; dependencia no-registry (`file:`/`link:`/`git...`/URL); SDK
   `forbidden` como transitivo en `package-lock.json` (lockfile v3, por nombre real de cada
   entrada); **ausencia de `package-lock.json` v3 legible** (sin él no se puede verificar el
   árbol transitivo, así que es en sí mismo una violación).
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

`tests/guardrails/ports-adapters/fixtures/evasion-corpus-sec-cns-010/` contiene el corpus 1
(28 técnicas de evasión + 2 puntos estructurales, symlinks y `node_modules` vendorizado).
`tests/guardrails/ports-adapters/fixtures/evasion2-corpus-sec-cns-010/` contiene el corpus 2
de la re-verificación (12 casos: referencia sin llamada a construcciones peligrosas, acceso
computado, eval indirecto, `.constructor`, destructuring, `Reflect.apply`/`construct`,
`new Worker({eval:true})`, `_load`/`binding`/`dlopen`, import relativo que escapa de `src/` o
entra a `node_modules/`, tsconfig JSONC con `extends`), más una fixture individual por caso
(`r01-*`, `r02-*`, `r03-*`) para aislar cada regla. Los tests
`corpus de evasión SEC-CNS-010...` y `corpus de evasión 2 SEC-CNS-010...` (en
`guardrail.test.ts`) verifican que **todos** los puntos de ambos corpus producen al menos
una violación.

**Nota sobre alcance:** este guardrail detecta evasiones conocidas por referencia estática
(identificador, propiedad, acceso computado con literal), no por flujo de datos completo.
No puede, por ejemplo, detectar un identificador reconstruido carácter por carácter en
runtime. Esa evasión deliberada residual la cubren, de forma parcial, la revisión humana
(CODEOWNERS, sujeta a P1-08/P1-09) y la regla de manifiesto: "sin el SDK instalado no hay
nada que cargar" aplica solo a los SDKs `forbidden` y a los SDKs sin adaptador consumidor,
no a un SDK `adapters-only` ya instalado (p. ej. `nodemailer` del sink), que el dominio
podría cargar de forma ofuscada en runtime. El egress deny-by-default de ADR-003 §3 (c)
aún no existe en LOCAL ni en CI (se verifica en STAGING, bloqueado por H19), así que en IT0
no compensa esta evasión.

**Riesgo residual — PENDIENTE DE ACEPTACIÓN DE CARLOS (PR CA-136):**

> 1. El guardrail no detecta evasión deliberada por construcción dinámica en runtime (p. ej.
>    un identificador armado carácter por carácter) de un SDK `adapters-only` ya instalado
>    por un adaptador; los SDKs `forbidden` y los SDKs sin adaptador no están instalados.
> 2. Hasta que exista el ruleset de `main` (P1-09) y el egress de ADR-003 §3 (c) en STAGING,
>    el único control es la revisión humana del PR; en IT0 el impacto se limita a datos
>    sintéticos, sin credenciales de proveedor.
> 3. Aceptado para IT0 LOCAL + CI; se revalúa antes de STAGING o datos reales (gate H19 /
>    ADR-010), dueño lampone-security.

## Dependencias

Solo `devDependencies`, versiones exactas, sin scripts de ciclo de vida:

- `typescript` (TypeScript compiler API para parsear el AST de los archivos escaneados)
- `@types/node`

Sin dependencias nuevas en runtime de producto. Node fijado en `24.21.0` (`engines.node` y
`actions/setup-node`; SEC-CNS-010 P1-07).
