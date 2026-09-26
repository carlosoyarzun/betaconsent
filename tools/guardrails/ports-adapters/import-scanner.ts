// Gobierna: ADR-001 §11, CA-136 (H21), SEC-CNS-010 (P1-01, R-01).
// Detecta, con el TypeScript compiler API (AST, no expresiones regulares):
//   (a) especificadores de módulo importados de forma verificable (literal):
//       import estático, `export ... from`, `import()` dinámico con literal, `require()`
//       con literal y `<x>.createRequire(...)(...)` con literal;
//   (b) usos de primitivas peligrosas que permiten evadir (a), fail-closed. Este guardrail
//       es un control contra el acoplamiento accidental a SDKs de proveedor y contra las
//       evasiones conocidas (ver `tests/guardrails/ports-adapters/fixtures/evasion-corpus-
//       sec-cns-010/` y `evasion2-corpus-sec-cns-010/`); no es un analizador de flujo de
//       datos y no puede cubrir toda ofuscación deliberada posible (p.ej. reconstruir un
//       nombre carácter por carácter). Esa evasión deliberada residual se cubre con
//       revisión humana vía CODEOWNERS, con la regla de manifiesto (sin el SDK instalado
//       no hay nada que cargar en runtime) y con el egress deny-by-default de ADR-003 §3 (c).
//
//   Primitivas detectadas, como REFERENCIA (no solo llamada), en todo src/** salvo
//   src/infra/adapters/**:
//     - `require`/`eval`: en TODO src/**, incl. adaptadores (ver reglas específicas abajo).
//     - `Function` (como valor, `new Function(...)`, o vía `.constructor`/`["constructor"]`
//       de cualquier expresión), `createRequire`, `getBuiltinModule`, `_load`, `binding`,
//       `_linkedBinding`, `dlopen`, `mainModule`: fuera de adaptadores.
//     - cualquier acceso a propiedad (`.x` o `[...]`) de un identificador literalmente
//       llamado `module` o `require`, sea cual sea la propiedad: fuera de adaptadores.
//     - `Reflect.apply`/`Reflect.construct` cuyo primer argumento sea uno de los anteriores.
//     - import()/require()/createRequire(...)(...) con argumento no literal.
//     - `import.meta.resolve(...)`.

import ts from "typescript";

export type ModuleSpecifierKind =
  | "static-import"
  | "export-from"
  | "dynamic-import"
  | "require"
  | "create-require-call"
  | "declare-module"
  | "type-reference-directive";

export interface ModuleSpecifierFinding {
  category: "module-specifier";
  kind: ModuleSpecifierKind;
  specifier: string;
  line: number;
}

export type PrimitiveFindingKind =
  | "non-literal-dynamic-call"
  | "forbidden-require-usage"
  | "forbidden-eval-reference"
  | "forbidden-import-meta-resolve"
  | "forbidden-dangerous-reference";

export type PrimitiveScope = "everywhere" | "outside-adapters";

export interface PrimitiveFinding {
  category: "primitive";
  kind: PrimitiveFindingKind;
  line: number;
  /** Solo para "forbidden-dangerous-reference": el nombre detectado y su alcance. */
  name?: string;
  scope?: PrimitiveScope;
}

export type Finding = ModuleSpecifierFinding | PrimitiveFinding;

/** Nombres cuya sola referencia (identificador, propiedad, elemento computado con literal,
 * "bindingElement" de destructuring) es peligrosa fuera de src/infra/adapters/**. */
const DANGEROUS_REFERENCE_NAMES = new Set([
  "Function",
  "createRequire",
  "getBuiltinModule",
  "_load",
  "binding",
  "_linkedBinding",
  "dlopen",
  "mainModule",
  "constructor",
]);

/** Identificadores cuyo primer argumento a Reflect.apply/Reflect.construct es peligroso;
 * mapeado a si la referencia correspondiente es de alcance "everywhere" u "outside-adapters". */
const REFLECT_TARGET_SCOPE: Record<string, PrimitiveScope> = {
  eval: "everywhere",
  require: "everywhere",
  Function: "outside-adapters",
  createRequire: "outside-adapters",
  getBuiltinModule: "outside-adapters",
  _load: "outside-adapters",
  binding: "outside-adapters",
  _linkedBinding: "outside-adapters",
  dlopen: "outside-adapters",
  mainModule: "outside-adapters",
};

function scriptKindFor(filePath: string): ts.ScriptKind {
  if (filePath.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (filePath.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (filePath.endsWith(".ts") || filePath.endsWith(".mts") || filePath.endsWith(".cts")) {
    return ts.ScriptKind.TS;
  }
  return ts.ScriptKind.JS;
}

/** true si el callee de una CallExpression termina en la propiedad `createRequire`. */
function isCreateRequirePropertyAccess(expr: ts.Node): expr is ts.PropertyAccessExpression {
  return ts.isPropertyAccessExpression(expr) && expr.name.text === "createRequire";
}

/** true si `expr` es la meta-propiedad `import.meta`. */
function isImportMeta(expr: ts.Node): boolean {
  return ts.isMetaProperty(expr) && expr.keywordToken === ts.SyntaxKind.ImportKeyword && expr.name.text === "meta";
}

/** true si `expr` es `import.meta.resolve` (el callee típico de `import.meta.resolve(...)`). */
function isImportMetaResolve(expr: ts.Node): boolean {
  return ts.isPropertyAccessExpression(expr) && expr.name.text === "resolve" && isImportMeta(expr.expression);
}

/** Quita envolturas sintácticas transparentes (paréntesis, `as X`, `!`, `<X>`) para llegar
 * a la expresión "real" que hay debajo, p.ej. en `(module as any)["require"]`. */
function unwrapExpression(expr: ts.Expression): ts.Expression {
  let current = expr;
  while (true) {
    if (ts.isParenthesizedExpression(current)) {
      current = current.expression;
    } else if (ts.isAsExpression(current) || ts.isSatisfiesExpression(current)) {
      current = current.expression;
    } else if (ts.isNonNullExpression(current)) {
      current = current.expression;
    } else if (ts.isTypeAssertionExpression(current)) {
      current = current.expression;
    } else {
      return current;
    }
  }
}

export function scanFileForFindings(filePath: string, sourceText: string): Finding[] {
  const sourceFile = ts.createSourceFile(
    filePath,
    sourceText,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    scriptKindFor(filePath),
  );

  const findings: Finding[] = [];

  const lineOf = (node: ts.Node): number =>
    sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;

  const pushModuleSpecifier = (
    specifierExpr: ts.Expression | undefined,
    kind: ModuleSpecifierKind,
    node: ts.Node,
  ): boolean => {
    if (specifierExpr !== undefined && ts.isStringLiteralLike(specifierExpr)) {
      findings.push({ category: "module-specifier", kind, specifier: specifierExpr.text, line: lineOf(node) });
      return true;
    }
    return false;
  };

  const pushPrimitive = (kind: PrimitiveFindingKind, node: ts.Node, extra?: { name?: string; scope?: PrimitiveScope }): void => {
    findings.push({ category: "primitive", kind, line: lineOf(node), ...extra });
  };

  const pushDangerousReference = (name: string, node: ts.Node): void => {
    pushPrimitive("forbidden-dangerous-reference", node, { name, scope: "outside-adapters" });
  };

  /** true si `call` es una de las formas "importadoras" que exigen argumento literal:
   * import(...), require(...) directo, o <x>.createRequire(...)(...) . */
  const isImportLikeCall = (call: ts.CallExpression): boolean => {
    const callee = call.expression;
    if (callee.kind === ts.SyntaxKind.ImportKeyword) return true;
    if (ts.isIdentifier(callee) && callee.text === "require") return true;
    if (ts.isCallExpression(callee) && isCreateRequirePropertyAccess(callee.expression)) return true;
    return false;
  };

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) {
      pushModuleSpecifier(node.moduleSpecifier, "static-import", node);
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) {
      pushModuleSpecifier(node.moduleSpecifier, "export-from", node);
    } else if (ts.isImportEqualsDeclaration(node)) {
      const ref = node.moduleReference;
      if (ts.isExternalModuleReference(ref) && ts.isStringLiteralLike(ref.expression)) {
        findings.push({
          category: "module-specifier",
          kind: "static-import",
          specifier: ref.expression.text,
          line: lineOf(node),
        });
      }
    } else if (ts.isModuleDeclaration(node) && ts.isStringLiteralLike(node.name)) {
      // declare module "pkg" { ... }
      findings.push({
        category: "module-specifier",
        kind: "declare-module",
        specifier: node.name.text,
        line: lineOf(node),
      });
    } else if (
      ts.isImportTypeNode(node) &&
      ts.isLiteralTypeNode(node.argument) &&
      ts.isStringLiteralLike(node.argument.literal)
    ) {
      // type T = import("pkg").Foo; — solo-tipo, se erase en runtime, pero igual se reporta
      // (fail-closed): sigue siendo una referencia auditable al SDK en el código fuente.
      findings.push({
        category: "module-specifier",
        kind: "static-import",
        specifier: node.argument.literal.text,
        line: lineOf(node),
      });
    } else if (ts.isImportSpecifier(node)) {
      // import { createRequire } from "..."; import { createRequire as cr } from "...";
      const importedName = (node.propertyName ?? node.name).text;
      if (DANGEROUS_REFERENCE_NAMES.has(importedName)) {
        pushDangerousReference(importedName, node);
      }
    } else if (ts.isBindingElement(node)) {
      // const { createRequire: cr } = ...;  const { _load } = ...;
      const nameNode = node.propertyName ?? node.name;
      if (ts.isIdentifier(nameNode) && DANGEROUS_REFERENCE_NAMES.has(nameNode.text)) {
        pushDangerousReference(nameNode.text, node);
      }
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const arg0 = node.arguments[0];

      if (isImportLikeCall(node)) {
        let matchedSpecifier = false;
        if (callee.kind === ts.SyntaxKind.ImportKeyword) {
          matchedSpecifier = pushModuleSpecifier(arg0, "dynamic-import", node);
        } else if (ts.isIdentifier(callee) && callee.text === "require") {
          matchedSpecifier = pushModuleSpecifier(arg0, "require", node);
        } else if (ts.isCallExpression(callee) && isCreateRequirePropertyAccess(callee.expression)) {
          matchedSpecifier = pushModuleSpecifier(arg0, "create-require-call", node);
        }
        if (!matchedSpecifier) {
          // import()/require()/createRequire(...)(...) con argumento no literal (variable,
          // concatenación, template con sustituciones, ausente, etc.): fail-closed.
          pushPrimitive("non-literal-dynamic-call", node);
        }
      } else if (isImportMetaResolve(callee)) {
        pushPrimitive("forbidden-import-meta-resolve", node);
      } else if (
        ts.isPropertyAccessExpression(callee) &&
        ts.isIdentifier(callee.expression) &&
        callee.expression.text === "Reflect" &&
        (callee.name.text === "apply" || callee.name.text === "construct") &&
        arg0 !== undefined
      ) {
        // Reflect.apply(eval, ...) / Reflect.construct(Function, ...)
        const target = unwrapExpression(arg0);
        if (ts.isIdentifier(target) && target.text in REFLECT_TARGET_SCOPE) {
          const scope = REFLECT_TARGET_SCOPE[target.text];
          if (target.text === "eval") {
            pushPrimitive("forbidden-eval-reference", node);
          } else {
            pushPrimitive("forbidden-dangerous-reference", node, { name: target.text, scope });
          }
        }
      }
    } else if (ts.isNewExpression(node)) {
      if (ts.isIdentifier(node.expression) && node.expression.text === "Function") {
        pushDangerousReference("Function", node);
      }
    } else if (ts.isElementAccessExpression(node)) {
      const base = unwrapExpression(node.expression);
      if (ts.isIdentifier(base) && (base.text === "module" || base.text === "require")) {
        // module["x"], require["x"] (cualquier propiedad, incl. computada).
        pushDangerousReference(base.text, node);
      }
      const arg = node.argumentExpression;
      if (ts.isStringLiteralLike(arg)) {
        if (arg.text === "constructor" || DANGEROUS_REFERENCE_NAMES.has(arg.text)) {
          pushDangerousReference(arg.text, node);
        }
      }
    } else if (ts.isPropertyAccessExpression(node)) {
      const base = unwrapExpression(node.expression);
      if (ts.isIdentifier(base) && (base.text === "module" || base.text === "require")) {
        // module.x, require.x (cualquier propiedad; module.require y require.resolve
        // quedan cubiertos aquí también, de forma deliberadamente amplia).
        pushDangerousReference(base.text, node);
      } else if (node.name.text === "require") {
        // <algo>.require donde <algo> no es literalmente `module`/`require` (p.ej.
        // process.mainModule.require, globalThis.require): igual de peligroso.
        pushPrimitive("forbidden-dangerous-reference", node, { name: "require", scope: "everywhere" });
      } else if (DANGEROUS_REFERENCE_NAMES.has(node.name.text)) {
        pushDangerousReference(node.name.text, node);
      }
    } else if (ts.isIdentifier(node) && node.text === "eval") {
      // Toda referencia a `eval`, no solo la llamada directa: (0, eval)(..), globalThis.eval,
      // const e = eval; e(..), Reflect.apply(eval, ..).
      const parent = node.parent;
      const isPropertyName = parent !== undefined && ts.isPropertyAccessExpression(parent) && parent.name === node;
      if (!isPropertyName) {
        pushPrimitive("forbidden-eval-reference", node);
      }
    } else if (ts.isIdentifier(node) && DANGEROUS_REFERENCE_NAMES.has(node.text) && node.text !== "constructor") {
      // Function, createRequire, getBuiltinModule, _load, binding, _linkedBinding, dlopen,
      // mainModule como identificador libre (no como nombre de propiedad, ya cubierto arriba).
      const parent = node.parent;
      const isPropertyName = parent !== undefined && ts.isPropertyAccessExpression(parent) && parent.name === node;
      const isImportOrBindingName =
        parent !== undefined &&
        (ts.isImportSpecifier(parent) || ts.isBindingElement(parent)) &&
        (parent.propertyName ?? parent.name) === node;
      if (!isPropertyName && !isImportOrBindingName) {
        pushDangerousReference(node.text, node);
      }
    } else if (ts.isIdentifier(node) && node.text === "require") {
      const parent = node.parent;
      const isDirectLiteralCallCallee =
        parent !== undefined && ts.isCallExpression(parent) && parent.expression === node;
      const isRequireResolveLiteralCall =
        parent !== undefined &&
        ts.isPropertyAccessExpression(parent) &&
        parent.expression === node &&
        parent.name.text === "resolve" &&
        parent.parent !== undefined &&
        ts.isCallExpression(parent.parent) &&
        parent.parent.expression === parent &&
        parent.parent.arguments[0] !== undefined &&
        ts.isStringLiteralLike(parent.parent.arguments[0]);
      const isPropertyName = parent !== undefined && ts.isPropertyAccessExpression(parent) && parent.name === node;
      const isElementBase =
        parent !== undefined && ts.isElementAccessExpression(parent) && unwrapExpression(parent.expression) === node;
      const isImportBinding =
        parent !== undefined &&
        (ts.isImportSpecifier(parent) || ts.isImportClause(parent) || ts.isNamespaceImport(parent));
      if (!isDirectLiteralCallCallee && !isRequireResolveLiteralCall && !isPropertyName && !isElementBase && !isImportBinding) {
        pushPrimitive("forbidden-require-usage", node);
      }
    }
    ts.forEachChild(node, visit);
  };

  visit(sourceFile);

  // /// <reference types="pkg" />
  for (const ref of sourceFile.typeReferenceDirectives) {
    findings.push({
      category: "module-specifier",
      kind: "type-reference-directive",
      specifier: ref.fileName,
      line: sourceFile.getLineAndCharacterOfPosition(ref.pos).line + 1,
    });
  }

  return findings;
}

/** Filtra solo los hallazgos de especificador de módulo (para las reglas de deny-list y capas). */
export function moduleSpecifierFindings(findings: Finding[]): ModuleSpecifierFinding[] {
  return findings.filter((f): f is ModuleSpecifierFinding => f.category === "module-specifier");
}

/** Filtra solo los hallazgos de primitivas peligrosas. */
export function primitiveFindings(findings: Finding[]): PrimitiveFinding[] {
  return findings.filter((f): f is PrimitiveFinding => f.category === "primitive");
}
