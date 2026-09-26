// Gobierna: ADR-001 §11, CA-136 (H21), SEC-CNS-010 (P1-01).
// Detecta, con el TypeScript compiler API (AST, no expresiones regulares):
//   (a) especificadores de módulo importados de forma verificable (literal):
//       import estático, `export ... from`, `import()` dinámico con literal, `require()`
//       con literal y `<x>.createRequire(...)(...)` con literal;
//   (b) usos de primitivas peligrosas que permiten evadir (a), fail-closed:
//       - import()/require()/createRequire(...)(...) con argumento NO literal;
//       - cualquier referencia a `require` que no sea un `require('literal')` directo
//         (alias, `.call`, `.apply`, `.bind`, paso como valor) — excepto `require.resolve('literal')`;
//       - `<algo>.require` (module.require, process.mainModule.require, globalThis.require,
//         global.require, window.require, Module._load, o cualquier `<x>.require`);
//       - `eval(...)`, `Function(...)`/`new Function(...)`;
//       - `import.meta.resolve(...)`;
//       - cualquier identificador o propiedad llamada `createRequire` (import, alias,
//         destructuring, member access), como referencia (no solo la llamada encadenada).

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
  | "forbidden-global-require-access"
  | "forbidden-eval-or-function"
  | "forbidden-import-meta-resolve"
  | "forbidden-create-require-reference";

export interface PrimitiveFinding {
  category: "primitive";
  kind: PrimitiveFindingKind;
  line: number;
}

export type Finding = ModuleSpecifierFinding | PrimitiveFinding;

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

  const pushPrimitive = (kind: PrimitiveFindingKind, node: ts.Node): void => {
    findings.push({ category: "primitive", kind, line: lineOf(node) });
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
    } else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument) && ts.isStringLiteralLike(node.argument.literal)) {
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
      if (importedName === "createRequire") {
        pushPrimitive("forbidden-create-require-reference", node);
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
      } else if (ts.isIdentifier(callee) && (callee.text === "eval" || callee.text === "Function")) {
        pushPrimitive("forbidden-eval-or-function", node);
      }
    } else if (ts.isNewExpression(node)) {
      if (ts.isIdentifier(node.expression) && node.expression.text === "Function") {
        pushPrimitive("forbidden-eval-or-function", node);
      }
    } else if (ts.isPropertyAccessExpression(node)) {
      if (node.name.text === "createRequire") {
        // <x>.createRequire (referencia, se llame o no de inmediato en esta misma expresión).
        pushPrimitive("forbidden-create-require-reference", node);
      } else if (node.name.text === "require") {
        // module.require, process.mainModule.require, globalThis.require, Module._load
        // vía require, o cualquier otra propiedad `.require`: conservador a propósito.
        pushPrimitive("forbidden-global-require-access", node);
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
      const isImportBinding =
        parent !== undefined && (ts.isImportSpecifier(parent) || ts.isImportClause(parent) || ts.isNamespaceImport(parent));
      if (!isDirectLiteralCallCallee && !isRequireResolveLiteralCall && !isPropertyName && !isImportBinding) {
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
