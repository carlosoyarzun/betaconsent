// Gobierna: ADR-001 §11, CA-136 (H21).
// Detecta especificadores de módulo importados por un archivo fuente usando el
// TypeScript compiler API (AST), no expresiones regulares. Cubre:
//   - import estático (`import x from 'y'`, `import 'y'`)
//   - `export ... from 'y'` (incl. `export * from 'y'`)
//   - `import('y')` dinámico con literal de cadena
//   - `require('y')` con literal de cadena
//   - `<algo>.createRequire(...)('y')` (patrón module.createRequire(...)(...))
//
// No intenta resolver imports dinámicos con especificador no literal (ya prohibidos
// por otra regla de lint, ADR-001 §6.1); esos quedan fuera de alcance de este guardrail.

import ts from "typescript";

export type ImportKind =
  | "static-import"
  | "export-from"
  | "dynamic-import"
  | "require"
  | "create-require-call";

export interface DetectedImport {
  specifier: string;
  kind: ImportKind;
  line: number; // 1-based
}

function scriptKindFor(filePath: string): ts.ScriptKind {
  if (filePath.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (filePath.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (filePath.endsWith(".ts") || filePath.endsWith(".mts") || filePath.endsWith(".cts")) {
    return ts.ScriptKind.TS;
  }
  return ts.ScriptKind.JS;
}

/** True si el callee de una CallExpression termina en la propiedad `createRequire`. */
function calleeEndsInCreateRequire(expr: ts.LeftHandSideExpression): boolean {
  return ts.isPropertyAccessExpression(expr) && expr.name.text === "createRequire";
}

export function scanFileForImports(filePath: string, sourceText: string): DetectedImport[] {
  const sourceFile = ts.createSourceFile(
    filePath,
    sourceText,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    scriptKindFor(filePath),
  );

  const found: DetectedImport[] = [];

  const lineOf = (node: ts.Node): number =>
    sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;

  const pushIfStringLiteral = (specifierExpr: ts.Expression | undefined, kind: ImportKind, node: ts.Node) => {
    if (specifierExpr !== undefined && ts.isStringLiteralLike(specifierExpr)) {
      found.push({ specifier: specifierExpr.text, kind, line: lineOf(node) });
    }
  };

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) {
      pushIfStringLiteral(node.moduleSpecifier, "static-import", node);
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) {
      pushIfStringLiteral(node.moduleSpecifier, "export-from", node);
    } else if (ts.isImportEqualsDeclaration(node)) {
      const ref = node.moduleReference;
      if (ts.isExternalModuleReference(ref) && ts.isStringLiteralLike(ref.expression)) {
        found.push({ specifier: ref.expression.text, kind: "static-import", line: lineOf(node) });
      }
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      if (callee.kind === ts.SyntaxKind.ImportKeyword) {
        // import('literal')
        const arg = node.arguments[0];
        pushIfStringLiteral(arg, "dynamic-import", node);
      } else if (ts.isIdentifier(callee) && callee.text === "require") {
        // require('literal')
        const arg = node.arguments[0];
        pushIfStringLiteral(arg, "require", node);
      } else if (ts.isCallExpression(callee) && calleeEndsInCreateRequire(callee.expression)) {
        // <x>.createRequire(...)('literal')
        const arg = node.arguments[0];
        pushIfStringLiteral(arg, "create-require-call", node);
      }
    }
    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return found;
}
