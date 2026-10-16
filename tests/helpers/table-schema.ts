// Gobierna: ADR-010 rev. 6 §10 fila PR-7 (sub-PR 7c, Q16; decision de Carlos del 2026-10-17, C-2): app.revocation y app.rights_case pasan al esquema case_state (0081).
// Helper de tests: esquema y dueño de las tablas de agregado que recorren los tests genericos. Solo tests.

const CASE_STATE_TABLES: readonly string[] = ["revocation", "rights_case"];

/** Esquema de una tabla de agregado: case_state para Revocation y RightsCase (0081), app para el resto. */
export const tableSchema = (table: string): "app" | "case_state" => (CASE_STATE_TABLES.includes(table) ? "case_state" : "app");

/** Nombre calificado `esquema.tabla`. */
export const qualified = (table: string): string => `${tableSchema(table)}.${table}`;

/** Dueño esperado de la tabla: case_state_owner para las movidas (0081), consent_owner para el resto. */
export const tableOwner = (table: string): string => (tableSchema(table) === "case_state" ? "case_state_owner" : "consent_owner");
