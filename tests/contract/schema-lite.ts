// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), CA-116 fix (P1 contrato vs
// implementación). Validador propio, mínimo, de JSON Schema (sin dependencias nuevas):
// soporta exactamente el subconjunto de palabras clave que usan
// contracts/schemas/api-payloads.schema.json, contracts/schemas/common.schema.json y
// contracts/schemas/ledger-event-payloads.schema.json en las definiciones referenciadas por
// las respuestas HTTP (consent-flow.handler.ts, rights-case-resume.handler.ts) y por los
// payloads de eventos del ledger que ya emite el dominio: $ref (dentro del mismo esquema o a
// otro), type, required, properties, additionalProperties: false, enum, const (incluido const
// de array), oneOf, pattern (string) y, desde CA-127, allOf con if/then (sin else; lo usa
// outbox-events.schema.json#/$defs/OutboxEvent) y `properties` sin `type`. No implementa
// else, dependentRequired, anyOf,
// patternProperties ni formatos (ningún $defs validado aquí los necesita; los que sí los usan
// se reportan como finding en vez de forzar un validador más grande).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONTRACTS_SCHEMAS_DIR = join(HERE, "..", "..", "contracts", "schemas");

type JsonSchema = Record<string, unknown>;

function loadSchemaFile(fileName: string): JsonSchema {
  const raw = readFileSync(join(CONTRACTS_SCHEMAS_DIR, fileName), "utf8");
  return JSON.parse(raw) as JsonSchema;
}

const SCHEMA_FILES: Readonly<Record<string, JsonSchema>> = {
  "common.schema.json": loadSchemaFile("common.schema.json"),
  "api-payloads.schema.json": loadSchemaFile("api-payloads.schema.json"),
  "ledger-event-payloads.schema.json": loadSchemaFile("ledger-event-payloads.schema.json"),
  "outbox-events.schema.json": loadSchemaFile("outbox-events.schema.json"),
};

function getByPointer(doc: JsonSchema, pointer: string): JsonSchema {
  const parts = pointer.split("/").filter((p) => p.length > 0);
  let node: unknown = doc;
  for (const part of parts) {
    if (typeof node !== "object" || node === null) {
      throw new Error(`schema-lite: puntero no resoluble "${pointer}"`);
    }
    node = (node as Record<string, unknown>)[part];
  }
  if (typeof node !== "object" || node === null) {
    throw new Error(`schema-lite: puntero no resoluble "${pointer}"`);
  }
  return node as JsonSchema;
}

/** Resuelve un $ref tipo "../schemas/common.schema.json#/$defs/Ref" o local "#/$defs/Foo". */
function resolveRef(ref: string, currentFile: string): { schema: JsonSchema; file: string } {
  const hashIndex = ref.indexOf("#");
  const filePart = hashIndex === -1 ? ref : ref.slice(0, hashIndex);
  const pointer = hashIndex === -1 ? "" : ref.slice(hashIndex + 1);
  const file = filePart.length === 0 ? currentFile : filePart.replace(/^(\.\.\/)*schemas\//, "");
  const doc = SCHEMA_FILES[file];
  if (!doc) throw new Error(`schema-lite: esquema no cargado "${file}" (ref "${ref}")`);
  return { schema: getByPointer(doc, pointer), file };
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function validateNode(schema: JsonSchema, value: unknown, path: string, file: string, errors: string[]): void {
  if (typeof schema.$ref === "string") {
    const resolved = resolveRef(schema.$ref, file);
    validateNode(resolved.schema, value, path, resolved.file, errors);
    return;
  }

  // allOf (CA-127): cada rama se valida; una rama con if/then aplica `then` solo si `if` valida.
  // No hace return: el resto de las palabras clave del mismo nodo se siguen evaluando.
  if (Array.isArray(schema.allOf)) {
    for (const branch of schema.allOf as JsonSchema[]) {
      if (branch.if !== undefined) {
        const ifErrors: string[] = [];
        validateNode(branch.if as JsonSchema, value, path, file, ifErrors);
        if (ifErrors.length === 0 && branch.then !== undefined) {
          validateNode(branch.then as JsonSchema, value, path, file, errors);
        }
      } else {
        validateNode(branch, value, path, file, errors);
      }
    }
  }

  if (Array.isArray(schema.oneOf)) {
    const branches = schema.oneOf as JsonSchema[];
    const matches = branches.filter((branch) => {
      const branchErrors: string[] = [];
      validateNode(branch, value, path, file, branchErrors);
      return branchErrors.length === 0;
    });
    if (matches.length !== 1) {
      errors.push(`${path}: no coincide exactamente una rama de oneOf (coincidencias: ${matches.length})`);
    }
    return;
  }

  if ("const" in schema) {
    if (!deepEqual(value, schema.const)) {
      errors.push(`${path}: esperado const ${JSON.stringify(schema.const)}, recibido ${JSON.stringify(value)}`);
    }
    return;
  }

  if (Array.isArray(schema.enum)) {
    if (!schema.enum.some((candidate) => deepEqual(candidate, value))) {
      errors.push(`${path}: esperado uno de enum ${JSON.stringify(schema.enum)}, recibido ${JSON.stringify(value)}`);
    }
    return;
  }

  const isObjectSchema = schema.type === "object" || (schema.type === undefined && typeof schema.properties === "object");
  if (isObjectSchema) {
    if (schema.type === undefined && (typeof value !== "object" || value === null || Array.isArray(value))) return;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      errors.push(`${path}: esperado objeto, recibido ${JSON.stringify(value)}`);
      return;
    }
    const obj = value as Record<string, unknown>;
    const required = Array.isArray(schema.required) ? (schema.required as string[]) : [];
    for (const key of required) {
      if (!(key in obj)) errors.push(`${path}: falta la propiedad requerida "${key}"`);
    }
    const properties = (schema.properties as Record<string, JsonSchema> | undefined) ?? {};
    for (const key of Object.keys(obj)) {
      if (key in properties) {
        validateNode(properties[key] as JsonSchema, obj[key], `${path}.${key}`, file, errors);
      } else if (schema.additionalProperties === false) {
        errors.push(`${path}: propiedad adicional no permitida "${key}" (additionalProperties: false)`);
      }
    }
    return;
  }

  if (schema.type === "integer") {
    if (typeof value !== "number" || !Number.isInteger(value)) {
      errors.push(`${path}: esperado integer, recibido ${JSON.stringify(value)}`);
      return;
    }
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      errors.push(`${path}: ${value} por debajo del mínimo ${schema.minimum}`);
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      errors.push(`${path}: ${value} por encima del máximo ${schema.maximum}`);
    }
    return;
  }

  if (schema.type === "string") {
    if (typeof value !== "string") {
      errors.push(`${path}: esperado string, recibido ${JSON.stringify(value)}`);
      return;
    }
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: "${value}" no coincide con el patrón ${schema.pattern}`);
    }
    return;
  }

  if (schema.type === "array") {
    if (!Array.isArray(value)) {
      errors.push(`${path}: esperado array, recibido ${JSON.stringify(value)}`);
    }
    return;
  }

  // Nodo sin palabra clave soportada (p. ej. solo `description`): nada que validar.
}

export interface ValidationResult {
  readonly ok: boolean;
  readonly errors: readonly string[];
}

function validateAgainstDef(fileName: string, defName: string, value: unknown): ValidationResult {
  const doc = SCHEMA_FILES[fileName];
  if (!doc) throw new Error(`schema-lite: esquema no cargado "${fileName}"`);
  const defs = doc.$defs as Record<string, JsonSchema> | undefined;
  const schema = defs?.[defName];
  if (!schema) throw new Error(`schema-lite: "${defName}" no existe en ${fileName}#/$defs`);
  const errors: string[] = [];
  validateNode(schema, value, "$", fileName, errors);
  return { ok: errors.length === 0, errors };
}

/** Valida contra contracts/schemas/api-payloads.schema.json#/$defs/<defName>. */
export function validateApiPayload(defName: string, value: unknown): ValidationResult {
  return validateAgainstDef("api-payloads.schema.json", defName, value);
}

/** Valida contra contracts/schemas/common.schema.json#/$defs/<defName>. */
export function validateCommon(defName: string, value: unknown): ValidationResult {
  return validateAgainstDef("common.schema.json", defName, value);
}

/** Valida un sobre contra contracts/schemas/outbox-events.schema.json#/$defs/OutboxEvent
 * (incluye el payload por eventType vía allOf/if/then). */
export function validateOutboxEvent(envelope: unknown): ValidationResult {
  return validateAgainstDef("outbox-events.schema.json", "OutboxEvent", envelope);
}

/** Valida el `payload` de un evento del ledger contra
 * contracts/schemas/ledger-event-payloads.schema.json#/$defs/<eventType> (lista blanca por
 * eventType, INV-CM-05). */
export function validateLedgerEventPayload(eventType: string, payload: unknown): ValidationResult {
  return validateAgainstDef("ledger-event-payloads.schema.json", eventType, payload);
}
