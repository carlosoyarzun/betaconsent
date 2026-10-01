// CA-128 (X6, P1-A): movido desde tests/contract/schema-lite.ts para que el append del ledger valide el
// payload contra el contrato real (tests/contract/schema-lite.ts lo re-exporta; mismos nombres).
// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), CA-116 fix (P1 contrato vs
// implementación). Validador propio, mínimo, de JSON Schema (sin dependencias nuevas):
// soporta exactamente el subconjunto de palabras clave que usan
// contracts/schemas/api-payloads.schema.json, contracts/schemas/common.schema.json y
// contracts/schemas/ledger-event-payloads.schema.json en las definiciones referenciadas por
// las respuestas HTTP (consent-flow.handler.ts, rights-case-resume.handler.ts) y por los
// payloads de eventos del ledger que ya emite el dominio: $ref (dentro del mismo esquema o a
// otro), type (string|number|integer|boolean|null|object|array), required, properties,
// additionalProperties, enum, const, oneOf (exactamente una rama), anyOf, not, allOf, if/then/else,
// dependentRequired, items/minItems/maxItems/uniqueItems, minLength/maxLength/pattern, format
// date-time (RFC 3339 estricto) y email, minimum/maximum. FAIL-CLOSED (CA-128 X6 P1, INV-CM-05): una
// palabra clave desconocida lanza al cargar; anotaciones permitidas: $id, $schema, $defs, description,
// title, examples, status, writeOnly y x-*.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONTRACTS_SCHEMAS_DIR = join(HERE, "..", "..", "..", "..", "contracts", "schemas");

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
  "security-event-payloads.schema.json": loadSchemaFile("security-event-payloads.schema.json"),
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
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, i) => deepEqual(item, b[i]));
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const ak = Object.keys(ao);
  if (ak.length !== Object.keys(bo).length) return false;
  return ak.every((k) => k in bo && deepEqual(ao[k], bo[k]));
}

// CA-128 (X6 P1, INV-CM-05): FAIL-CLOSED. Toda palabra clave de un nodo de esquema debe estar en uno de
// estos dos conjuntos; una desconocida lanza al cargar/validar (antes se ignoraba en silencio y el
// ledger aceptaba payloads fuera del contrato).
const VALIDATION_KEYWORDS: ReadonlySet<string> = new Set([
  "$ref", "type", "const", "enum", "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
  "required", "properties", "additionalProperties", "dependentRequired",
  "items", "minItems", "maxItems", "uniqueItems",
  "minLength", "maxLength", "pattern", "format", "minimum", "maximum",
]);
// Anotaciones sin efecto de validación ($defs se recorre aparte). Los `x-*` son extensiones del repo.
const ANNOTATION_KEYWORDS: ReadonlySet<string> = new Set([
  "$id", "$schema", "$defs", "description", "title", "examples", "status", "writeOnly",
]);
const SCHEMA_TYPES: ReadonlySet<string> = new Set(["string", "number", "integer", "boolean", "null", "object", "array"]);
const SUPPORTED_FORMATS: ReadonlySet<string> = new Set(["date-time", "email"]);

function isSchemaObject(v: unknown): v is JsonSchema {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Lanza si el nodo (o cualquier subnodo) usa una palabra clave no soportada. */
export function assertSchemaKeywordsSupported(schema: unknown, where = "$"): void {
  if (typeof schema === "boolean") return; // esquema booleano (true/false)
  if (!isSchemaObject(schema)) throw new Error(`schema-lite: ${where} no es un esquema objeto`);
  for (const [key, val] of Object.entries(schema)) {
    if (key.startsWith("x-") || ANNOTATION_KEYWORDS.has(key)) {
      if (key === "$defs") {
        if (!isSchemaObject(val)) throw new Error(`schema-lite: ${where}/$defs invalido`);
        for (const [name, def] of Object.entries(val)) assertSchemaKeywordsSupported(def, `${where}/$defs/${name}`);
      }
      continue;
    }
    if (!VALIDATION_KEYWORDS.has(key)) {
      throw new Error(`schema-lite: palabra clave no soportada "${key}" en ${where} (fail-closed, INV-CM-05)`);
    }
    switch (key) {
      case "properties":
        if (!isSchemaObject(val)) throw new Error(`schema-lite: ${where}/properties invalido`);
        for (const [name, sub] of Object.entries(val)) assertSchemaKeywordsSupported(sub, `${where}/properties/${name}`);
        break;
      case "allOf":
      case "anyOf":
      case "oneOf":
        if (!Array.isArray(val)) throw new Error(`schema-lite: ${where}/${key} invalido`);
        val.forEach((sub, i) => assertSchemaKeywordsSupported(sub, `${where}/${key}/${i}`));
        break;
      case "not":
      case "if":
      case "then":
      case "else":
      case "items":
        assertSchemaKeywordsSupported(val, `${where}/${key}`);
        break;
      case "additionalProperties":
        if (typeof val === "boolean") break;
        assertSchemaKeywordsSupported(val, `${where}/additionalProperties`);
        break;
      case "type": {
        const types = Array.isArray(val) ? val : [val];
        for (const t of types) {
          if (typeof t !== "string" || !SCHEMA_TYPES.has(t)) throw new Error(`schema-lite: type no soportado ${JSON.stringify(t)} en ${where}`);
        }
        break;
      }
      case "format":
        if (typeof val !== "string" || !SUPPORTED_FORMATS.has(val)) {
          throw new Error(`schema-lite: format no soportado ${JSON.stringify(val)} en ${where}`);
        }
        break;
      case "pattern":
        if (typeof val !== "string") throw new Error(`schema-lite: pattern invalido en ${where}`);
        new RegExp(val);
        break;
      case "dependentRequired":
        if (!isSchemaObject(val) || !Object.values(val).every((l) => Array.isArray(l))) {
          throw new Error(`schema-lite: dependentRequired invalido en ${where}`);
        }
        break;
      default:
        break;
    }
  }
}

const DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/** RFC 3339 date-time estricto: T y Z en mayuscula, fecha de calendario real, hora/offset en rango. */
export function isRfc3339DateTime(value: string): boolean {
  const m = DATE_TIME.exec(value);
  if (!m) return false;
  const [year, month, day, hour, minute, second] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number) as [number, number, number, number, number, number];
  if (month < 1 || month > 12 || day < 1) return false;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1] as number;
  if (day > dim) return false;
  if (hour > 23 || minute > 59 || second > 60) return false;
  if (m[7] !== undefined && (Number(m[8]) > 23 || Number(m[9]) > 59)) return false;
  return true;
}

const EMAIL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

function checkFormat(format: string, value: string): boolean {
  if (format === "date-time") return isRfc3339DateTime(value);
  if (format === "email") return value.length <= 254 && EMAIL.test(value);
  throw new Error(`schema-lite: format no soportado ${JSON.stringify(format)}`);
}

function typeMatches(type: string, value: unknown): boolean {
  switch (type) {
    case "string": return typeof value === "string";
    case "number": return typeof value === "number" && Number.isFinite(value);
    case "integer": return typeof value === "number" && Number.isInteger(value);
    case "boolean": return typeof value === "boolean";
    case "null": return value === null;
    case "array": return Array.isArray(value);
    case "object": return typeof value === "object" && value !== null && !Array.isArray(value);
    default: throw new Error(`schema-lite: type no soportado ${JSON.stringify(type)}`);
  }
}

function valid(schema: JsonSchema | boolean, value: unknown, file: string): boolean {
  const errs: string[] = [];
  validateNode(schema, value, "$", file, errs);
  return errs.length === 0;
}

// Evalua TODAS las palabras clave del nodo (sin retornos tempranos): un fallo en cualquiera es un error.
function validateNode(schema: JsonSchema | boolean, value: unknown, path: string, file: string, errors: string[]): void {
  if (typeof schema === "boolean") {
    if (!schema) errors.push(`${path}: esquema false (nada valida)`);
    return;
  }
  assertNodeKeywords(schema);

  if (typeof schema.$ref === "string") {
    const resolved = resolveRef(schema.$ref, file);
    validateNode(resolved.schema, value, path, resolved.file, errors);
  }

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? (schema.type as string[]) : [schema.type as string];
    if (!types.some((t) => typeMatches(t, value))) {
      errors.push(`${path}: esperado tipo ${types.join("|")}, recibido ${typeof value === "string" ? "string" : JSON.stringify(value)}`);
      // Con tipo equivocado las palabras clave especificas de otro tipo no aplican.
    }
  }

  if ("const" in schema && !deepEqual(value, schema.const)) {
    errors.push(`${path}: no coincide con const`);
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => deepEqual(candidate, value))) {
    errors.push(`${path}: fuera de enum`);
  }

  if (Array.isArray(schema.allOf)) {
    for (const branch of schema.allOf as JsonSchema[]) validateNode(branch, value, path, file, errors);
  }
  if (Array.isArray(schema.anyOf)) {
    if (!(schema.anyOf as JsonSchema[]).some((b) => valid(b, value, file))) {
      errors.push(`${path}: no coincide ninguna rama de anyOf`);
    }
  }
  if (Array.isArray(schema.oneOf)) {
    const matches = (schema.oneOf as JsonSchema[]).filter((b) => valid(b, value, file)).length;
    if (matches !== 1) errors.push(`${path}: no coincide exactamente una rama de oneOf (coincidencias: ${matches})`);
  }
  if (schema.not !== undefined && valid(schema.not as JsonSchema | boolean, value, file)) {
    errors.push(`${path}: coincide con un esquema prohibido (not)`);
  }
  if (schema.if !== undefined) {
    const branch = valid(schema.if as JsonSchema | boolean, value, file) ? schema.then : schema.else;
    if (branch !== undefined) validateNode(branch as JsonSchema | boolean, value, path, file, errors);
  }

  if (typeof value === "string") {
    if (typeof schema.minLength === "number" && [...value].length < schema.minLength) {
      errors.push(`${path}: longitud menor que minLength ${schema.minLength}`);
    }
    if (typeof schema.maxLength === "number" && [...value].length > schema.maxLength) {
      errors.push(`${path}: longitud mayor que maxLength ${schema.maxLength}`);
    }
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: no coincide con el patrón ${schema.pattern}`);
    }
    if (typeof schema.format === "string" && !checkFormat(schema.format, value)) {
      errors.push(`${path}: formato ${schema.format} inválido`);
    }
  }

  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) errors.push(`${path}: ${value} por debajo del mínimo ${schema.minimum}`);
    if (typeof schema.maximum === "number" && value > schema.maximum) errors.push(`${path}: ${value} por encima del máximo ${schema.maximum}`);
  }

  if (Array.isArray(value)) {
    if (typeof schema.minItems === "number" && value.length < schema.minItems) errors.push(`${path}: menos de ${schema.minItems} elementos`);
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) errors.push(`${path}: más de ${schema.maxItems} elementos`);
    if (isSchemaObject(schema.items)) {
      value.forEach((item, i) => validateNode(schema.items as JsonSchema, item, `${path}[${i}]`, file, errors));
    }
    if (schema.uniqueItems === true) {
      for (let i = 0; i < value.length; i += 1) {
        for (let j = i + 1; j < value.length; j += 1) {
          if (deepEqual(value[i], value[j])) errors.push(`${path}: elementos repetidos (uniqueItems)`);
        }
      }
    }
  }

  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const required = Array.isArray(schema.required) ? (schema.required as string[]) : [];
    for (const key of required) {
      if (!(key in obj)) errors.push(`${path}: falta la propiedad requerida "${key}"`);
    }
    if (isSchemaObject(schema.dependentRequired)) {
      for (const [trigger, needed] of Object.entries(schema.dependentRequired as Record<string, string[]>)) {
        if (trigger in obj) {
          for (const key of needed) {
            if (!(key in obj)) errors.push(`${path}: "${trigger}" exige la propiedad "${key}" (dependentRequired)`);
          }
        }
      }
    }
    const properties = (schema.properties as Record<string, JsonSchema> | undefined) ?? {};
    for (const key of Object.keys(obj)) {
      if (key in properties) {
        validateNode(properties[key] as JsonSchema, obj[key], `${path}.${key}`, file, errors);
      } else if (schema.additionalProperties === false) {
        errors.push(`${path}: propiedad adicional no permitida "${key}" (additionalProperties: false)`);
      } else if (isSchemaObject(schema.additionalProperties)) {
        validateNode(schema.additionalProperties, obj[key], `${path}.${key}`, file, errors);
      }
    }
  }
}

// Comprobacion de claves del nodo actual (los subnodos se comprueban al visitarlos y, completo, al cargar).
function assertNodeKeywords(schema: JsonSchema): void {
  for (const key of Object.keys(schema)) {
    if (key.startsWith("x-") || ANNOTATION_KEYWORDS.has(key) || VALIDATION_KEYWORDS.has(key)) continue;
    throw new Error(`schema-lite: palabra clave no soportada "${key}" (fail-closed, INV-CM-05)`);
  }
}

// Carga: todo $defs de cada contrato debe usar solo palabras clave soportadas.
for (const [fileName, doc] of Object.entries(SCHEMA_FILES)) {
  try {
    assertSchemaKeywordsSupported(doc, fileName);
  } catch (err) {
    throw new Error(`schema-lite: contrato ${fileName} no cargable: ${(err as Error).message}`);
  }
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

/** Defs del contrato por eventType, o null si el contrato no declara el tipo (ledger o stream SECURITY). */
export function validateLedgerOrSecurityPayload(eventType: string, payload: unknown): ValidationResult | null {
  const ledgerDefs = SCHEMA_FILES["ledger-event-payloads.schema.json"]?.$defs as Record<string, unknown> | undefined;
  if (ledgerDefs && eventType in ledgerDefs) return validateAgainstDef("ledger-event-payloads.schema.json", eventType, payload);
  const securityDefs = SCHEMA_FILES["security-event-payloads.schema.json"]?.$defs as Record<string, unknown> | undefined;
  if (securityDefs && eventType in securityDefs && eventType !== "SecurityEvent") {
    return validateAgainstDef("security-event-payloads.schema.json", eventType, payload);
  }
  return null;
}

/** Tipos con $def en el contrato del ledger (fuente unica de la lista blanca). */
export function contractLedgerEventTypes(): string[] {
  const doc = SCHEMA_FILES["ledger-event-payloads.schema.json"] as Record<string, unknown>;
  const disabled = new Set((doc["x-disabled-in-it0"] as string[] | undefined) ?? []);
  return Object.keys(doc.$defs as object).filter((k) => !disabled.has(k));
}

/** Tipos con $def en el contrato del stream SECURITY (transitorios en el ledger). */
export function contractSecurityEventTypes(): string[] {
  const doc = SCHEMA_FILES["security-event-payloads.schema.json"] as Record<string, unknown>;
  return Object.keys(doc.$defs as object).filter((k) => k !== "SecurityEvent");
}
