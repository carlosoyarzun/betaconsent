// Gobierna: JIRA CA-116 (H01), specs/test-framework.spec.yaml (dependencias: sin parser YAML en la
// allowlist, ADR-001 §5). Parser YAML MÍNIMO, escrito a mano, sin dependencias externas, para el
// subconjunto de sintaxis usado en specs/state-machines/*.spec.yaml y specs/adapters/*.spec.yaml:
//   - mapeos y secuencias por indentación (2 espacios)
//   - secuencias y mapeos "flow" en una línea: [a, b] / {a: b, c: d} (con anidación), incluidos
//     ítems de secuencia que SON un flow map/list ("- {id: X, ...}", "- [a, b]"; legalDecisions y
//     openItems reales usan este patrón)
//   - escalares planos, con comillas simples/dobles (incluida una cadena entre comillas dobles que
//     cruza varias líneas, único caso observado hoy en rights-case.spec.yaml)
//   - escalares de bloque '>' (folded) y '|' (literal), plegados a una sola línea (no se necesita el
//     salto de línea exacto para los chequeos de H01)
//   - comentarios '#' fuera de comillas
//   - null/true/false/números
// NO implementa: anclas/alias, tags explícitos, multi-documento, claves complejas. Si un spec real
// usara alguna de esas construcciones, este parser debe fallar de forma visible (excepción), no en
// silencio: se prefiere un error de parseo a una lectura parcial incorrecta de una spec de gobierno.
// Fail-closed (SEC-CNS-014 P2), todo con throw explícito, nunca un valor parcial silencioso: línea
// top-level sin consumir al terminar el documento; flow list/map sin ']'/'}' de cierre; texto
// sobrante tras cerrar un flow; clave duplicada en un mapeo (por indentación, flow, o ítem de
// secuencia inline).

export type YamlValue = string | number | boolean | null | YamlValue[] | { [key: string]: YamlValue };

interface Line {
  indent: number;
  content: string;
  lineNo: number;
}

function isQuoteChar(c: string): boolean {
  return c === '"' || c === "'";
}

// Cuenta comillas dobles no escapadas en una línea (para detectar escalares entre comillas que
// cruzan varias líneas físicas).
function charAt(s: string, i: number): string {
  return i >= 0 && i < s.length ? s[i]! : "";
}

function countUnescapedDoubleQuotes(line: string): number {
  let count = 0;
  for (let i = 0; i < line.length; i++) {
    if (charAt(line, i) === '"' && charAt(line, i - 1) !== "\\") count++;
  }
  return count;
}

function stripComment(line: string): string {
  let inQuote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = charAt(line, i);
    if (inQuote) {
      if (c === inQuote && charAt(line, i - 1) !== "\\") inQuote = null;
      continue;
    }
    if (isQuoteChar(c)) {
      inQuote = c;
      continue;
    }
    if (c === "#" && (i === 0 || charAt(line, i - 1) === " " || charAt(line, i - 1) === "\t")) {
      return line.slice(0, i);
    }
  }
  return line;
}

// Preprocesa el texto crudo en líneas lógicas: fusiona líneas físicas cuando una cadena entre
// comillas dobles queda sin cerrar (folding de un escalar "..." multi-línea), descarta líneas en
// blanco y líneas 100% comentario, calcula indentación y quita comentarios de cola.
function toLines(text: string): Line[] {
  const raw = text.split("\n");
  const merged: { text: string; lineNo: number }[] = [];
  for (let i = 0; i < raw.length; i++) {
    let current = raw[i] ?? "";
    const lineNo = i + 1;
    // Si la línea (antes de fusionar) tiene comillas dobles sin balancear, va acumulando líneas
    // siguientes (con fold: un espacio) hasta que balanceen.
    while (countUnescapedDoubleQuotes(current) % 2 === 1 && i + 1 < raw.length) {
      i++;
      current = current + " " + (raw[i] ?? "").trim();
    }
    merged.push({ text: current, lineNo });
  }
  const out: Line[] = [];
  for (const { text: t, lineNo } of merged) {
    if (/^\s*#/.test(t)) continue;
    const withoutComment = stripComment(t).replace(/\s+$/, "");
    if (withoutComment.trim() === "") continue;
    const indentMatch = withoutComment.match(/^ */);
    const indent = indentMatch ? indentMatch[0].length : 0;
    out.push({ indent, content: withoutComment.slice(indent), lineNo });
  }
  return out;
}

function parseScalar(raw: string): YamlValue {
  const s = raw.trim();
  if (s === "") return null;
  if (s === "null" || s === "~") return null;
  if (s === "true") return true;
  if (s === "false") return false;
  if (s.startsWith('"') && s.endsWith('"') && s.length >= 2) {
    return unescapeDouble(s.slice(1, -1));
  }
  if (s.startsWith("'") && s.endsWith("'") && s.length >= 2) {
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
  return s;
}

function unescapeDouble(s: string): string {
  return s.replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
}

// Parser recursivo de valores "flow" ([...] / {...} / escalar), usado tanto para valores flow de
// una línea como como fallback de escalar simple.
class FlowParser {
  private pos = 0;
  private readonly s: string;
  constructor(s: string) {
    this.s = s;
  }

  // Parsea un valor flow completo (top-level) y exige que no quede texto sobrante tras cerrar el
  // último ']'/'}' (fail-closed, SEC-CNS-014 P2c: "trae texto sobrante tras ]/}").
  static parseTopLevel(s: string): YamlValue {
    const parser = new FlowParser(s);
    const value = parser.parseValue();
    parser.skipSpaces();
    if (parser.pos !== parser.s.length) {
      throw new Error(`yaml-lite: texto sobrante tras el valor flow: "${parser.s.slice(parser.pos)}" (en "${s}")`);
    }
    return value;
  }

  private peek(offset = 0): string {
    return charAt(this.s, this.pos + offset);
  }

  parseValue(): YamlValue {
    this.skipSpaces();
    const c = this.peek();
    if (c === "[") return this.parseFlowSeq();
    if (c === "{") return this.parseFlowMap();
    if (c === '"') return this.parseDoubleQuoted();
    if (c === "'") return this.parseSingleQuoted();
    return this.parsePlainUntil([",", "]", "}"]);
  }

  private skipSpaces(): void {
    while (this.peek() === " ") this.pos++;
  }

  private parseFlowSeq(): YamlValue[] {
    this.pos++; // [
    const items: YamlValue[] = [];
    this.skipSpaces();
    if (this.peek() === "]") {
      this.pos++;
      return items;
    }
    while (true) {
      items.push(this.parseValue());
      this.skipSpaces();
      if (this.peek() === ",") {
        this.pos++;
        this.skipSpaces();
        continue;
      }
      break;
    }
    // Fail-closed (SEC-CNS-014 P2c): una lista flow sin ']' de cierre es un error de sintaxis, no un
    // final silencioso.
    if (this.peek() !== "]") {
      throw new Error(`yaml-lite: lista flow sin ']' de cierre (posición ${this.pos} de "${this.s}")`);
    }
    this.pos++;
    return items;
  }

  private parseFlowMap(): { [key: string]: YamlValue } {
    this.pos++; // {
    const map: { [key: string]: YamlValue } = {};
    this.skipSpaces();
    if (this.peek() === "}") {
      this.pos++;
      return map;
    }
    while (true) {
      this.skipSpaces();
      const key = this.parseKey();
      this.skipSpaces();
      if (this.peek() === ":") this.pos++;
      this.skipSpaces();
      const value = this.parseValue();
      // Fail-closed (SEC-CNS-014 P2d): clave duplicada dentro del mismo mapeo flow.
      if (Object.prototype.hasOwnProperty.call(map, key)) {
        throw new Error(`yaml-lite: clave duplicada "${key}" en mapeo flow ("${this.s}")`);
      }
      map[key] = value;
      this.skipSpaces();
      if (this.peek() === ",") {
        this.pos++;
        continue;
      }
      break;
    }
    // Fail-closed (SEC-CNS-014 P2c): un mapeo flow sin '}' de cierre es un error de sintaxis.
    if (this.peek() !== "}") {
      throw new Error(`yaml-lite: mapeo flow sin '}' de cierre (posición ${this.pos} de "${this.s}")`);
    }
    this.pos++;
    return map;
  }

  private parseKey(): string {
    if (this.peek() === '"') return String(this.parseDoubleQuoted());
    if (this.peek() === "'") return String(this.parseSingleQuoted());
    return String(this.parsePlainUntil([":"]));
  }

  private parseDoubleQuoted(): string {
    this.pos++; // "
    let out = "";
    while (this.pos < this.s.length && this.peek() !== '"') {
      if (this.peek() === "\\" && this.pos + 1 < this.s.length) {
        out += this.peek(1);
        this.pos += 2;
        continue;
      }
      out += this.peek();
      this.pos++;
    }
    this.pos++; // closing "
    return out;
  }

  private parseSingleQuoted(): string {
    this.pos++; // '
    let out = "";
    while (this.pos < this.s.length) {
      if (this.peek() === "'" && this.peek(1) === "'") {
        out += "'";
        this.pos += 2;
        continue;
      }
      if (this.peek() === "'") break;
      out += this.peek();
      this.pos++;
    }
    this.pos++; // closing '
    return out;
  }

  private parsePlainUntil(stopChars: string[]): YamlValue {
    let out = "";
    while (this.pos < this.s.length && !stopChars.includes(this.peek())) {
      out += this.peek();
      this.pos++;
    }
    return parseScalar(out);
  }
}

function parseFlowOrScalar(raw: string): YamlValue {
  const trimmed = raw.trim();
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    return FlowParser.parseTopLevel(trimmed);
  }
  return parseScalar(trimmed);
}

// Divide "key: resto" respetando comillas (el ':' de separación es el primero fuera de comillas
// seguido de espacio o fin de línea).
function splitKeyValue(content: string): { key: string; rest: string } | null {
  let inQuote: string | null = null;
  for (let i = 0; i < content.length; i++) {
    const c = charAt(content, i);
    if (inQuote) {
      if (c === inQuote) inQuote = null;
      continue;
    }
    if (isQuoteChar(c)) {
      inQuote = c;
      continue;
    }
    if (c === ":" && (i + 1 === content.length || charAt(content, i + 1) === " ")) {
      const key = content.slice(0, i).trim();
      const rest = content.slice(i + 1).trim();
      return { key: stripKeyQuotes(key), rest };
    }
  }
  return null;
}

function stripKeyQuotes(key: string): string {
  if (key.startsWith('"') && key.endsWith('"')) return key.slice(1, -1);
  if (key.startsWith("'") && key.endsWith("'")) return key.slice(1, -1);
  return key;
}

function isSeqItemLine(line: Line): boolean {
  return line.content === "-" || line.content.startsWith("- ");
}

class BlockParser {
  private readonly lines: Line[];
  constructor(lines: Line[]) {
    this.lines = lines;
  }

  private lineAt(i: number): Line {
    const l = this.lines[i];
    if (!l) throw new Error(`yaml-lite: índice de línea fuera de rango (${i})`);
    return l;
  }

  parseDocument(): YamlValue {
    const [value, next] = this.parseBlock(0, 0);
    // Fail-closed (SEC-CNS-014 P2a): si queda una línea top-level sin consumir, el documento tiene
    // una estructura que este parser no entendió (p. ej. una indentación irregular); mejor un error
    // visible que devolver un valor parcial silenciosamente.
    if (next < this.lines.length) {
      throw new Error(`yaml-lite: línea ${this.lineAt(next).lineNo} sin consumir al terminar el documento: "${this.lineAt(next).content}"`);
    }
    return value ?? {};
  }

  // Devuelve [valor, siguienteÍndice]. `indent` es la indentación mínima esperada del bloque.
  private parseBlock(i: number, indent: number): [YamlValue, number] {
    if (i >= this.lines.length || this.lineAt(i).indent < indent) return [null, i];
    if (isSeqItemLine(this.lineAt(i))) return this.parseSeq(i, this.lineAt(i).indent);
    return this.parseMap(i, this.lineAt(i).indent);
  }

  private parseSeq(i: number, indent: number): [YamlValue[], number] {
    const items: YamlValue[] = [];
    while (i < this.lines.length && this.lineAt(i).indent === indent && isSeqItemLine(this.lineAt(i))) {
      const line = this.lineAt(i);
      const rest = line.content === "-" ? "" : line.content.slice(2);
      if (rest === "") {
        i++;
        if (i < this.lines.length && this.lineAt(i).indent > indent) {
          const [value, next] = this.parseBlock(i, this.lineAt(i).indent);
          items.push(value);
          i = next;
        } else {
          items.push(null);
        }
        continue;
      }
      // Ítem de secuencia que es un flow map/list en la misma línea: "- {id: X, ...}" / "- [a, b]"
      // (p. ej. legalDecisions/openItems de las specs reales). Se parsea como flow ANTES de intentar
      // "clave: valor": si no, splitKeyValue corta en el primer ":" dentro de las llaves y genera una
      // clave basura como "{id" (bug reportado, SEC-CNS-014 yaml-lite P2).
      if (rest.startsWith("{") || rest.startsWith("[")) {
        items.push(this.parseScalarField(rest));
        i++;
        continue;
      }
      const kv = splitKeyValue(rest);
      if (kv) {
        // Ítem de secuencia que es un mapeo inline: "- id: X". La indentación virtual de las
        // claves hermanas es la columna donde empieza "id" (indent + 2).
        const virtualIndent = indent + 2;
        const [map, next] = this.parseInlineMap(i, indent, virtualIndent, kv);
        items.push(map);
        i = next;
        continue;
      }
      items.push(this.parseScalarField(rest));
      i++;
    }
    return [items, i];
  }

  // Parsea un mapeo cuya primera línea es "- key: value" (el resto de claves va en líneas
  // siguientes con indentación == virtualIndent).
  private parseInlineMap(
    i: number,
    _seqIndent: number,
    virtualIndent: number,
    firstKv: { key: string; rest: string },
  ): [Record<string, YamlValue>, number] {
    const map: Record<string, YamlValue> = {};
    let idx = i;
    let kv: { key: string; rest: string } | null = firstKv;
    let firstLine = true;
    while (kv) {
      // Fail-closed (SEC-CNS-014 P2d): clave duplicada dentro del mismo mapeo por indentación.
      if (Object.prototype.hasOwnProperty.call(map, kv.key)) {
        throw new Error(`yaml-lite: clave duplicada "${kv.key}" en línea ${this.lineAt(idx).lineNo}`);
      }
      idx++;
      if (kv.rest === "") {
        if (idx < this.lines.length && this.lineAt(idx).indent > virtualIndent) {
          const [value, next] = this.parseBlock(idx, this.lineAt(idx).indent);
          map[kv.key] = value;
          idx = next;
        } else {
          map[kv.key] = null;
        }
      } else if (kv.rest === "|" || kv.rest === ">" || kv.rest === "|-" || kv.rest === ">-" || kv.rest === "|+" || kv.rest === ">+") {
        const [value, next] = this.parseBlockScalar(idx, virtualIndent);
        map[kv.key] = value;
        idx = next;
      } else {
        map[kv.key] = this.parseScalarField(kv.rest);
      }
      firstLine = false;
      if (idx < this.lines.length && this.lineAt(idx).indent === virtualIndent && !isSeqItemLine(this.lineAt(idx))) {
        kv = splitKeyValue(this.lineAt(idx).content);
        if (!kv) break;
      } else {
        kv = null;
      }
    }
    void firstLine;
    return [map, idx];
  }

  private parseMap(i: number, indent: number): [Record<string, YamlValue>, number] {
    const map: Record<string, YamlValue> = {};
    let idx = i;
    while (idx < this.lines.length && this.lineAt(idx).indent === indent && !isSeqItemLine(this.lineAt(idx))) {
      const kv = splitKeyValue(this.lineAt(idx).content);
      if (!kv) {
        throw new Error(`yaml-lite: línea ${this.lineAt(idx).lineNo} no parece "clave: valor": "${this.lineAt(idx).content}"`);
      }
      // Fail-closed (SEC-CNS-014 P2d): clave duplicada dentro del mismo mapeo por indentación.
      if (Object.prototype.hasOwnProperty.call(map, kv.key)) {
        throw new Error(`yaml-lite: clave duplicada "${kv.key}" en línea ${this.lineAt(idx).lineNo}`);
      }
      idx++;
      if (kv.rest === "") {
        if (idx < this.lines.length && this.lineAt(idx).indent > indent) {
          const [value, next] = this.parseBlock(idx, this.lineAt(idx).indent);
          map[kv.key] = value;
          idx = next;
        } else {
          map[kv.key] = null;
        }
      } else if (["|", ">", "|-", ">-", "|+", ">+"].includes(kv.rest)) {
        const [value, next] = this.parseBlockScalar(idx, indent);
        map[kv.key] = value;
        idx = next;
      } else {
        map[kv.key] = this.parseScalarField(kv.rest);
      }
    }
    return [map, idx];
  }

  private parseBlockScalar(i: number, parentIndent: number): [string, number] {
    const parts: string[] = [];
    let idx = i;
    while (idx < this.lines.length && this.lineAt(idx).indent > parentIndent) {
      parts.push(this.lineAt(idx).content);
      idx++;
    }
    return [parts.join(" ").trim(), idx];
  }

  private parseScalarField(rest: string): YamlValue {
    return parseFlowOrScalar(rest);
  }
}

export function parseYaml(text: string): YamlValue {
  const lines = toLines(text);
  return new BlockParser(lines).parseDocument();
}
