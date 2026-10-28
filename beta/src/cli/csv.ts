// Gobierna: DEC de Carlos "Reconstrucción mínima" (2026-10-19), decisión 5 (identificadores opacos y CSV mínimo) y plan v2 H1-09.
// Parser CSV propio (sin dependencias, comillas RFC 4180 básicas) y validación del lote de invitaciones. Sin RUT, sin apellidos.

export const CSV_HEADER = ["student_ref", "student_first_name", "guardian_email"] as const;
export const MAX_ROWS = 10_000;
export const MAX_FIRST_NAME = 40;

/** Misma forma que el CHECK invitation_student_ref_shape / invitation_batch_ref_shape de la base. */
const OPAQUE_REF = /^[A-Za-z0-9_-]{8,64}$/;
const RUT_LIKE = /^[0-9]{7,8}-?[0-9kK]$/;
const EMAIL_SHAPE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

export function isBatchRef(v: string): boolean {
  return OPAQUE_REF.test(v);
}

export class CsvFormatError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "CsvFormatError";
    this.code = code;
  }
}

/** Parser RFC 4180 básico: campos entre comillas con "" como comilla literal y saltos de línea embebidos; separador coma; CRLF o LF. */
export function parseCsv(input: string): string[][] {
  const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  const records: string[][] = [];
  let record: string[] = [];
  let field = "";
  let inQuotes = false;
  let fieldStarted = false;
  const endField = (): void => {
    record.push(field);
    field = "";
    fieldStarted = false;
  };
  const endRecord = (): void => {
    endField();
    // Línea totalmente vacía: se ignora.
    if (!(record.length === 1 && record[0] === "")) records.push(record);
    record = [];
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
      continue;
    }
    if (c === '"' && !fieldStarted) {
      inQuotes = true;
      fieldStarted = true;
    } else if (c === '"') {
      throw new CsvFormatError("CSV_BAD_QUOTE");
    } else if (c === ",") {
      endField();
    } else if (c === "\r") {
      if (text[i + 1] === "\n") i++;
      endRecord();
    } else if (c === "\n") {
      endRecord();
    } else {
      field += c;
      fieldStarted = true;
    }
  }
  if (inQuotes) throw new CsvFormatError("CSV_UNTERMINATED_QUOTE");
  if (fieldStarted || field !== "" || record.length > 0) endRecord();
  return records;
}

export interface InvitationRow {
  readonly rowNumber: number;
  readonly studentRef: string;
  readonly studentFirstName: string;
  readonly guardianEmail: string;
}

export interface RowIssue {
  /** 1 = primera fila de datos (la cabecera no cuenta). */
  readonly row: number;
  readonly field: string;
  readonly reason: string;
  /** Solo para problemas del correo: forma enmascarada a***@dominio. */
  readonly masked_email?: string;
}

/** a***@dominio. Nunca devuelve el correo completo. */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  if (at < 1) return "***";
  return `${email.slice(0, 1)}***${email.slice(at)}`;
}

export type ParsedBatch = { readonly ok: true; readonly rows: InvitationRow[] } | { readonly ok: false; readonly headerError?: string; readonly issues: RowIssue[] };

/** Valida cabecera exacta y todas las filas. Devuelve TODAS las filas inválidas (todo o nada: si hay alguna, el llamador no escribe). */
export function parseInvitationCsv(input: string): ParsedBatch {
  const records = parseCsv(input);
  const header = records[0];
  if (header === undefined || header.length !== CSV_HEADER.length || header.some((h, i) => h !== CSV_HEADER[i])) {
    return { ok: false, headerError: `CSV_BAD_HEADER (se espera exactamente ${CSV_HEADER.join(",")})`, issues: [] };
  }
  const data = records.slice(1);
  if (data.length === 0) return { ok: false, headerError: "CSV_EMPTY", issues: [] };
  if (data.length > MAX_ROWS) return { ok: false, headerError: `CSV_TOO_MANY_ROWS (máximo ${MAX_ROWS})`, issues: [] };

  const rows: InvitationRow[] = [];
  const issues: RowIssue[] = [];
  const seen = new Set<string>();
  data.forEach((rec, idx) => {
    const row = idx + 1;
    if (rec.length !== CSV_HEADER.length) {
      issues.push({ row, field: "row", reason: "WRONG_COLUMN_COUNT" });
      return;
    }
    const ref = (rec[0] ?? "").trim();
    const name = (rec[1] ?? "").trim();
    const email = (rec[2] ?? "").trim().toLowerCase();
    const before = issues.length;
    if (!OPAQUE_REF.test(ref)) issues.push({ row, field: "student_ref", reason: "INVALID_OPAQUE_REF (8-64 de A-Za-z0-9_-)" });
    else if (RUT_LIKE.test(ref)) issues.push({ row, field: "student_ref", reason: "RUT_LIKE_REF_REJECTED" });
    else if (seen.has(ref)) issues.push({ row, field: "student_ref", reason: "DUPLICATE_STUDENT_REF_IN_FILE" });
    if (name.length < 1 || name.length > MAX_FIRST_NAME || CONTROL_CHARS.test(name)) issues.push({ row, field: "student_first_name", reason: `INVALID_FIRST_NAME (1-${MAX_FIRST_NAME} caracteres, sin control)` });
    if (!EMAIL_SHAPE.test(email) || email.length > 254) issues.push({ row, field: "guardian_email", reason: "INVALID_EMAIL", masked_email: maskEmail(email) });
    if (issues.length === before) {
      seen.add(ref);
      rows.push({ rowNumber: row, studentRef: ref, studentFirstName: name, guardianEmail: email });
    }
  });
  return issues.length > 0 ? { ok: false, issues } : { ok: true, rows };
}
