// Gobierna: specs/test-framework.spec.yaml §"Evidence format" (TEST-FRAMEWORK),
// JIRA CA-118 (H03), DEC-BR-014 E5 ("formato de evidencia definido").
//
// Reporter de node:test que emite una línea JSON (JSON Lines) por caso de test hoja
// (test:pass / test:fail; se omiten hooks y nodos de suite). Se usa junto al reporter
// "spec" (salida humana en stdout) vía --test-reporter-destination separado; ver
// tools/testing/run-tests.ts. Cero PII: solo IDs de test, ruta relativa del archivo,
// resultado, duración y, si falla, el código de error y un mensaje truncado (nunca
// valores de datos ni stack trace completo).

import { relative } from "node:path";
import { getRunContext } from "./run-context.ts";

interface TestEventErrorDetails {
  code?: string;
  message?: string;
  cause?: { message?: string };
}

interface TestEventData {
  name: string;
  file?: string;
  testNumber?: number;
  skip?: boolean | string;
  todo?: boolean | string;
  details?: {
    type?: string;
    duration_ms?: number;
    error?: TestEventErrorDetails;
  };
}

interface TestEvent {
  type: string;
  data: TestEventData;
}

const REPO_ROOT = process.env.EVIDENCE_REPO_ROOT ?? process.cwd();
const LAYER = process.env.TEST_LAYER ?? "unknown";
const GOVERNING_ID_RE =
  /\b(?:TEST-CNS-\d+|REQ-CNS-\d+|RULE-CNS-\d+|SEC-CNS-\d+|API-CNS-\d+|PRIV-CNS-\d+|UX-CNS-\d+|DEC-CNS-\d+|DEC-BR-\d+|ADR-\d+)\b/g;
const MAX_ERROR_MESSAGE_LENGTH = 200;

function extractGovernedBy(name: string): string[] {
  const matches = name.match(GOVERNING_ID_RE);
  return matches ? [...new Set(matches)] : [];
}

function toRelativeFile(file: string | undefined): string | null {
  if (!file) return null;
  try {
    return relative(REPO_ROOT, file);
  } catch {
    return file;
  }
}

function truncate(value: string | null | undefined, max: number): string | null {
  if (typeof value !== "string") return null;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function resultOf(eventType: string, data: TestEventData): "pass" | "fail" | "skip" | "todo" {
  if (eventType === "test:fail") return "fail";
  if (data.skip !== undefined && data.skip !== false) return "skip";
  if (data.todo !== undefined && data.todo !== false) return "todo";
  return "pass";
}

function errorSummary(data: TestEventData): { code: string | null; message: string | null } | null {
  const error = data.details?.error;
  if (!error) return null;
  return {
    code: typeof error.code === "string" ? error.code : null,
    message: truncate(error.cause?.message ?? error.message ?? null, MAX_ERROR_MESSAGE_LENGTH),
  };
}

export default async function* evidenceReporter(source: AsyncIterable<TestEvent>): AsyncGenerator<string> {
  const { runId, commitSha } = getRunContext();

  for await (const event of source) {
    if (event.type !== "test:pass" && event.type !== "test:fail") continue;
    const { data } = event;
    // Solo casos hoja de tipo "test" (no hooks ni before/after).
    if (data.details?.type !== "test") continue;

    const line = {
      schema: "test-evidence/v1",
      runId,
      commitSha,
      recordedAt: new Date().toISOString(),
      layer: LAYER,
      file: toRelativeFile(data.file),
      testName: data.name,
      testNumber: data.testNumber ?? null,
      durationMs: data.details?.duration_ms ?? null,
      result: resultOf(event.type, data),
      governedBy: extractGovernedBy(data.name ?? ""),
      error: event.type === "test:fail" ? errorSummary(data) : null,
    };
    yield `${JSON.stringify(line)}\n`;
  }
}
