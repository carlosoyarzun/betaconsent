// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), JIRA CA-118 (H03),
// DEC-BR-014 E5.
//
// Contexto de una corrida de tests, sin PII: id de corrida, commit y hora UTC.
// Usado por tools/testing/run-tests.ts y tools/testing/evidence-reporter.ts.

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";

export interface RunContext {
  runId: string;
  commitSha: string;
  startedAt: string;
}

export function getRunContext(): RunContext {
  const runId = process.env.TEST_RUN_ID ?? deriveRunId();
  const commitSha = process.env.GITHUB_SHA ?? gitHeadSha();
  const startedAt = new Date().toISOString();
  return { runId, commitSha, startedAt };
}

function deriveRunId(): string {
  // GitHub Actions: run_id-run_attempt es estable dentro de la misma corrida de
  // workflow y distingue reintentos; fuera de CI, un UUID por invocación.
  if (process.env.GITHUB_RUN_ID) {
    const attempt = process.env.GITHUB_RUN_ATTEMPT ?? "1";
    return `${process.env.GITHUB_RUN_ID}-${attempt}`;
  }
  return `local-${randomUUID()}`;
}

function gitHeadSha(): string {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  } catch {
    return "UNKNOWN";
  }
}
