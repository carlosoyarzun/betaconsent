// Gobierna: ADR-010 rev. 5 §4.3(2) / §10 PR-6b (begin_oidc_authorization + complete_oidc_callback reemplazan a enqueue_oidc_exchange); tests de PR-4/PR-6-0 que necesitan una
// solicitud STEP_UP en PENDING. Helper SOLO de tests: compone las dos funciones con un state aleatorio, igual que lo haria el navegador honesto (state en cookie y en el callback).
// Devuelve exchange_ref o null si la base deniega (la evidencia ya se confirmo: las funciones no lanzan ante un DENY).

import { createHash, randomBytes } from "node:crypto";
import type { Client } from "pg";

export const STEP_UP_P51_MAX = 1000;
export const STEP_UP_P51_WINDOW_SECONDS = 3600;

export async function enqueueStepUp(platform: Client, principal: string | null, binding: string, code: string, pkceVerifier: string, ttlSeconds = 60): Promise<string | null> {
  const state = randomBytes(24).toString("base64url");
  const stateHash = createHash("sha256").update(state, "utf8").digest("hex");
  await platform.query("BEGIN");
  let ref: string | null;
  try {
    if (principal !== null) await platform.query("SELECT set_config('app.principal_ref', $1, true)", [principal]);
    ref = (await platform.query<{ r: string | null }>(
      "SELECT platform.begin_oidc_authorization('STEP_UP', $1, $2, $3, NULL, $4, NULL, $5, $6) AS r",
      [stateHash, binding, pkceVerifier, ttlSeconds, STEP_UP_P51_MAX, STEP_UP_P51_WINDOW_SECONDS],
    )).rows[0]?.r ?? null;
    await platform.query("COMMIT");
  } catch (error) {
    await platform.query("ROLLBACK");
    throw error;
  }
  if (ref === null) return null;
  await platform.query("BEGIN");
  try {
    const done = (await platform.query<{ r: string | null }>("SELECT platform.complete_oidc_callback($1, $2) AS r", [state, code])).rows[0]?.r ?? null;
    await platform.query("COMMIT");
    return done;
  } catch (error) {
    await platform.query("ROLLBACK");
    throw error;
  }
}
