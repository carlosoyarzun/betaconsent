// Gobierna: plan v2 H1-05. App HTTP sobre adaptadores en memoria (sin base): camino feliz, CSRF y uniformidad.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, before, test } from "node:test";

import { generateInvitationToken } from "../../../src/domain/crypto.ts";
import { createMemoryPorts } from "../../../src/db/adapters/memory/memory-ports.ts";
import { MemoryMailer } from "../../../src/mail/memory-mailer.ts";
import { createApp } from "../../../src/server/app.ts";
import { createJsonLogger } from "../../../src/server/log.ts";
import { loadSpaBundle } from "../../../src/server/spa-assets.ts";
import { Browser, lastOtp, makeFixtureDist, ORIGIN } from "../../helpers-http.ts";

const ports = createMemoryPorts({});
const mailer = new MemoryMailer(ORIGIN);
let server: ReturnType<typeof createServer>;
let base = "";

before(async () => {
  const app = createApp({
    config: { publicOrigin: ORIGIN, sessionSecret: Buffer.alloc(48, 4), environment: "LOCAL" },
    ports,
    recipients: { forInvitation: async () => "a@pruebas.example.invalid" },
    readGuardianEmail: async () => "a@pruebas.example.invalid",
    mailer,
    policy: { dataClass: "SYNTHETIC", allowlist: ["@pruebas.example.invalid"] },
    outbox: { enqueue: async () => undefined },
    spa: loadSpaBundle(makeFixtureDist()),
    logger: createJsonLogger(() => undefined),
    checkHealth: async () => undefined,
  });
  server = createServer((req, res) => void app.handle(req, res));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
after(() => new Promise((r) => server.close(r)));

test("camino feliz en memoria hasta GRANTED + AUTHORIZED, y 403 sin CSRF", async () => {
  const { invitationRef } = await ports.invitations.import({ studentRef: "stu-mem-1", studentFirstName: "Ana", guardianEmail: "a@pruebas.example.invalid", batchRef: "b" });
  const { token, tokenHash } = generateInvitationToken();
  await ports.invitations.armToken({ invitationRef, tokenHash, expiresAt: new Date(Date.now() + 60_000), consentVersion: "v1" });
  const b = new Browser(base);
  assert.equal((await b.get(`/i/${token}`)).status, 303);
  assert.equal((await b.get("/welcome")).status, 200);
  assert.equal((await b.post("/invitation/open", {}, { csrf: false })).status, 403);
  assert.equal((await b.post("/invitation/open")).status, 200);
  assert.equal((await b.post("/otp/request")).status, 202);
  assert.equal((await b.post("/otp/submit", { code: lastOtp(mailer) })).status, 200);
  for (const s of [{ stepKind: "CONTEXT_INFORMATION_VIEWED" }, { stepKind: "CONSENT_VERSION_VIEWED" }, { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "LEGAL_GUARDIAN", authorityDeclared: true }, { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true }]) {
    assert.equal((await b.post("/decision/steps", s)).status, 200);
  }
  const partial = await b.post("/decision/submit", { purposes: [{ purpose: "STUDY_PARTICIPATION", choice: "GRANT" }] });
  assert.equal(partial.json.code, "PURPOSE_SELECTION_INVALID");
  const ok = await b.post("/decision/submit", { purposes: ["STUDY_PARTICIPATION", "AUDIO_RECORDING", "AUTOMATED_ANALYSIS", "HUMAN_REVIEW"].map((purpose) => ({ purpose, choice: "GRANT" })) });
  assert.equal(ok.json.state, "GRANTED");
  assert.equal((await ports.authorization.byStudentRef("stu-mem-1")).status, "AUTHORIZED");
});

test("pasos incompletos => 422 y sesión de otro handle => 404 (el último enlace manda)", async () => {
  const mk = async (ref: string) => {
    const { invitationRef } = await ports.invitations.import({ studentRef: ref, studentFirstName: "Ana", guardianEmail: "a@pruebas.example.invalid", batchRef: "b" });
    const t = generateInvitationToken();
    await ports.invitations.armToken({ invitationRef, tokenHash: t.tokenHash, expiresAt: new Date(Date.now() + 60_000), consentVersion: "v1" });
    return t.token;
  };
  const t1 = await mk("stu-mem-2");
  const t2 = await mk("stu-mem-3");
  const b = new Browser(base);
  await b.get(`/i/${t1}`);
  await b.get("/welcome");
  await b.post("/invitation/open");
  await b.post("/otp/request");
  await b.post("/otp/submit", { code: lastOtp(mailer) });
  assert.equal((await b.post("/decision/submit", { purposes: [] })).json.code, "DECISION_STEPS_INCOMPLETE");
  await b.get(`/i/${t2}`); // otro enlace: la sesión previa deja de valer
  assert.equal((await b.get("/decision/page-state")).status, 404);
});
