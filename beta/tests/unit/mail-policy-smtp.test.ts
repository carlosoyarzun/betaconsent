// Gobierna: plan v2 H1-06. Allowlist por data_class, TLS del adaptador SMTP y OTP síncrono sin rastro.
import assert from "node:assert/strict";
import { test } from "node:test";

import { MemoryMailer } from "../../src/mail/memory-mailer.ts";
import { OtpSendError, OtpSuppressedError, sendOtpNow } from "../../src/mail/otp.ts";
import { isRecipientAllowed, readDataClass, type RecipientPolicy } from "../../src/mail/recipient-policy.ts";
import { buildTransportOptions } from "../../src/mail/smtp-mailer.ts";

const SYN: RecipientPolicy = { dataClass: "SYNTHETIC", allowlist: ["qa@example.invalid", "@pruebas.example.invalid"] };

test("SYNTHETIC: solo correos y dominios de la allowlist", () => {
  assert.ok(isRecipientAllowed("QA@example.invalid", SYN));
  assert.ok(isRecipientAllowed("cualquiera@pruebas.example.invalid", SYN));
  assert.ok(!isRecipientAllowed("otro@example.invalid", SYN));
  assert.ok(!isRecipientAllowed("x@sub.pruebas.example.invalid", SYN));
  assert.ok(!isRecipientAllowed("x@pruebas.example.invalid.evil.invalid", SYN));
  assert.ok(!isRecipientAllowed("sin-arroba", SYN));
});

test("REAL: la allowlist se ignora", () => {
  assert.ok(isRecipientAllowed("cualquiera@real.example.invalid", { dataClass: "REAL", allowlist: [] }));
});

test("readDataClass lee ops.db_catalog y falla cerrado", async () => {
  const q = (rows: { data_class: string }[]) => ({ query: async () => ({ rows }) }) as never;
  assert.equal(await readDataClass(q([{ data_class: "SYNTHETIC" }])), "SYNTHETIC");
  await assert.rejects(readDataClass(q([])));
  await assert.rejects(readDataClass(q([{ data_class: "OTHER" }])));
});

test("SMTP: TLS obligatorio y jamás rejectUnauthorized:false", () => {
  const a = buildTransportOptions({ smtpUrl: "smtps://u:p@smtp.example.invalid:465" });
  assert.equal(a.secure, true);
  const b = buildTransportOptions({ smtpUrl: "smtp://u:p@smtp.example.invalid:587" });
  assert.equal(b.secure, false);
  assert.equal(b.requireTLS, true);
  assert.equal(buildTransportOptions({ smtpUrl: "smtp://smtp.example.invalid:465" }).secure, true);
  for (const o of [a, b]) assert.ok(!JSON.stringify(o).includes("rejectUnauthorized"));
  // Texto plano: solo con la bandera Y host loopback.
  assert.equal(buildTransportOptions({ smtpUrl: "smtp://smtp.example.invalid:25", allowPlaintextLoopback: true }).requireTLS, true);
  assert.equal(buildTransportOptions({ smtpUrl: "smtp://localhost:1025", allowPlaintextLoopback: true }).ignoreTLS, true);
  assert.equal(buildTransportOptions({ smtpUrl: "smtp://localhost:1025" }).requireTLS, true);
  assert.throws(() => buildTransportOptions({ smtpUrl: "http://x" }));
});

test("OTP: no aparece en stdout/stderr/console ni en el error al fallar", async () => {
  const CODE = "735192";
  const captured: string[] = [];
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  const methods = ["log", "info", "warn", "error", "debug"] as const;
  const origConsole = methods.map((m) => console[m]);
  const spy = (chunk: unknown): boolean => (captured.push(String(chunk)), true);
  const consoleSpy = (...args: unknown[]): void => void captured.push(args.map(String).join(" "));
  methods.forEach((m) => (console[m] = consoleSpy));
  let failure: unknown;
  const ok = new MemoryMailer();
  const bad = new MemoryMailer();
  bad.failWith = new Error(`SMTP rechazó el mensaje con cuerpo ${CODE}`);
  try {
    // Parchea solo durante el envío: el reporter de node:test usa stdout.
    process.stdout.write = spy as never;
    process.stderr.write = spy as never;
    await sendOtpNow(ok, "qa@example.invalid", CODE);
    await sendOtpNow(bad, "qa@example.invalid", CODE).catch((e: unknown) => (failure = e));
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
    methods.forEach((m, i) => (console[m] = origConsole[i] as never));
  }
  assert.equal(ok.sent.length, 1);
  assert.ok(ok.sent[0]?.text.includes(CODE), "el código sí viaja en el cuerpo del correo");
  assert.ok(!ok.sent[0]?.subject.includes(CODE));
  assert.ok(failure instanceof OtpSendError);
  assert.ok(!String((failure as Error).message + (failure as Error).stack).includes(CODE));
  assert.ok(!(failure as { cause?: unknown }).cause);
  assert.equal(captured.filter((c) => c.includes(CODE)).length, 0, "el código apareció en el log");
});

test("OTP: fuera de la allowlist no se envía", async () => {
  const m = new MemoryMailer();
  await assert.rejects(sendOtpNow(m, "x@fuera.example.invalid", "111111", { policy: SYN }), OtpSuppressedError);
  assert.equal(m.sent.length, 0);
  await sendOtpNow(m, "qa@example.invalid", "111111", { policy: SYN });
  assert.equal(m.sent.length, 1);
});
