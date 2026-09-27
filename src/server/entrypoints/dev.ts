#!/usr/bin/env node
// Entrypoint de desarrollo LOCAL (GRD-CM-13, ADR-003 rev. 7: sin infraestructura real, solo
// adapters in-memory). Arranca el flujo invitación -> OTP -> decisión en 127.0.0.1 con un
// tenant, un contexto BETA_2026_01 y una invitación sintéticos (dominio example.invalid, cero
// PII). Exige environment=LOCAL: cualquier otro valor aborta antes de escuchar (fail-closed).
// Uso: `node src/server/entrypoints/dev.ts` (PORT opcional, default 3000). Documentado en
// src/README.md.

import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createDefaultConsentFlowPorts } from "./http/consent-flow-server.ts";
import { loadOtpPolicyConfig } from "../modules/otp-challenge/otp-policy.config.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../modules/invitation/invitation.ts";
import { LECTORPRO_BETA_CONFIG } from "../modules/consent-decision/lectorpro-beta.config.ts";

const environment = process.env.CNS_ENVIRONMENT ?? "";
if (environment !== "LOCAL") {
  // GRD-CM-13 (fixture_actor_environment): este entrypoint es de seed FIXTURE + sink de
  // depuración; solo puede correr en LOCAL. Aborta sin escuchar ningún puerto.
  console.error(
    `dev.ts requiere CNS_ENVIRONMENT=LOCAL (recibido: "${environment || "(vacío)"}"). ` +
      "Nunca corre en DEV/STAGING/PRODUCTION (GRD-CM-13). Abortando.",
  );
  process.exit(1);
}

const port = Number.parseInt(process.env.PORT ?? "3000", 10);
const allowedOrigin = process.env.CNS_ALLOWED_ORIGIN ?? `http://127.0.0.1:${port}`;

// D4: P-01/P-02/P-03 no tienen valor aprobado en specs/contracts; este override es
// LOCAL-only, nunca un default de producción (ver otp-policy.config.ts).
const LOCAL_ONLY_DEV_OTP_POLICY = { codeLength: 6, ttlMs: 5 * 60_000, maxAttempts: 3 };
const otpPolicy = loadOtpPolicyConfig(LOCAL_ONLY_DEV_OTP_POLICY);

const ports = createDefaultConsentFlowPorts(otpPolicy);
const sessionSecret = randomBytes(32);

const TENANT_ID = "tenant-dev";
const INVITATION_REF = "inv-dev-001";
const SUBJECT_REF = "dev-subject@example.invalid";
const CHANNEL_REF = "dev-decision-maker@example.invalid";

createInvitation(ports.invitation, TENANT_ID, "INVITER", {
  invitationRef: INVITATION_REF,
  contextRef: LECTORPRO_BETA_CONFIG.contextRef,
  productRef: LECTORPRO_BETA_CONFIG.productRef,
  subjectRef: SUBJECT_REF,
});
markInvitationReady(ports.invitation, TENANT_ID, "INVITER", INVITATION_REF, {
  consentVersion: "v1-dev",
  expiresAt: new Date(Date.now() + 24 * 60 * 60_000),
  recipientChannelRef: CHANNEL_REF,
});
const { token } = sendInvitation(ports.invitation, TENANT_ID, "INVITER", INVITATION_REF);

const server = createConsentFlowHttpServer({
  config: { allowedOrigin },
  ports,
  sessionSecret,
  environment: "LOCAL",
});

server.listen(port, "127.0.0.1", () => {
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  console.log(`Consent App (IT0, LOCAL) escuchando en ${baseUrl}`);
  console.log(`Invitación sintética (token de un solo uso, body de POST /invitation/open): ${token}`);
  console.log(`Leer el OTP emitido: GET ${baseUrl}/__dev/otp-sink (solo existe con CNS_ENVIRONMENT=LOCAL).`);
});
