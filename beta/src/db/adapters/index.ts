// Gobierna: plan v2 H1-04. Ensamble de los puertos sobre PostgreSQL.
import type { Ports } from "../../ports/index.ts";
import type { UnitOfWork } from "../unit-of-work.ts";
import { createPgAuthorizationQuery } from "./authorization.adapter.ts";
import { createPgDecisionRepo } from "./decision.adapter.ts";
import { createPgInvitationRepo } from "./invitation.adapter.ts";
import { createPgOtpRepo } from "./otp.adapter.ts";
import { createPgRevocationRepo } from "./revocation.adapter.ts";

export interface PgPortsOptions {
  /** Unidad de trabajo sobre el pool del rol consent_mailer: issue_otp y arm_invitation_token (SEC-CNS-024-V1). */
  readonly mailerUow: UnitOfWork;
}

/** `uow` = pool de la app (consent_app, atiende HTTP); `mailerUow` = pool de consent_mailer (emite OTP y tokens). */
export function createPgPorts(uow: UnitOfWork, { mailerUow }: PgPortsOptions): Ports {
  return {
    invitations: createPgInvitationRepo(uow, mailerUow),
    otp: createPgOtpRepo(uow, mailerUow),
    decisions: createPgDecisionRepo(uow),
    revocations: createPgRevocationRepo(uow),
    authorization: createPgAuthorizationQuery(uow),
  };
}
