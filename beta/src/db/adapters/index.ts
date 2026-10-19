// Gobierna: plan v2 H1-04. Ensamble de los puertos sobre PostgreSQL.
import type { Ports } from "../../ports/index.ts";
import type { UnitOfWork } from "../unit-of-work.ts";
import { createPgAuthorizationQuery } from "./authorization.adapter.ts";
import { createPgDecisionRepo } from "./decision.adapter.ts";
import { createPgInvitationRepo } from "./invitation.adapter.ts";
import { createPgOtpRepo } from "./otp.adapter.ts";
import { createPgRevocationRepo } from "./revocation.adapter.ts";

export function createPgPorts(uow: UnitOfWork): Ports {
  return {
    invitations: createPgInvitationRepo(uow),
    otp: createPgOtpRepo(uow),
    decisions: createPgDecisionRepo(uow),
    revocations: createPgRevocationRepo(uow),
    authorization: createPgAuthorizationQuery(uow),
  };
}
