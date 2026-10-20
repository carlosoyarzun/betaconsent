// Gobierna: plan v2 H1-04. Conjunto de puertos que consume el backend HTTP (H1-05).
import type { AuthorizationStatusQuery } from "./authorization.port.ts";
import type { DecisionRepo } from "./decision.port.ts";
import type { InvitationRepo } from "./invitation.port.ts";
import type { OtpRepo } from "./otp.port.ts";
import type { RevocationRepo } from "./revocation.port.ts";

export type * from "./authorization.port.ts";
export type * from "./decision.port.ts";
export type * from "./invitation.port.ts";
export type * from "./otp.port.ts";
export type * from "./revocation.port.ts";

export interface Ports {
  readonly invitations: InvitationRepo;
  readonly otp: OtpRepo;
  readonly decisions: DecisionRepo;
  readonly revocations: RevocationRepo;
  readonly authorization: AuthorizationStatusQuery;
}
