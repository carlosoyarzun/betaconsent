// Gobierna: plan v2 H1-04. Consulta de autorización; authorization_status de 0003 (AUTHORIZED solo con decisión GRANTED no revocada).
import type { AuthorizationStatus, ConsentId, StudentRef } from "../domain/types.ts";

export interface AuthorizationStatusResult {
  readonly status: AuthorizationStatus;
  readonly asOf: Date;
  readonly decisionRef: ConsentId | null;
}

export interface AuthorizationStatusQuery {
  byStudentRef(studentRef: StudentRef): Promise<AuthorizationStatusResult>;
}
