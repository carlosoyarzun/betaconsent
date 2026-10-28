// Gobierna: plan v2 H1-08. Mock de LectorPro para el E2E: usa el cliente de referencia y decide si puede iniciar una lectura (DEC-BR-022 (b): consulta antes de CADA lectura).
import { createAuthorizationClient } from "../../src/client/lectorpro-authorization-client.ts";
import type { AuthorizationClientOptions, ClientLogEvent } from "../../src/client/lectorpro-authorization-client.ts";

export function createLectorProMock(opts: AuthorizationClientOptions): { canStartReading(studentRef: string): Promise<boolean>; readonly events: readonly ClientLogEvent[] } {
  const events: ClientLogEvent[] = [];
  const client = createAuthorizationClient({ ...opts, onEvent: (e) => void events.push(e) });
  return { canStartReading: (studentRef) => client.isAuthorized(studentRef), events };
}
