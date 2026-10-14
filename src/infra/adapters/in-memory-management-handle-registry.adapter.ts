// Gobierna: src/server/ports/management-handle.port.ts. Adaptador in-memory IT0 LOCAL/CI: registra el handle por hash en el
// MISMO TenantHandle que resuelve GET /m/{token} y /manage, y participa del journal del UoW (si la unidad revierte, el
// handle se deshace). Sin red.

import type { ManagementHandleRegistryPort } from "../../server/ports/management-handle.port.ts";
import type { InMemoryTenantHandleAdapter } from "./in-memory-tenant-handle.adapter.ts";
import { TX_JOURNAL, type TxParticipant, type Undo } from "./in-memory-tx.ts";

export interface InMemoryManagementHandleRegistry extends ManagementHandleRegistryPort, TxParticipant {}

export function createInMemoryManagementHandleRegistry(store: InMemoryTenantHandleAdapter): InMemoryManagementHandleRegistry {
  let journal: Undo[] | null = null;
  return {
    [TX_JOURNAL](j) {
      journal = j;
    },
    async register(input) {
      const undo = store.issueByHash(input);
      if (journal) journal.push(undo);
    },
  };
}
