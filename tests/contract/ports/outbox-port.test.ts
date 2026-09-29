// Gobierna: src/server/ports/outbox.port.ts (CA-127), ADR-001 §11 regla (4). TEST-CNS-694.

import { runOutboxPortContract } from "./outbox-port.contract.ts";
import { createInMemoryOutboxAdapter } from "../../../src/infra/adapters/in-memory-outbox.adapter.ts";

runOutboxPortContract("in-memory", createInMemoryOutboxAdapter);
