// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), ADR-001 §11 regla (4),
// JIRA CA-118 (H03).
//
// Entrypoint de la capa "contract": corre la misma suite de ExampleCounterPort contra
// dos adaptadores de ejemplo. Cuando exista un puerto real en src/server/ports/** (p.
// ej. ObjectStorage), su suite de contrato sigue este mismo patrón: un archivo
// *.contract.ts con los casos y un *.test.ts por puerto que lo registra contra cada
// adaptador real (fake en memoria y adaptador IT0), tal como exige ADR-001 §11 regla
// (4).

import { runExampleCounterPortContract } from "./example-port.contract.ts";
import { createInMemoryCounterAdapter } from "./adapters/in-memory.adapter.ts";
import { createArrayLogCounterAdapter } from "./adapters/array-log.adapter.ts";

runExampleCounterPortContract("in-memory", createInMemoryCounterAdapter);
runExampleCounterPortContract("array-log", createArrayLogCounterAdapter);
