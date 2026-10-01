// Gobierna: ADR-001 §11 ("los adaptadores ... solo los importa src/server/entrypoints/**").
// Único punto de cableado de adaptadores in-memory IT0 con node:http puro (sin frameworks,
// sin dependencias nuevas). Expone createRightsCaseHttpServer para tests (puerto efímero de
// localhost) y para un futuro proceso real.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { createInMemoryLedgerAdapter } from "../../../infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../infra/adapters/in-memory-rights-case-repository.adapter.ts";
import {
  createInMemoryTenantHandleAdapter,
  type InMemoryTenantHandleAdapter,
} from "../../../infra/adapters/in-memory-tenant-handle.adapter.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { RightsCaseRepositoryPort } from "../../ports/rights-case-repository.port.ts";
import type { UnitOfWorkPort } from "../../ports/unit-of-work.port.ts";
import { createInMemoryTenancy } from "../../../infra/adapters/in-memory-tenancy.ts";
import type { RightsCasePorts } from "../../modules/rights-case/rights-case.ts";
import { loadRightsCaseHttpConfig, type RightsCaseHttpConfig } from "./config.ts";
import { handleConfirmCaseReturnViaHandle } from "./rights-case-resume.handler.ts";

/** Ports in-memory concretos que cablea este entrypoint (único punto de wiring, ADR-001 §11).
 * Expone los tipos concretos de los adaptadores (no solo el port) para que los tests puedan
 * usar sus métodos de seed (issue/rotate) sin castear. */
export interface RightsCaseInMemoryPorts {
  readonly tenantHandle: InMemoryTenantHandleAdapter;
  readonly rightsCaseRepo: RightsCaseRepositoryPort;
  readonly ledger: LedgerPort;
  readonly uow: UnitOfWorkPort;
}

export interface RightsCaseHttpServerOptions {
  readonly config?: Partial<RightsCaseHttpConfig>;
  /** Ports a usar; si se omiten, este entrypoint los cablea. Los tests inyectan los suyos
   * para poder seedear estado antes del request. */
  readonly ports?: Pick<RightsCasePorts, "tenantHandle" | "rightsCaseRepo" | "ledger" | "uow">;
}

export function createDefaultInMemoryPorts(): RightsCaseInMemoryPorts {
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  const ledger = createInMemoryLedgerAdapter();
  return {
    tenantHandle: createInMemoryTenantHandleAdapter(),
    rightsCaseRepo,
    ledger,
    uow: createInMemoryTenancy({ ledger, rightsCaseRepo }).uow,
    // revocationRepo no lo usa RC2u; se mantiene fuera de este subconjunto de ports.
  };
}

function readBody(req: IncomingMessage): Promise<void> {
  // EmptyCommand (contracts/api-payloads.schema.json): el cuerpo no lleva campos; solo se
  // drena el stream para no dejar la conexión colgada, sin parsear ni usar su contenido.
  return new Promise((resolve, reject) => {
    req.on("data", () => {});
    req.on("end", () => resolve());
    req.on("error", reject);
  });
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

/** P1: contracts/openapi/consent-it0.openapi.yaml fija application/problem+json en
 * components.responses.CsrfRejected (403); el resto (200 InReviewAck, 404 UniformNotFound) es
 * application/json. */
function contentTypeForStatus(status: number): string {
  return status === 403 ? "application/problem+json" : "application/json";
}

export function createRightsCaseHttpServer(options: RightsCaseHttpServerOptions = {}): Server {
  const config = loadRightsCaseHttpConfig(options.config);
  const ports = options.ports ?? createDefaultInMemoryPorts();

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? "";
    const path = url.split("?", 1)[0];

    if (req.method === "POST" && path === "/rights-case/resume") {
      await readBody(req);
      const result = await handleConfirmCaseReturnViaHandle(
        {
          originHeader: headerValue(req.headers.origin),
          csrfHeaderToken: headerValue(req.headers[config.csrfHeaderName]),
          cookieHeader: headerValue(req.headers.cookie),
        },
        ports,
        config,
      );
      const payload = JSON.stringify(result.body);
      res.writeHead(result.status, { "content-type": contentTypeForStatus(result.status) });
      res.end(payload);
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: 404 }));
  });
}
