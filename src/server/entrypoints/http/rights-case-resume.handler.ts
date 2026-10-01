// Gobierna: contracts/openapi/consent-it0.openapi.yaml API-CNS-149 (POST /rights-case/resume),
// specs/state-machines/rights-case.spec.yaml RC2u (ConfirmCaseReturnViaHandle),
// specs/state-machines/common.spec.yaml GRD-CM-10, ERR-CM-09, ERR-CM-01.
// TEST-CNS-468, TEST-CNS-469, TEST-CNS-470 (traceability/test-matrix.csv).
//
// Handler puro (sin node:http): recibe la request ya normalizada (cabeceras/cookies leídas
// por el transport en server.ts) y devuelve status+body. GRD-CM-10 se aplica ANTES de
// resolver el handle o llamar cualquier función de transición (ninguna transición se dispara
// si falla CSRF/Origin). x-uniform-response (API-CNS-149): 200 IN_REVIEW idéntico para éxito,
// caso ya CONTACTING, origin != CHANNEL_UNREACHABLE (ERR-RC-01) y caso no ligado (ERR-RC-09);
// ERR-CM-01/ERR-CM-10 -> 404 uniforme; ERR-CM-09 -> 403 (GRD-CM-10 onFail).

import { randomUUID } from "node:crypto";

import { DomainError } from "../../modules/common/errors.ts";
import { assertCsrfAndOrigin } from "../../modules/common/guards.ts";
import { confirmCaseReturnViaHandle, type RightsCasePorts } from "../../modules/rights-case/rights-case.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";

export interface RawRequestInfo {
  readonly originHeader: string | undefined;
  readonly csrfHeaderToken: string | undefined;
  readonly cookieHeader: string | undefined;
}

export interface HttpResult {
  readonly status: 200 | 403 | 404;
  readonly body: Readonly<Record<string, unknown>>;
}

const RIGHTS_PATHS_AVAILABLE = ["OTP", "RECOVERY_LINK", "HUMAN_CASE"] as const;

function inReviewAck(): HttpResult {
  return { status: 200, body: { result: "IN_REVIEW", rightsPathsAvailable: RIGHTS_PATHS_AVAILABLE } };
}

function csrfRejected(): HttpResult {
  return { status: 403, body: { code: "CSRF_REJECTED", status: 403, correlationId: randomUUID() } };
}

function uniformNotFound(): HttpResult {
  return { status: 404, body: { status: 404 } };
}

/**
 * RC2u vía HTTP. GRD-CM-10 primero (sin excepción); si pasa, resuelve el handle desde la
 * cookie manage y llama confirmCaseReturnViaHandle, que ya encapsula GRD-CM-01/GRD-RC-14/
 * GRD-RC-07. No consume el handle: la cookie no se toca ni se rota aquí (TEST-CNS-470).
 */
export async function handleConfirmCaseReturnViaHandle(
  request: RawRequestInfo,
  ports: Pick<RightsCasePorts, "tenantHandle" | "rightsCaseRepo" | "ledger" | "uow">,
  config: RightsCaseHttpConfig,
): Promise<HttpResult> {
  const cookies = parseCookies(request.cookieHeader);

  try {
    assertCsrfAndOrigin({
      originHeader: request.originHeader,
      allowedOrigin: config.allowedOrigin,
      csrfHeaderToken: request.csrfHeaderToken,
      csrfCookieToken: cookies[config.csrfCookieName],
    });

    const handle = cookies[config.manageHandleCookieName] ?? "";
    await confirmCaseReturnViaHandle(ports, handle);
    return inReviewAck();
  } catch (err) {
    if (err instanceof DomainError) {
      switch (err.code) {
        case "ERR-CM-09":
          return csrfRejected();
        case "ERR-CM-01":
        case "ERR-CM-10":
          return uniformNotFound();
        case "ERR-RC-01":
        case "ERR-RC-09":
          // x-uniform-response: el fallo de estas guards no se distingue del éxito.
          return inReviewAck();
        default:
          // Fail-closed: cualquier otro DomainError no previsto por esta transición se trata
          // como 404 uniforme, nunca se filtra al cliente.
          return uniformNotFound();
      }
    }
    throw err;
  }
}
