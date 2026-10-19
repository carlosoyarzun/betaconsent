// Gobierna: UX-CNS-002 (+ UX-CNS-004 §3 para los scopes MANAGE/REVOCATION) y ADR-001 F1 fase B. Equivale a renderVerifyPage(scope)
// de verify-page.ts + assets/verify.js: UNA pantalla parametrizada por `scope` (como `data-verify-scope` en el SSR).
// Esta fase solo monta `scope="DECISION"` en /verify; los otros dos scopes quedan listos y probados aquí para quien migre
// /manage/verify y /manage/revocation/verify (no se tocan sus archivos de página).
// INV-OT-06: en MANAGE/REVOCATION el bloqueo NUNCA ofrece «solicitar nuevo código»; ofrece recuperación (RV0) y caso humano (RC1).
// Copy [UX — borrador] tal cual el SSR (incluidos los marcadores P-01/P-02/P-06 sin valor aprobado): no se redacta aquí.
import { useRef, useState } from "react";
import { postJson } from "../../api/client.ts";
import { AlertHead } from "../alert-head.tsx";
import { HelpLink } from "../help-link.tsx";
import { Stepper } from "../stepper.tsx";
import { navigation } from "../../router.ts";
import { NetworkAlert, UniformAlert } from "./alerts.tsx";
import { useFocusWhen } from "./use-focus-when.ts";

export type VerifyScope = "DECISION" | "MANAGE" | "REVOCATION";

/** Equivale a NEXT_ROUTE_BY_SCOPE de verify-page.ts (`data-verify-next`). */
const NEXT_ROUTE_BY_SCOPE: Readonly<Record<VerifyScope, string>> = {
  DECISION: "/decision",
  MANAGE: "/manage",
  REVOCATION: "/manage/revocation/confirm",
};

type View = "none" | "rejected" | "expired" | "locked" | "network" | "uniform" | "resend-ok" | "resend-limit";
type LastAction = "submit" | "request" | null;

const RESEND_OK_MESSAGE = "Te enviamos un nuevo código.";
const RESEND_LIMIT_MESSAGE = "Alcanzaste el límite de reenvíos disponible por ahora.";
const CONNECT_FEEDBACK = "No pudimos conectar. Inténtalo nuevamente.";

/** Estado de error uniforme de la propia pantalla (equivale a renderVerifyUniformErrorPage()). */
/** Copy BORRADOR (H1-10). Sin plazos ni promesas. */
const HUMAN_CASE_MESSAGE = "Si no puedes recibir el código, contacta al colegio. El colegio verificará tu identidad y te indicará cómo continuar.";

export function VerifyUniformError() {
  return (
    <main className="lp-page-container lp-verify-page" aria-labelledby="verify-h1">
      <h1 id="verify-h1">Verifica el código</h1>
      <UniformAlert title="No pudimos continuar con esta verificación.">
        <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
      </UniformAlert>
      <HelpLink />
    </main>
  );
}

export function VerifyScreen({ scope }: { readonly scope: VerifyScope }) {
  const isRights = scope === "MANAGE" || scope === "REVOCATION";
  const nextRoute = NEXT_ROUTE_BY_SCOPE[scope];
  const [view, setView] = useState<View>("none");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [rightsFeedback, setRightsFeedback] = useState<string | null>(null);
  const busyRef = useRef(false);
  const codeRef = useRef("");
  const lastAction = useRef<LastAction>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const lockedRightsRef = useRef<HTMLDivElement>(null);

  // 33:11: en el bloqueo RIGHTS el foco pasa a la alerta (tabindex=-1).
  useFocusWhen(lockedRightsRef, view === "locked" && isRights);

  function changeBusy(next: boolean): void {
    busyRef.current = next;
    setBusy(next);
  }

  function handleOtpRejected(errorCode: string): void {
    if (errorCode === "OTP_LOCKED" || errorCode === "OTP_BUDGET_EXHAUSTED_DECISION" || errorCode === "OTP_BUDGET_EXHAUSTED_RIGHTS") {
      // SEC-CNS-021 PR-4 (V6/V6r): presupuesto agotado = mismo estado bloqueado (sin copy nuevo); RIGHTS conserva RECOVERY visible.
      setView("locked");
    } else if (errorCode === "OTP_EXPIRED_OR_CONSUMED") {
      setView("expired");
    } else {
      // OTP_CODE_REJECTED por defecto: no revela intentos restantes (V2, ERR-OT-02).
      setView("rejected");
    }
  }

  async function submitCode(): Promise<void> {
    if (busyRef.current) return;
    lastAction.current = "submit";
    setView("none");
    changeBusy(true);
    const res = await postJson("/otp/submit", { code: codeRef.current });
    changeBusy(false);
    if (res.ok) {
      if (res.status === 200) navigation.assign(nextRoute);
      return; // 2xx distinto de 200: sin `code`, el SSR no muestra nada
    }
    if (res.error.kind === "network") setView("network");
    else if (res.error.status === 404) setView("uniform");
    else if (res.error.code !== undefined) handleOtpRejected(res.error.code);
  }

  async function requestNewCode(): Promise<void> {
    if (busyRef.current) return;
    lastAction.current = "request";
    setView("none");
    changeBusy(true);
    const res = await postJson("/otp/request");
    changeBusy(false);
    if (!res.ok && res.error.kind === "network") {
      setView("network");
      return;
    }
    if (!res.ok && res.error.status === 404) {
      setView("uniform");
      return;
    }
    // 202 UniformAccepted: nuevo challenge (V1, GRD-OT-08); el usuario ingresa el código nuevo en el mismo campo.
    codeRef.current = "";
    setCode("");
    inputRef.current?.focus();
  }

  async function resendCode(): Promise<void> {
    // V2r (POST /otp/resend): reemplaza el código sin reiniciar attempts ni presupuesto (GRD-OT-06). Como verify.js, no
    // consulta ni fija `busy`.
    const res = await postJson("/otp/resend");
    if (res.ok) {
      if (res.status === 202) setView("resend-ok");
      return;
    }
    if (res.error.kind === "network") setView("network");
    else if (res.error.status === 409) setView("resend-limit");
    else if (res.error.status === 404) setView("uniform");
  }

  async function sendRecoveryLink(): Promise<void> {
    // RV0 fuente BEARER (POST /manage/recovery-link, API-CNS-134): sin canal en el body (GRD-RV-17); respuesta uniforme.
    const res = await postJson("/manage/recovery-link");
    if (!res.ok && res.error.kind === "network") setRightsFeedback(CONNECT_FEEDBACK);
    else setRightsFeedback(res.ok && res.status === 202 ? "Si corresponde, enviamos un enlace a tu vía de contacto registrada." : "");
  }

  function openHumanCase(): void {
    // H1-10 (BORRADOR, copy pendiente de Carlos): sin llamada de red; el caso humano es "contacta al colegio".
    setRightsFeedback(HUMAN_CASE_MESSAGE);
  }

  const retry = () => {
    if (lastAction.current === "submit") void submitCode();
    else if (lastAction.current === "request") void requestNewCode();
  };
  const resendKind = view === "resend-ok" ? "ok" : view === "resend-limit" ? "limit" : null;

  return (
    <main className="lp-page-container lp-verify-page" aria-labelledby="verify-h1">
      {scope === "DECISION" ? <Stepper step={1} /> : null}
      <h1 id="verify-h1">Verifica el código</h1>
      <div id="verify-form" hidden={view === "locked" && isRights}>
        <p>Enviamos un código a la vía de contacto registrada para continuar. No lo compartas con nadie.</p>
        <div className="lp-form-group" id="verify-form-group">
          <label className="lp-label" htmlFor="code-input">Código de verificación</label>
          <input
            ref={inputRef}
            className="lp-input lp-verify-code-input"
            id="code-input"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="Ingresa el código"
            aria-describedby="code-help code-error"
            aria-invalid={view === "rejected" ? "true" : "false"}
            value={code}
            onChange={(e) => {
              codeRef.current = e.target.value;
              setCode(e.target.value);
            }}
          />
          <p className="lp-input-help" id="code-help">Ingresa el código de [N] caracteres que enviamos (P-01, valor pendiente de aprobación). El código deja de funcionar después de [tiempo pendiente de aprobación] (P-02).</p>
          <div className="lp-input-error-msg" id="code-error" role="alert" aria-live="assertive" hidden={view !== "rejected"}>
            <span aria-hidden="true">⚠ </span>El código ingresado no es correcto. Revísalo e inténtalo nuevamente.
          </div>
        </div>
        <div className="lp-verify-resend">
          <span>¿No recibiste el código?</span>{" "}
          <button type="button" className="lp-link lp-verify-tap-target" id="resend-btn" onClick={() => void resendCode()}>Reenviar código</button>
        </div>
        <div
          aria-live="polite"
          role="status"
          id="resend-feedback"
          hidden={resendKind === null}
          className={resendKind === "limit" ? "lp-alert-warning" : resendKind === "ok" ? "lp-alert-success" : undefined}
        >
          {resendKind === null ? null : (
            <>
              <span aria-hidden="true">{resendKind === "limit" ? "! " : "✓ "}</span>
              {resendKind === "limit" ? RESEND_LIMIT_MESSAGE : RESEND_OK_MESSAGE}
            </>
          )}
        </div>
        <p>Puedes solicitarlo un número limitado de veces (P-06, valor pendiente de aprobación).</p>
        <button
          type="button"
          className="lp-btn lp-btn-primary lp-cta lp-verify-cta lp-verify-actions"
          id="verify-btn"
          aria-disabled={busy ? "true" : "false"}
          aria-busy={busy ? "true" : "false"}
          onClick={() => void submitCode()}
        >
          {busy ? "Verificando…" : "Verificar"}
        </button>
      </div>
      <HelpLink />

      <div role="alert" aria-live="assertive" className="lp-alert-warning" id="state-expired" hidden={view !== "expired"}>
        <AlertHead icon="warning" title="Este código ya no es válido." />
        <p>Puede haber expirado o haberse usado antes. Solicita uno nuevo para continuar.</p>
        <button type="button" className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="request-new-code-btn-expired" onClick={() => void requestNewCode()}>Solicitar nuevo código</button>
      </div>

      {isRights ? (
        <div role="alert" aria-live="assertive" className="lp-alert-error" id="state-locked-rights" tabIndex={-1} hidden={view !== "locked"} ref={lockedRightsRef}>
          <AlertHead icon="error" title="Bloqueamos este código por varios intentos incorrectos." />
          <p>Nunca pierdes la posibilidad de retirar tu consentimiento: elige una opción.</p>
          <div className="lp-actions-stack">
            <button type="button" className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="send-recovery-link-btn" onClick={() => void sendRecoveryLink()}>Enviar enlace de recuperación</button>
            <button type="button" className="lp-btn lp-btn-outline lp-cta lp-verify-tap-target" id="open-human-case-btn" onClick={openHumanCase}>Contactar al colegio</button>
          </div>
          <div aria-live="polite" role="status" id="rights-locked-feedback" hidden={rightsFeedback === null}>{rightsFeedback}</div>
        </div>
      ) : (
        <div role="alert" aria-live="assertive" className="lp-alert-error" id="state-locked" hidden={view !== "locked"}>
          <AlertHead icon="error" title="Bloqueamos este código por varios intentos incorrectos." />
          <p>Por seguridad, no podemos usarlo de nuevo. Solicita un código nuevo para continuar.</p>
          <button type="button" className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="request-new-code-btn-locked" onClick={() => void requestNewCode()}>Solicitar nuevo código</button>
        </div>
      )}

      <NetworkAlert hidden={view !== "network"} buttonClassName="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" onRetry={retry} />

      <UniformAlert hidden={view !== "uniform"} title="No pudimos continuar con esta verificación.">
        <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
      </UniformAlert>
    </main>
  );
}
