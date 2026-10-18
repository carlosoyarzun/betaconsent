// Gobierna: UX-CNS-004 §3 (CA-116) + INV-OT-06 + ADR-001 F1 (fase C). Equivale a renderVerifyPage("MANAGE"|"REVOCATION") de
// verify-page.ts + assets/verify.js con data-verify-scope MANAGE/REVOCATION (sin stepper; bloqueo = RECOVERY/caso humano,
// NUNCA "solicitar nuevo código" en el bloqueo ni "denegado"). Copy literal, incluidos los placeholders P-01/P-02/P-06
// (sin valor aprobado en SEC-CNS-006). El /verify de la decisión (scope DECISION) es otra página (fase B): este
// componente no la cubre.
import { useRef, useState } from "react";
import { openHumanCase, requestOtp, resendOtp, sendRecoveryLink, submitOtp } from "../../api/pages-c.ts";
import { navigation, type PageProps } from "../../router.ts";
import { AlertHead } from "../alert-head.tsx";
import { HelpLink } from "../help-link.tsx";
import { usePageTitle } from "../use-page-title.ts";
import { useFocusWhen } from "./use-focus-when.ts";

export type RightsVerifyScope = "MANAGE" | "REVOCATION";

/** Equivale a NEXT_ROUTE_BY_SCOPE de verify-page.ts (data-verify-next). */
const NEXT_ROUTE: Readonly<Record<RightsVerifyScope, string>> = {
  MANAGE: "/manage",
  REVOCATION: "/manage/revocation/confirm",
};

const VERIFY_LABEL = "Verificar";
const BUSY_LABEL = "Verificando…";

type View = "default" | "rejected" | "expired" | "locked" | "network" | "uniform" | "resendOk" | "resendLimit";

const LOCKED_CODES = new Set(["OTP_LOCKED", "OTP_BUDGET_EXHAUSTED_DECISION", "OTP_BUDGET_EXHAUSTED_RIGHTS"]);

function UniformErrorBody() {
  return (
    <>
      <AlertHead icon="error" title="No pudimos continuar con esta verificación." />
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </>
  );
}

/** Equivale a renderVerifyUniformErrorPage() (INV-CM-05). */
function VerifyUniformError() {
  return (
    <main className="lp-page-container lp-verify-page" aria-labelledby="verify-h1">
      <h1 id="verify-h1">Verifica el código</h1>
      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-uniform">
        <UniformErrorBody />
      </div>
      <HelpLink />
    </main>
  );
}

export function RightsVerify({ scope, pageState }: PageProps & { readonly scope: RightsVerifyScope }) {
  usePageTitle("Verifica el código");
  const [view, setView] = useState<View>("default");
  const [busy, setBusyState] = useState(false);
  const [code, setCode] = useState("");
  const [rightsFeedback, setRightsFeedback] = useState<string | null>(null);
  const busyRef = useRef(false);
  const lastAction = useRef<(() => void) | null>(null);
  const codeRef = useRef<HTMLInputElement>(null);
  const lockedRightsRef = useRef<HTMLDivElement>(null);
  useFocusWhen(lockedRightsRef, view === "locked");

  if (pageState === "uniform-error") return <VerifyUniformError />;

  function setBusy(value: boolean): void {
    busyRef.current = value;
    setBusyState(value);
  }

  function submitCode(): void {
    if (busyRef.current) return;
    lastAction.current = submitCode;
    setView("default");
    setBusy(true);
    void submitOtp(code).then((res) => {
      setBusy(false);
      if (!res.ok && res.error.kind === "network") {
        setView("network");
      } else if (res.ok && res.status === 200) {
        navigation.assign(NEXT_ROUTE[scope]);
      } else if (!res.ok && res.error.status === 404) {
        setView("uniform");
      } else if (!res.ok && typeof res.error.code === "string") {
        // V2/V4/V5 (handoff §6): OTP_CODE_REJECTED por defecto, sin revelar intentos restantes (ERR-OT-02).
        if (LOCKED_CODES.has(res.error.code)) setView("locked");
        else if (res.error.code === "OTP_EXPIRED_OR_CONSUMED") setView("expired");
        else setView("rejected");
      }
    });
  }

  function requestNewCode(): void {
    if (busyRef.current) return;
    lastAction.current = requestNewCode;
    setView("default");
    setBusy(true);
    void requestOtp().then((res) => {
      setBusy(false);
      if (!res.ok && res.error.kind === "network") {
        setView("network");
      } else if (!res.ok && res.error.status === 404) {
        setView("uniform");
      } else {
        // 202 UniformAccepted: nuevo challenge (V1, GRD-OT-08); el usuario ingresa el código nuevo en el mismo campo.
        setCode("");
        codeRef.current?.focus();
      }
    });
  }

  function resendCode(): void {
    if (busyRef.current) return;
    void resendOtp().then((res) => {
      if (res.ok && res.status === 202) setView("resendOk");
      else if (!res.ok && res.error.kind === "network") setView("network");
      else if (!res.ok && res.error.status === 409) setView("resendLimit");
      else if (!res.ok && res.error.status === 404) setView("uniform");
    });
  }

  function onSendRecoveryLink(): void {
    void sendRecoveryLink().then((res) => {
      if (!res.ok && res.error.kind === "network") setRightsFeedback("No pudimos conectar. Inténtalo nuevamente.");
      else setRightsFeedback(res.ok && res.status === 202 ? "Si corresponde, enviamos un enlace a tu vía de contacto registrada." : "");
    });
  }

  function onOpenHumanCase(): void {
    void openHumanCase().then((res) => {
      if (!res.ok && res.error.kind === "network") setRightsFeedback("No pudimos conectar. Inténtalo nuevamente.");
      else setRightsFeedback(res.ok && res.status === 200 ? "Abrimos un caso; te contactaremos." : "");
    });
  }

  const feedbackKind = view === "resendOk" ? "ok" : view === "resendLimit" ? "limit" : null;
  return (
    <main className="lp-page-container lp-verify-page" aria-labelledby="verify-h1">
      <h1 id="verify-h1">Verifica el código</h1>
      <div id="verify-form" hidden={view === "locked"}>
        <p>Enviamos un código a la vía de contacto registrada para continuar. No lo compartas con nadie.</p>
        <div className="lp-form-group" id="verify-form-group">
          <label className="lp-label" htmlFor="code-input">Código de verificación</label>
          <input
            className="lp-input lp-verify-code-input"
            id="code-input"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="Ingresa el código"
            aria-describedby="code-help code-error"
            aria-invalid={view === "rejected" ? "true" : "false"}
            ref={codeRef}
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <p className="lp-input-help" id="code-help">Ingresa el código de [N] caracteres que enviamos (P-01, valor pendiente de aprobación). El código deja de funcionar después de [tiempo pendiente de aprobación] (P-02).</p>
          <div className="lp-input-error-msg" id="code-error" role="alert" aria-live="assertive" hidden={view !== "rejected"}>
            <span aria-hidden="true">⚠ </span>El código ingresado no es correcto. Revísalo e inténtalo nuevamente.
          </div>
        </div>
        <div className="lp-verify-resend">
          <span>¿No recibiste el código?</span>{" "}
          <button type="button" className="lp-link lp-verify-tap-target" id="resend-btn" onClick={resendCode}>Reenviar código</button>
        </div>
        <div
          aria-live="polite"
          role="status"
          id="resend-feedback"
          className={feedbackKind === "limit" ? "lp-alert-warning" : feedbackKind === "ok" ? "lp-alert-success" : undefined}
          hidden={feedbackKind === null}
        >
          {feedbackKind !== null && (
            <>
              <span aria-hidden="true">{feedbackKind === "limit" ? "! " : "✓ "}</span>
              {feedbackKind === "limit" ? "Alcanzaste el límite de reenvíos disponible por ahora." : "Te enviamos un nuevo código."}
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
          onClick={submitCode}
        >
          {busy ? BUSY_LABEL : VERIFY_LABEL}
        </button>
      </div>
      <HelpLink />

      <div role="alert" aria-live="assertive" className="lp-alert-warning" id="state-expired" hidden={view !== "expired"}>
        <AlertHead icon="warning" title="Este código ya no es válido." />
        <p>Puede haber expirado o haberse usado antes. Solicita uno nuevo para continuar.</p>
        <button type="button" className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="request-new-code-btn-expired" onClick={requestNewCode}>Solicitar nuevo código</button>
      </div>

      <div role="alert" aria-live="assertive" className="lp-alert-error" id="state-locked-rights" tabIndex={-1} hidden={view !== "locked"} ref={lockedRightsRef}>
        <AlertHead icon="error" title="Bloqueamos este código por varios intentos incorrectos." />
        <p>Nunca pierdes la posibilidad de retirar tu consentimiento: elige una opción.</p>
        <div className="lp-actions-stack">
          <button type="button" className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="send-recovery-link-btn" onClick={onSendRecoveryLink}>Enviar enlace de recuperación</button>
          <button type="button" className="lp-btn lp-btn-outline lp-cta lp-verify-tap-target" id="open-human-case-btn" onClick={onOpenHumanCase}>Abrir caso con soporte humano</button>
        </div>
        <div aria-live="polite" role="status" id="rights-locked-feedback" hidden={rightsFeedback === null}>{rightsFeedback}</div>
      </div>

      <div role="alert" aria-live="polite" className="lp-alert-warning" id="error-network" hidden={view !== "network"}>
        <AlertHead icon="warning" title="No pudimos conectar." />
        <p>Revisa tu conexión e inténtalo nuevamente.</p>
        <button type="button" className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="retry-btn" onClick={() => lastAction.current?.()}>Reintentar</button>
      </div>

      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-uniform" hidden={view !== "uniform"}>
        <UniformErrorBody />
      </div>
    </main>
  );
}
