// Gobierna: UX-CNS-004 (frames 33:45 confirmar-retiro, 33:54 comprobante, 33:64 retiro-cancelado, 33:73, 33:79),
// revocation.spec.yaml R2/R3/R8, F-PR6-25 (copy interino ERR-RV-21, no legal) + ADR-001 F1 (fase C). Equivale a
// revocation-page.ts + assets/revocation.js. INV-CM-08: la página no transiciona al cargar salvo R2 (idempotente), como el .js.
// Los marcadores [LEGAL DECISION] son texto VISIBLE y literal (no se redacta copy legal aquí).
import { useEffect, useRef, useState } from "react";
import { confirmRevocation, verifyRevocation, withdrawRevocation } from "../api/pages-c.ts";
import { AlertHead } from "../components/alert-head.tsx";
import { HELP_MAILTO, REVOCATION_APPLY_FAILED_COPY as APPLY_FAILED } from "../components/c/apply-failed-copy.ts";
import { useFocusWhen } from "../components/c/use-focus-when.ts";
import { HelpLink } from "../components/help-link.tsx";
import { usePageTitle } from "../components/use-page-title.ts";
import type { PageProps } from "../router.ts";

const RECEIPT_WATERMARK = "Comprobante de prueba · marca de agua IT0 · datos sintéticos";
const LEGAL_EFFECT = "[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]";
const LEGAL_SCOPE = "[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro (total, sin retiro parcial) e irreversibilidad desde esta pantalla (protocolo l.423)]";

type Phase = "form" | "applied" | "withdrawn";
type Banner = "none" | "network" | "uniform" | "applyFailed";
type Pending = "none" | "confirm" | "withdraw";

/** Equivale a renderRevocationUniformErrorPage() (INV-CM-05). */
function RevocationUniformError() {
  return (
    <main className="lp-page-container lp-revocation-page" aria-labelledby="revocation-h1">
      <h1 id="revocation-h1">Confirmar retiro</h1>
      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-uniform">
        <AlertHead icon="error" title="No pudimos continuar con este retiro." />
        <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
      </div>
      <HelpLink />
    </main>
  );
}

export function RevocationConfirmPage({ pageState }: PageProps) {
  usePageTitle("Confirmar retiro");
  const [phase, setPhase] = useState<Phase>("form");
  const [banner, setBanner] = useState<Banner>("none");
  const [pending, setPending] = useState<Pending>("none");
  const [receipt, setReceipt] = useState("");
  const busy = useRef(false);
  const lastAction = useRef<(() => void) | null>(null);
  const r2Sent = useRef(false);
  const appliedHeading = useRef<HTMLHeadingElement>(null);
  const withdrawnHeading = useRef<HTMLHeadingElement>(null);
  const applyFailedAlert = useRef<HTMLDivElement>(null);
  useFocusWhen(appliedHeading, phase === "applied");
  useFocusWhen(withdrawnHeading, phase === "withdrawn");
  useFocusWhen(applyFailedAlert, banner === "applyFailed");

  // R2 (verificación de la solicitud) al cargar: idempotente si ya VERIFIED. Solo un fallo de red muestra aviso (como el .js).
  useEffect(() => {
    if (pageState === "uniform-error" || r2Sent.current) return;
    r2Sent.current = true;
    void verifyRevocation().then((res) => {
      if (!res.ok && res.error.kind === "network") setBanner("network");
    });
  }, [pageState]);

  if (pageState === "uniform-error") return <RevocationUniformError />;

  function onConfirm(): void {
    if (busy.current) return;
    lastAction.current = onConfirm;
    busy.current = true;
    setBanner("none");
    setPending("confirm");
    void confirmRevocation().then((res) => {
      busy.current = false;
      setPending("none");
      if (res.ok) {
        const ref = res.data?.revocationRef;
        if (typeof ref === "string") {
          setReceipt(ref);
          setBanner("none");
          setPhase("applied");
        }
      } else if (res.error.kind === "network") setBanner("network");
      else if (res.error.status === 404) setBanner("uniform");
      else if (res.error.status === 503) setBanner("applyFailed"); // F-PR6-25: NO es un acuse
    });
  }

  function onWithdraw(): void {
    if (busy.current) return;
    lastAction.current = onWithdraw;
    busy.current = true;
    setBanner("none");
    setPending("withdraw");
    void withdrawRevocation().then((res) => {
      busy.current = false;
      setPending("none");
      if (!res.ok && res.error.kind === "network") setBanner("network");
      else if (!res.ok && res.error.status === 404) setBanner("uniform");
      else {
        setBanner("none");
        setPhase("withdrawn");
      }
    });
  }

  return (
    <main className="lp-page-container lp-revocation-page" aria-labelledby="revocation-h1">
      <h1 id="revocation-h1">Confirmar retiro</h1>

      <div id="revocation-form" hidden={phase !== "form"}>
        <section className="lp-card-default lp-revocation-section" aria-labelledby="confirm-h2">
          <h2 id="confirm-h2">Vas a retirar tu consentimiento</h2>
          <p>Vas a retirar tu consentimiento para el Estudio Beta de LectorPro.</p>
          <p className="lp-legal-note">{LEGAL_EFFECT}</p>
          <p className="lp-legal-note">{LEGAL_SCOPE}</p>
        </section>
        <div className="lp-actions-stack">
          <button
            type="button"
            className="lp-btn lp-btn-danger lp-cta lp-revocation-cta lp-verify-tap-target"
            id="confirm-revocation-btn"
            aria-disabled={pending === "confirm" ? "true" : "false"}
            aria-busy={pending === "confirm" ? "true" : "false"}
            onClick={onConfirm}
          >
            {pending === "confirm" ? "Confirmando…" : "Confirmar retiro total"}
          </button>
          <button
            type="button"
            className="lp-btn lp-btn-outline lp-cta lp-revocation-cta lp-verify-tap-target"
            id="withdraw-btn"
            aria-disabled={pending === "withdraw" ? "true" : "false"}
            aria-busy={pending === "withdraw" ? "true" : "false"}
            onClick={onWithdraw}
          >
            {pending === "withdraw" ? "Cancelando…" : "Cancelar solicitud de retiro"}
          </button>
        </div>
        <HelpLink />
      </div>

      <div role="status" aria-live="polite" id="state-applied" hidden={phase !== "applied"}>
        <span className="lp-hero-icon" aria-hidden="true">✓</span>
        <h1 id="applied-heading" tabIndex={-1} ref={appliedHeading}>Retiramos tu consentimiento</h1>
        <p className="lp-legal-note">{LEGAL_EFFECT}</p>
        <section className="lp-card lp-card-default" aria-labelledby="applied-receipt-h2">
          <h2 id="applied-receipt-h2">Comprobante</h2>
          <p className="lp-receipt-ref" id="applied-receipt">{receipt}</p>
          <div className="lp-badge-row"><span className="lp-badge lp-badge-warning">{RECEIPT_WATERMARK}</span></div>
        </section>
        <p>Nunca te mostraremos aquí el enlace de gestión: lo enviamos solo a la vía de contacto ya verificada.</p>
      </div>

      <div role="status" aria-live="polite" id="state-withdrawn" hidden={phase !== "withdrawn"}>
        <h1 id="withdrawn-heading" tabIndex={-1} ref={withdrawnHeading}>Cancelamos tu solicitud de retiro</h1>
        <p>Tu consentimiento sigue vigente. Puedes volver a solicitar el retiro cuando quieras.</p>
      </div>

      <div role="alert" aria-live="polite" className="lp-alert-warning" id="error-network" hidden={banner !== "network"}>
        <AlertHead icon="warning" title="No pudimos conectar." />
        <p>Revisa tu conexión e inténtalo nuevamente.</p>
        <button type="button" className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="retry-btn" onClick={() => lastAction.current?.()}>Reintentar</button>
      </div>

      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-uniform" hidden={banner !== "uniform"}>
        <AlertHead icon="error" title="No pudimos continuar con este retiro." />
        <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
      </div>

      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-apply-failed" tabIndex={-1} hidden={banner !== "applyFailed"} ref={applyFailedAlert}>
        <AlertHead icon="error" title={APPLY_FAILED.title} />
        <p>{APPLY_FAILED.body}</p>
        <p id="apply-failed-code">{APPLY_FAILED.codeLabel}: {APPLY_FAILED.code}</p>
        <a href="/manage" className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="new-code-link">{APPLY_FAILED.primaryLabel}</a>
        <p><a href={HELP_MAILTO} className="lp-link" id="apply-failed-help">{APPLY_FAILED.helpLabel}</a></p>
      </div>
    </main>
  );
}
