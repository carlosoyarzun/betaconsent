// Gobierna: UX-CNS-004 (frames 33:87 confirmar, 33:96 en-curso R11 NOOP, 33:106 error uniforme ERR-RV-05), API-CNS-135
// (POST /recovery/revoke), F-PR6-25 (copy interino ERR-RV-22, no legal), UX-CNS-015 F1/F2 (foco WCAG 2.4.3/4.1.3, PR #110)
// + ADR-001 F1 (fase C). Equivale a recovery-page.ts + assets/recovery.js. La cabecera COOP same-origin la pone el servidor.
// Un solo POST decide qué bloque se muestra: lo decide la respuesta, nunca esta página. Marcadores [LEGAL DECISION] literales.
import { useRef, useState } from "react";
import { recoveryRevoke } from "../api/pages-c.ts";
import { AlertHead } from "../components/alert-head.tsx";
import { HELP_MAILTO, RECOVERY_APPLY_FAILED_COPY as APPLY_FAILED } from "../components/c/apply-failed-copy.ts";
import { useFocusWhen } from "../components/c/use-focus-when.ts";
import { usePageTitle } from "../components/use-page-title.ts";
import type { PageProps } from "../router.ts";

const LEGAL_EFFECT = "[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]";
const LEGAL_SCOPE = "[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro (total, sin retiro parcial) e irreversibilidad desde esta pantalla (protocolo l.423)]";

type Phase = "form" | "applied" | "inProgress";
type Banner = "none" | "network" | "uniform" | "applyFailed";

/** Equivale a renderRecoveryUniformErrorPage() (33:106, INV-CM-05). */
function RecoveryUniformError() {
  return (
    <main className="lp-page-container lp-revocation-page" aria-labelledby="recovery-h1">
      <h1 id="recovery-h1">Confirmar retiro</h1>
      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-uniform">
        <p>No pudimos continuar con este retiro.</p>
        <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
      </div>
      <p>¿Tampoco tienes tu enlace de gestión? Contáctanos y te ayudamos a recuperar el acceso sin revelar datos de otras personas.</p>
      <p><a href="mailto:ayuda@example.invalid" className="lp-link">¿Necesitas ayuda? Escríbenos a ayuda@example.invalid</a></p>
    </main>
  );
}

export function RecoveryConfirmPage({ pageState }: PageProps) {
  usePageTitle("Recuperar acceso");
  const [phase, setPhase] = useState<Phase>("form");
  const [banner, setBanner] = useState<Banner>("none");
  const [busy, setBusyState] = useState(false);
  const [receipt, setReceipt] = useState("");
  const busyRef = useRef(false);
  const confirmBtn = useRef<HTMLButtonElement>(null);
  const appliedHeading = useRef<HTMLHeadingElement>(null);
  const inProgressHeading = useRef<HTMLHeadingElement>(null);
  const applyFailedAlert = useRef<HTMLDivElement>(null);
  useFocusWhen(appliedHeading, phase === "applied");
  useFocusWhen(inProgressHeading, phase === "inProgress");
  useFocusWhen(applyFailedAlert, banner === "applyFailed");

  if (pageState === "uniform-error") return <RecoveryUniformError />;

  function confirmRecovery(): void {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusyState(true);
    // UX-CNS-015 F1/F2 (WCAG 2.4.3 / 4.1.3): "Volver a intentar" vive dentro del aviso que se oculta; el foco pasa antes
    // al botón principal (visible, con aria-busy y la etiqueta "Confirmando…") para que no caiga a <body>.
    confirmBtn.current?.focus();
    setBanner("none");
    void recoveryRevoke().then((res) => {
      busyRef.current = false;
      setBusyState(false);
      if (!res.ok && res.error.kind === "network") {
        setBanner("network");
      } else if (!res.ok && res.error.status === 503) {
        setBanner("applyFailed"); // token NO consumido (F-PR6-48): el enlace sigue válido, no es el error uniforme
      } else if ((!res.ok && res.error.status === 404) || (res.ok && res.status === 202)) {
        setBanner("uniform");
      } else if (res.ok && res.data?.state === "CONFIRMED" && typeof res.data.revocationRef === "string") {
        setReceipt(`Comprobante: ${res.data.revocationRef}`);
        setBanner("none");
        setPhase("applied");
      } else if (res.ok && res.data?.result === "IN_PROGRESS") {
        setBanner("none");
        setPhase("inProgress");
      } else {
        setBanner("uniform");
      }
    });
  }

  const ariaBusy = busy ? "true" : "false";
  return (
    <main className="lp-page-container lp-revocation-page" aria-labelledby="recovery-h1">
      <h1 id="recovery-h1">Confirmar retiro</h1>

      <div id="recovery-form" hidden={phase !== "form"}>
        <section className="lp-card-default lp-revocation-section" aria-labelledby="recovery-confirm-h2">
          <h2 id="recovery-confirm-h2">Vas a retirar tu consentimiento</h2>
          <p>Vas a retirar tu consentimiento para el Estudio Beta de LectorPro.</p>
          <p className="lp-revocation-legal-note">{LEGAL_EFFECT}</p>
          <p className="lp-revocation-legal-note">{LEGAL_SCOPE}</p>
        </section>
        <button
          type="button"
          className="lp-btn lp-btn-danger lp-cta lp-revocation-cta lp-verify-tap-target"
          id="confirm-recovery-btn"
          aria-disabled={ariaBusy}
          aria-busy={ariaBusy}
          ref={confirmBtn}
          onClick={confirmRecovery}
        >
          {busy ? "Confirmando…" : "Confirmar retiro total"}
        </button>
        <p><a href="mailto:ayuda@example.invalid" className="lp-link">¿Necesitas ayuda? Escríbenos a ayuda@example.invalid</a></p>
      </div>

      <div role="status" aria-live="polite" id="state-applied" hidden={phase !== "applied"}>
        <h2 id="applied-heading" tabIndex={-1} ref={appliedHeading}>Retiramos tu consentimiento</h2>
        <p id="applied-receipt">{receipt}</p>
        <p className="lp-revocation-legal-note">{LEGAL_EFFECT}</p>
        <p>Nunca te mostraremos aquí el enlace de gestión: lo enviamos solo a la vía de contacto ya verificada.</p>
      </div>

      <div role="status" aria-live="polite" id="state-in-progress" hidden={phase !== "inProgress"}>
        <h2 id="in-progress-heading" tabIndex={-1} ref={inProgressHeading}>Este retiro ya está en curso</h2>
        <p>Ya confirmamos este retiro antes: no necesitas hacer nada más.</p>
      </div>

      <div role="alert" aria-live="polite" id="error-network" hidden={banner !== "network"}>
        <p>No pudimos conectar.</p>
        <p>Revisa tu conexión e inténtalo nuevamente.</p>
        <button type="button" className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target" id="retry-btn" onClick={confirmRecovery}>Reintentar</button>
      </div>

      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-uniform" hidden={banner !== "uniform"}>
        <p>No pudimos continuar con este retiro.</p>
        <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
      </div>

      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-apply-failed" tabIndex={-1} hidden={banner !== "applyFailed"} ref={applyFailedAlert}>
        <AlertHead icon="error" title={APPLY_FAILED.title} />
        <p>{APPLY_FAILED.body}</p>
        <p id="apply-failed-code">{APPLY_FAILED.codeLabel}: {APPLY_FAILED.code}</p>
        <button
          type="button"
          className="lp-btn lp-btn-primary lp-cta lp-verify-tap-target"
          id="retry-apply-btn"
          aria-disabled={ariaBusy}
          aria-busy={ariaBusy}
          onClick={confirmRecovery}
        >
          {APPLY_FAILED.primaryLabel}
        </button>
        <p><a href={HELP_MAILTO} className="lp-link" id="apply-failed-help">{APPLY_FAILED.helpLabel}</a></p>
      </div>
    </main>
  );
}
