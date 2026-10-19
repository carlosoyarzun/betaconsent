// Gobierna: UX-CNS-001 (/welcome) + ADR-001 F1. Equivale a welcome-page.ts + assets/welcome.js (mismo copy, clases, ARIA).
// INV-CM-08: no transiciona nada; solo abre la invitación (POST /invitation/open) y pide el OTP (POST /otp/request).
// GRD-OT-02: el código va solo al canal ligado a la invitación (no hay elección de canal).
import { useRef, useState } from "react";
import { postJson } from "../api/client.ts";
import { AlertHead } from "../components/alert-head.tsx";
import { HelpLink } from "../components/help-link.tsx";
import { usePageTitle } from "../components/use-page-title.ts";
import { navigation, type PageProps } from "../router.ts";

const CONTINUE_LABEL = "Continuar";
const BUSY_LABEL = "Abriendo invitación…";

type Banner = "none" | "uniform" | "network";

function UniformErrorBody() {
  return (
    <>
      <AlertHead icon="error" title="No pudimos abrir esta invitación." />
      <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
    </>
  );
}

/** Estado de error uniforme (INV-CM-05): sin sesión/handle elegible. Equivale a renderWelcomeUniformErrorPage(). */
function WelcomeUniformError() {
  return (
    <main className="lp-page-container lp-welcome-page" aria-labelledby="welcome-h1">
      <h1 id="welcome-h1">Bienvenida a la invitación</h1>
      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-uniform">
        <UniformErrorBody />
      </div>
      <HelpLink />
    </main>
  );
}

export function WelcomePage({ pageState }: PageProps) {
  usePageTitle("Bienvenida a la invitación");
  const [busy, setBusy] = useState(false);
  const [banner, setBanner] = useState<Banner>("none");
  const inFlight = useRef(false);

  if (pageState === "uniform-error") return <WelcomeUniformError />;

  async function startFlow(): Promise<void> {
    if (inFlight.current) return;
    inFlight.current = true;
    setBanner("none");
    setBusy(true);
    try {
      const opened = await postJson("/invitation/open");
      if (!opened.ok) {
        if (opened.error.kind === "network") setBanner("network");
        else setBanner("uniform");
        return;
      }
      const otp = await postJson("/otp/request");
      if (!otp.ok) {
        setBanner(otp.error.kind === "network" ? "network" : "uniform");
        return;
      }
      // UX-CNS-002: /verify exige la sesión con verificationRef, que este /otp/request ya fijó.
      setBusy(false);
      navigation.assign("/verify");
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  const ariaBusy = busy ? "true" : "false";
  const label = busy ? BUSY_LABEL : CONTINUE_LABEL;
  const onContinue = () => void startFlow();

  return (
    <main className="lp-page-container lp-welcome-page" aria-labelledby="welcome-h1">
      <h1 id="welcome-h1">Bienvenida a la invitación</h1>
      <div className="lp-welcome-grid">
        <div>
          <section className="lp-card lp-card-default" aria-label="Detalle de la invitación">
            <p>Colegio Ejemplo te invita a participar en el Estudio Beta de LectorPro.</p>
            <p>LectorPro es una aplicación que apoya la lectura del estudiante. El colegio invita a las familias a sumarse a un estudio piloto.</p>
          </section>
          <section className="lp-card lp-card-default lp-decision-section" aria-labelledby="how-h2">
            <h2 id="how-h2">Cómo funciona</h2>
            <ol className="lp-howto">
              <li><strong>Verifica tu identidad</strong>Te enviaremos un código de verificación a la vía de contacto registrada.</li>
              <li><strong>Revisa la información</strong>Leerás en qué consiste el estudio y qué datos se tratarían.</li>
              <li><strong>Decide si participar</strong>La decisión es tuya. Podrás aceptar o no aceptar cada finalidad.</li>
            </ol>
          </section>
          <div className="lp-welcome-action-mobile">
            <button
              type="button"
              className="lp-btn lp-btn-primary lp-cta lp-welcome-cta lp-welcome-action"
              id="continue-btn"
              data-continue
              aria-disabled={busy ? "true" : "false"}
              aria-busy={ariaBusy}
              onClick={onContinue}
            >
              {label}
            </button>
          </div>
        </div>
        <aside className="lp-card lp-card-default lp-welcome-aside" aria-labelledby="ready-h2">
          <h2 id="ready-h2">¿Listo para comenzar?</h2>
          <p>A continuación te enviaremos un código de verificación. Después de confirmarlo, podrás revisar la información y decidir si participar.</p>
          <button
            type="button"
            className="lp-btn lp-btn-primary lp-cta lp-welcome-cta"
            id="continue-btn-aside"
            data-continue
            aria-disabled={busy ? "true" : "false"}
            aria-busy={ariaBusy}
            onClick={onContinue}
          >
            {label}
          </button>
        </aside>
      </div>
      <HelpLink />
      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-uniform" hidden={banner !== "uniform"}>
        <UniformErrorBody />
      </div>
      <div role="alert" aria-live="polite" className="lp-alert-warning" id="error-network" hidden={banner !== "network"}>
        <AlertHead icon="warning" title="No pudimos conectar." />
        <p>Revisa tu conexión e inténtalo nuevamente.</p>
        <button type="button" className="lp-btn lp-btn-primary lp-cta lp-welcome-cta" onClick={onContinue}>Reintentar</button>
      </div>
    </main>
  );
}
