// Gobierna: UX-CNS-004 (handoff revocation-handoff.md §2/§3; frames 33:2 entrada, 33:21 estado, 73:2 ya retirado, 59:3 error) +
// ADR-001 F1 fase B. Equivale a manage-page.ts + assets/manage.js. La variante (entrada / estado / ya retirado) que el SSR elegía
// en el servidor llega por GET /manage/page-state (API-CNS-195). INV-CM-08: la página no transiciona al cargar.
// Entrada: «Verificar mi identidad» -> POST /otp/request (scope MANAGE) -> /manage/verify.
// Estado: «Retirar mi consentimiento» -> POST /manage/revocation (R1) -> POST /otp/request (scope REVOCATION) -> /manage/revocation/verify.
// Copy [UX — borrador]; los marcadores [LEGAL DECISION] son TEXTO VISIBLE literal (no se redacta copy legal).
import { useEffect, useRef, useState } from "react";
import { postJson } from "../api/client.ts";
import { loadManagePageState, type ManageVariant, type PageStateResult, type ManagePageState } from "../api/pages-b.ts";
import { HelpLink } from "../components/help-link.tsx";
import { usePageTitle } from "../components/use-page-title.ts";
import { NetworkAlert, UniformAlert } from "../components/b/alerts.tsx";
import { navigation, type PageProps } from "../router.ts";

const TAP_CTA = "lp-btn lp-btn-primary lp-cta lp-verify-tap-target";
type Loaded = { readonly kind: "loading" } | PageStateResult<ManagePageState>;
type Banner = "none" | "uniform" | "network";

/** Estado de error uniforme (59:3; equivale a renderManageUniformErrorPage()): copy propio, enlace con estilo de botón a soporte. */
function ManageUniformError() {
  return (
    <main className="lp-page-container lp-manage-page" aria-labelledby="manage-h1">
      <h1 id="manage-h1">Gestiona tu consentimiento</h1>
      <UniformAlert title="Este enlace ya no está disponible.">
        <p>Puede que ya no sea válido. Esto no significa que se haya perdido tu posibilidad de gestionar tu consentimiento.</p>
      </UniformAlert>
      <div className="lp-actions-stack">
        <a href="mailto:ayuda@example.invalid" className={TAP_CTA} id="contact-support-btn">Contactar a soporte</a>
      </div>
      <HelpLink />
    </main>
  );
}

/** 73:2 manage/mobile/ya-retirado (equivale a renderManageRevokedPage()): neutro, sin CTA de retirar. */
function ManageRevoked() {
  return (
    <main className="lp-page-container lp-manage-page" aria-labelledby="manage-h1">
      <h1 id="manage-h1">Tu consentimiento</h1>
      <section className="lp-card-default lp-manage-status" role="status" aria-live="polite" id="manage-revoked">
        <p><strong>Tu consentimiento ya fue retirado.</strong></p>
        <p>No necesitas hacer nada más. Ya no hay una acción de retiro pendiente en este enlace.</p>
        <p className="lp-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]</p>
      </section>
      <div className="lp-actions-stack">
        <a href="mailto:ayuda@example.invalid" className={TAP_CTA} id="contact-support-btn">Contactar a soporte</a>
      </div>
      <HelpLink />
    </main>
  );
}

const STATUS_PURPOSES = ["Participar en el Estudio Beta", "Grabación de audio", "Análisis automatizado", "Revisión humana"] as const;

function ManageActive({ variant }: { readonly variant: "entry" | "status" }) {
  const [busy, setBusy] = useState(false);
  const [banner, setBanner] = useState<Banner>("none");
  const busyRef = useRef(false);

  function changeBusy(next: boolean): void {
    busyRef.current = next;
    setBusy(next);
  }

  async function startVerify(): Promise<void> {
    if (busyRef.current) return;
    changeBusy(true);
    setBanner("none");
    const res = await postJson("/otp/request");
    changeBusy(false);
    if (!res.ok) {
      setBanner(res.error.kind === "network" ? "network" : "uniform");
      return;
    }
    navigation.assign("/manage/verify");
  }

  async function startRevocation(): Promise<void> {
    if (busyRef.current) return;
    changeBusy(true);
    setBanner("none");
    const revocation = await postJson("/manage/revocation");
    if (!revocation.ok && revocation.error.kind === "network") {
      changeBusy(false);
      setBanner("network");
      return;
    }
    const otp = revocation.ok ? await postJson("/otp/request") : null;
    changeBusy(false);
    if (otp === null || (!otp.ok && otp.error.kind === "http")) {
      setBanner("uniform");
      return;
    }
    if (!otp.ok) {
      setBanner("network");
      return;
    }
    navigation.assign("/manage/revocation/verify");
  }

  const entry = variant === "entry";
  const retry = () => void (entry ? startVerify() : startRevocation());
  const ariaBusy = busy ? "true" : "false";

  return (
    <main className="lp-page-container lp-manage-page" aria-labelledby="manage-h1">
      <h1 id="manage-h1">Tu consentimiento</h1>
      {entry ? (
        <section className="lp-card lp-card-default">
          <p>Antes de mostrarte cualquier información, necesitamos verificar tu identidad con un código.</p>
          <button type="button" className={TAP_CTA} id="start-verify-btn" aria-disabled={ariaBusy} aria-busy={ariaBusy} onClick={() => void startVerify()}>
            {busy ? "Enviando código…" : "Verificar mi identidad"}
          </button>
        </section>
      ) : (
        <>
          <section className="lp-card-default lp-manage-status" role="status" aria-live="polite">
            <p><span className="lp-badge lp-badge-success">Consentimiento otorgado</span></p>
            <p>Colegio Ejemplo — Estudio Beta de LectorPro.</p>
            <p>Finalidades otorgadas:</p>
            <ul className="lp-purpose-list">
              {STATUS_PURPOSES.map((title) => <li key={title}><span aria-hidden="true">✓ </span>{title}</li>)}
            </ul>
            <p>Puedes retirar tu consentimiento en cualquier momento.</p>
            <p className="lp-legal-note">[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro (total, sin retiro parcial), protocolo l.423]</p>
          </section>
          <div className="lp-actions-stack">
            <button type="button" className="lp-btn lp-btn-danger lp-cta lp-revocation-cta lp-verify-tap-target" id="start-revocation-btn" aria-disabled={ariaBusy} aria-busy={ariaBusy} onClick={() => void startRevocation()}>
              {busy ? "Solicitando retiro…" : "Retirar mi consentimiento"}
            </button>
          </div>
        </>
      )}
      <HelpLink />

      <NetworkAlert hidden={banner !== "network"} buttonClassName={TAP_CTA} onRetry={retry} />

      <UniformAlert hidden={banner !== "uniform"} title="No pudimos continuar.">
        <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
      </UniformAlert>
    </main>
  );
}

export function ManagePage({ pageState }: PageProps) {
  usePageTitle("Tu consentimiento");
  const [loaded, setLoaded] = useState<Loaded>({ kind: "loading" });
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    if (pageState === "uniform-error") return;
    let cancelled = false;
    void loadManagePageState().then((result) => {
      if (!cancelled) setLoaded(result);
    });
    return () => {
      cancelled = true;
    };
  }, [pageState, reloadTick]);

  if (pageState === "uniform-error" || loaded.kind === "uniform") return <ManageUniformError />;
  if (loaded.kind === "loading") {
    return (
      <main className="lp-page-container lp-manage-page" aria-labelledby="manage-h1" aria-busy="true">
        <h1 id="manage-h1">Tu consentimiento</h1>
      </main>
    );
  }
  if (loaded.kind === "unavailable") {
    return (
      <main className="lp-page-container lp-manage-page" aria-labelledby="manage-h1">
        <h1 id="manage-h1">Tu consentimiento</h1>
        <NetworkAlert hidden={false} buttonClassName={TAP_CTA} onRetry={() => { setLoaded({ kind: "loading" }); setReloadTick((n) => n + 1); }} />
        <HelpLink />
      </main>
    );
  }
  const variant: ManageVariant = loaded.data.variant;
  return variant === "revoked" ? <ManageRevoked /> : <ManageActive variant={variant} />;
}
