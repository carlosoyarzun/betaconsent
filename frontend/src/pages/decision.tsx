// Gobierna: UX-CNS-003 (handoff /decision; flujo del invitado v2, D-02/D-06) + ADR-001 F1 fase B. Equivale a decision-page.ts +
// assets/decision.js. Los datos que el SSR interpolaba (relaciones, versión servida del texto, etiqueta del titular) llegan por
// GET /decision/page-state (API-CNS-194); el resto del copy es el literal del SSR.
// INV-CM-08: la página no transiciona al cargar; solo POST /decision/steps (C2) + /decision/submit (C3/C5) + /decision/subject-mismatch (I9).
// decisionMakerRef y consentId los deriva el servidor (D5): este componente nunca los envía.
// GRD-CD-03 / LD-06 / DEC-BR-003: los marcadores [LEGAL DECISION] son TEXTO VISIBLE literal; no se redacta copy legal.
// Nada preseleccionado (F-STITCH-03); «Acepto» y «No acepto» con el mismo peso visual (F-STITCH-19).
import { useEffect, useRef, useState } from "react";
import { postJson, type ApiResult } from "../api/client.ts";
import { loadDecisionPageState, type DecisionPageState, type PageStateResult, type ServedVersionView } from "../api/pages-b.ts";
import { AlertHead } from "../components/alert-head.tsx";
import { HelpLink } from "../components/help-link.tsx";
import { Stepper } from "../components/stepper.tsx";
import { usePageTitle } from "../components/use-page-title.ts";
import { NetworkAlert, UniformAlert } from "../components/b/alerts.tsx";
import { useFocusWhen } from "../components/b/use-focus-when.ts";
import type { PageProps } from "../router.ts";

/** Equivale a PURPOSES de guest-purposes.ts (UX-CNS-003; 4 finalidades de specs/adapters/lectorpro-beta.spec.yaml). [UX — borrador]. */
const PURPOSES: readonly { readonly purpose: string; readonly title: string; readonly description: string }[] = [
  { purpose: "STUDY_PARTICIPATION", title: "Participar en el Estudio Beta", description: "El estudiante participaría en sesiones de lectura del Estudio Beta de LectorPro." },
  { purpose: "AUDIO_RECORDING", title: "Grabación de audio", description: "Se grabaría el audio de las sesiones de lectura para poder analizarlas." },
  { purpose: "AUTOMATED_ANALYSIS", title: "Análisis automatizado", description: "El audio se analizaría con un motor automatizado de lectura." },
  { purpose: "HUMAN_REVIEW", title: "Revisión humana", description: "Una persona revisaría una muestra de los resultados para validar el análisis automatizado." },
];

type Subject = "yes" | "no";
type Choice = "GRANT" | "DECLINE";
type Terminal = "granted" | "declined" | "mismatch";
type Banner = "none" | "validation" | "conflict" | "network" | "uniform";
type Loaded = { readonly kind: "loading" } | PageStateResult<DecisionPageState>;

const VALIDATION_DETAIL = "Revisa las secciones marcadas y vuelve a intentarlo.";
const HELPER_DEFAULT = "Completa todas las secciones para continuar.";

interface SummaryItem {
  readonly targetId: string;
  readonly text: string;
}

/** Estado de error uniforme (equivale a renderDecisionUniformErrorPage()). */
function DecisionUniformError() {
  return (
    <main className="lp-page-container lp-decision-page" aria-labelledby="decision-h1">
      <h1 id="decision-h1">Revisa y decide</h1>
      <UniformAlert title="No pudimos continuar con esta decisión.">
        <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
      </UniformAlert>
      <HelpLink />
    </main>
  );
}

function RegisteredState({ kind, receipt, headingRef, hidden }: { readonly kind: "granted" | "declined"; readonly receipt: string; readonly headingRef: React.RefObject<HTMLHeadingElement | null>; readonly hidden: boolean }) {
  const granted = kind === "granted";
  return (
    <div role="status" aria-live="polite" id={`state-${kind}`} hidden={hidden}>
      <Stepper step={3} />
      <span className="lp-hero-icon" aria-hidden="true">{granted ? "✓" : "•"}</span>
      <h1 id={`${kind}-heading`} tabIndex={-1} ref={headingRef}>{granted ? "Listo, registramos tu decisión" : "Registramos tu decisión"}</h1>
      {granted ? (
        <p>Colegio Ejemplo — Estudio Beta de LectorPro.</p>
      ) : (
        <>
          <p>El estudiante no participará en el Estudio Beta.</p>
          <p className="lp-legal-note">[LEGAL DECISION — efecto de no aceptar una finalidad obligatoria (Q-13): copy pendiente de aprobación de Carlos]</p>
        </>
      )}
      <section className="lp-card lp-card-default" aria-labelledby={`${kind}-receipt-h2`}>
        <h2 id={`${kind}-receipt-h2`}>Comprobante</h2>
        <p className="lp-receipt-ref" id={`${kind}-receipt`}>{receipt}</p>
        <div className="lp-badge-row">
          <span className="lp-badge lp-badge-success">Registrado</span>
          <span className="lp-badge lp-badge-warning">Marca de agua IT0 · comprobante de prueba</span>
        </div>
      </section>
      <section className="lp-card lp-card-default lp-decision-section" aria-labelledby={`${kind}-next-h2`}>
        <h2 id={`${kind}-next-h2`}>Qué pasa ahora</h2>
        <ul className="lp-next-steps">
          <li><strong>Comprobante</strong>Te enviaremos el comprobante de tu decisión a la vía de contacto ya verificada.</li>
          {granted ? <li><strong>Gestionar o retirar tu decisión</strong>Te enviaremos aparte el enlace para gestionarla o retirarla, solo a esa vía de contacto. Nunca lo mostramos aquí.</li> : null}
          <li><strong>Puedes cerrar esta ventana</strong>No necesitas hacer nada más aquí.</li>
        </ul>
      </section>
    </div>
  );
}

export function DecisionPage({ pageState }: PageProps) {
  usePageTitle("Revisa y decide");
  const [loaded, setLoaded] = useState<Loaded>({ kind: "loading" });
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    if (pageState === "uniform-error") return;
    let cancelled = false;
    void loadDecisionPageState().then((result) => {
      if (!cancelled) setLoaded(result);
    });
    return () => {
      cancelled = true;
    };
  }, [pageState, reloadTick]);

  if (pageState === "uniform-error" || loaded.kind === "uniform") return <DecisionUniformError />;
  if (loaded.kind === "loading") {
    return (
      <main className="lp-page-container lp-decision-page" aria-labelledby="decision-h1" aria-busy="true">
        <h1 id="decision-h1">Revisa y decide</h1>
      </main>
    );
  }
  if (loaded.kind === "unavailable") {
    return (
      <main className="lp-page-container lp-decision-page" aria-labelledby="decision-h1">
        <h1 id="decision-h1">Revisa y decide</h1>
        <NetworkAlert hidden={false} buttonClassName="lp-btn lp-btn-primary lp-cta lp-decision-cta" onRetry={() => { setLoaded({ kind: "loading" }); setReloadTick((n) => n + 1); }} />
        <HelpLink />
      </main>
    );
  }
  return <DecisionForm state={loaded.data} />;
}

function DecisionForm({ state }: { readonly state: DecisionPageState }) {
  const [subject, setSubject] = useState<Subject | null>(null);
  const [relationship, setRelationship] = useState("");
  const [authority, setAuthority] = useState(false);
  const [choices, setChoices] = useState<Readonly<Record<string, Choice | undefined>>>({});
  const [banner, setBanner] = useState<Banner>("none");
  const [validationDetail, setValidationDetail] = useState(VALIDATION_DETAIL);
  const [summary, setSummary] = useState<readonly SummaryItem[]>([]);
  const [summaryTick, setSummaryTick] = useState(0);
  const [errSubject, setErrSubject] = useState(false);
  const [errRelationship, setErrRelationship] = useState(false);
  const [errAuthority, setErrAuthority] = useState(false);
  const [errPurposes, setErrPurposes] = useState<ReadonlySet<string>>(new Set());
  const [invalidSubject, setInvalidSubject] = useState(false);
  const [invalidRelationship, setInvalidRelationship] = useState(false);
  const [invalidPurposes, setInvalidPurposes] = useState<ReadonlySet<string>>(new Set());
  const [chipIds, setChipIds] = useState<ReadonlySet<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [mismatchBusy, setMismatchBusy] = useState(false);
  const [terminal, setTerminal] = useState<Terminal | null>(null);
  const [formHidden, setFormHidden] = useState(false);
  const [receipt, setReceipt] = useState("");
  const [servedOverride, setServedOverride] = useState<ServedVersionView | null>(null);
  const busyRef = useRef(false);
  const stateRef = useRef({ subject, relationship, authority, choices });
  stateRef.current = { subject, relationship, authority, choices };
  const validationRef = useRef<HTMLDivElement>(null);
  const grantedHeadingRef = useRef<HTMLHeadingElement>(null);
  const declinedHeadingRef = useRef<HTMLHeadingElement>(null);
  const mismatchHeadingRef = useRef<HTMLHeadingElement>(null);

  useFocusWhen(validationRef, banner === "validation" && summary.length > 0, summaryTick);
  useFocusWhen(grantedHeadingRef, terminal === "granted");
  useFocusWhen(declinedHeadingRef, terminal === "declined");
  useFocusWhen(mismatchHeadingRef, terminal === "mismatch");

  const served = servedOverride ?? state.servedVersion;
  const purposesComplete = PURPOSES.every((p) => choices[p.purpose] !== undefined);
  const complete = subject === "yes" && authority && relationship !== "" && purposesComplete;
  const submitDisabled = busy || !complete;
  const anyDecline = PURPOSES.some((p) => choices[p.purpose] === "DECLINE");
  const helper = subject === "no" ? "No podemos continuar: indicaste que no es tu estudiante." : complete ? "Todo listo para enviar." : HELPER_DEFAULT;

  function changeBusy(next: boolean): void {
    busyRef.current = next;
    setBusy(next);
  }

  function clearFieldErrors(): void {
    setErrSubject(false);
    setErrRelationship(false);
    setErrAuthority(false);
    setErrPurposes(new Set());
    setInvalidSubject(false);
    setInvalidRelationship(false);
    setInvalidPurposes(new Set());
    setSummary([]);
  }

  // Estado «incompleto» (106:189): resumen con un enlace por campo pendiente + error inline por campo; el foco pasa al resumen.
  function showIncompleteSummary(): void {
    const cur = stateRef.current;
    const items: SummaryItem[] = [];
    const missingPurposes = new Set<string>();
    if (cur.subject === null) items.push({ targetId: "subject-yes", text: "Confirma si es tu estudiante." });
    if (cur.relationship === "") items.push({ targetId: "relationship-select", text: "Indica tu relación con el estudiante." });
    if (!cur.authority) items.push({ targetId: "authority-declared", text: "Marca la casilla de autoridad." });
    PURPOSES.forEach((p, index) => {
      if (cur.choices[p.purpose] === undefined) {
        missingPurposes.add(p.purpose);
        items.push({ targetId: `first-${p.purpose}`, text: `Elige una opción en: ${index + 1}. ${p.title}` });
      }
    });
    setErrSubject(cur.subject === null);
    setInvalidSubject(cur.subject === null);
    setErrRelationship(cur.relationship === "");
    setInvalidRelationship(cur.relationship === "");
    setErrAuthority(!cur.authority);
    setErrPurposes(missingPurposes);
    setInvalidPurposes(missingPurposes);
    setChipIds(missingPurposes);
    setSummary(items);
    setBanner("validation");
    setValidationDetail(VALIDATION_DETAIL);
    setSummaryTick((n) => n + 1);
  }

  function showNetwork(): void {
    setBanner("network");
  }

  /** Equivale a handleStepOrSubmitResponse: 404 -> uniforme, 409 -> conflicto, 422 -> validación; cualquier otro estado SIGUE
   * (igual que decision.js, que solo interpreta esos tres). Devuelve null si ya se mostró un error. */
  function interpret(res: ApiResult<unknown>): Record<string, unknown> | null {
    if (res.ok) return (typeof res.data === "object" && res.data !== null ? (res.data as Record<string, unknown>) : {});
    if (res.error.kind === "http") {
      if (res.error.status === 404) {
        setBanner("uniform");
        return null;
      }
      if (res.error.status === 409) {
        setBanner("conflict");
        return null;
      }
      if (res.error.status === 422) {
        setValidationDetail(VALIDATION_DETAIL);
        setSummary([]);
        setBanner("validation");
        return null;
      }
      return {};
    }
    return null; // red: lo trata el llamador
  }

  async function submitDecision(): Promise<void> {
    if (busyRef.current) return;
    const cur = stateRef.current;
    const incomplete = !(cur.subject === "yes" && cur.authority && cur.relationship !== "" && PURPOSES.every((p) => cur.choices[p.purpose] !== undefined));
    if (incomplete) {
      if (cur.subject !== "no") showIncompleteSummary();
      return;
    }
    clearFieldErrors();
    setBanner("none");
    setTerminal(null);
    changeBusy(true);

    const run = async (path: string, body: unknown): Promise<Record<string, unknown> | null | "network"> => {
      const res = await postJson(path, body);
      if (!res.ok && res.error.kind === "network") return "network";
      return interpret(res);
    };
    const stop = (): void => changeBusy(false);

    const step1 = await run("/decision/steps", { stepKind: "CONTEXT_INFORMATION_VIEWED" });
    if (step1 === "network") return (stop(), showNetwork());
    if (step1 === null) return stop();
    const step2 = await run("/decision/steps", { stepKind: "CONSENT_VERSION_VIEWED" });
    if (step2 === "network") return (stop(), showNetwork());
    if (step2 === null) return stop();
    const sv = step2.servedVersion as Partial<ServedVersionView> | undefined;
    if (sv && typeof sv.text === "string" && typeof sv.consentVersion === "string" && typeof sv.privacyNoticeVersion === "string") {
      setServedOverride({ consentVersion: sv.consentVersion, privacyNoticeVersion: sv.privacyNoticeVersion, text: sv.text });
    }
    const step3 = await run("/decision/steps", { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: cur.relationship, authorityDeclared: true });
    if (step3 === "network") return (stop(), showNetwork());
    if (step3 === null) return stop();
    const step4 = await run("/decision/steps", { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true });
    if (step4 === "network") return (stop(), showNetwork());
    if (step4 === null) return stop();
    const purposes = PURPOSES.map((p) => ({ purpose: p.purpose, choice: cur.choices[p.purpose] }));
    const submitted = await run("/decision/submit", { purposes });
    stop();
    if (submitted === "network") return showNetwork();
    if (submitted === null) return;
    // Frames 27:49 (GRANTED) / 27:58 (DECLINED): la confirmación REEMPLAZA el formulario; el foco pasa a su encabezado.
    if (submitted.state === "GRANTED" || submitted.state === "DECLINED") {
      setBanner("none");
      setReceipt(typeof submitted.receiptRef === "string" ? submitted.receiptRef : "");
      setFormHidden(true);
      setTerminal(submitted.state === "GRANTED" ? "granted" : "declined");
    }
  }

  // D-06: POST /decision/subject-mismatch (I9). 200 -> aviso registrado; otro estado -> error uniforme; red -> aviso de conexión.
  async function reportMismatch(): Promise<void> {
    if (busyRef.current) return;
    busyRef.current = true;
    setMismatchBusy(true);
    const res = await postJson("/decision/subject-mismatch");
    busyRef.current = false;
    setMismatchBusy(false);
    if (!res.ok && res.error.kind === "network") {
      showNetwork();
      return;
    }
    setFormHidden(true);
    if (res.ok && res.status === 200) {
      setBanner("none");
      setTerminal("mismatch");
    } else {
      setBanner("uniform");
    }
  }

  function selectSubject(value: Subject): void {
    setSubject(value);
    setErrSubject(false);
  }

  function selectPurpose(purpose: string, choice: Choice): void {
    setChoices((prev) => ({ ...prev, [purpose]: choice }));
    setErrPurposes((prev) => { const next = new Set(prev); next.delete(purpose); return next; });
  }

  const retry = () => void submitDecision();

  return (
    <main className="lp-page-container lp-decision-page" aria-labelledby="decision-h1">
      <div id="decision-form" hidden={formHidden}>
        <Stepper step={2} />
        <h1 id="decision-h1">Revisa y decide</h1>
        <p>Colegio Ejemplo — Estudio Beta de LectorPro. Estás revisando esta decisión para el estudiante.</p>

        <section className="lp-card lp-card-default lp-decision-section" aria-labelledby="consent-text-h2">
          <h2 id="consent-text-h2">Texto del consentimiento</h2>
          <p className="lp-input-help" id="consent-version-help">Versión vigente del texto: {served.consentVersion} · Aviso de privacidad: {served.privacyNoticeVersion}</p>
          <div className="lp-decision-legal-box" id="consent-text-box">{served.text}</div>
        </section>

        <section className="lp-card lp-card-default lp-decision-section" aria-labelledby="subject-h2">
          <h2 id="subject-h2">¿Es tu estudiante?</h2>
          {state.subjectLabel ? <p className="lp-decision-subject-ref" id="subject-ref">{state.subjectLabel} · Colegio Ejemplo</p> : null}
          <p>Confirma que estás decidiendo por el estudiante correcto antes de continuar.</p>
          <div className="lp-decision-chip-pair lp-decision-group" role="radiogroup" aria-labelledby="subject-h2" aria-describedby="err-subject" id="subject-radiogroup" data-invalid={invalidSubject ? "true" : undefined}>
            <button type="button" className="lp-decision-chip" role="radio" aria-checked={subject === "yes" ? "true" : "false"} id="subject-yes" data-value="yes" onClick={() => selectSubject("yes")}>Sí, es correcto</button>
            <button type="button" className="lp-decision-chip" role="radio" aria-checked={subject === "no" ? "true" : "false"} id="subject-no" data-value="no" onClick={() => selectSubject("no")}>No es mi estudiante</button>
          </div>
          <p className="lp-field-error" id="err-subject" hidden={!errSubject}><span aria-hidden="true">⚠ </span>Elige una opción.</p>
          <div role="alert" aria-live="assertive" className="lp-alert-warning" id="subject-mismatch-note" hidden={subject !== "no"}>
            <AlertHead icon="warning" title="No podemos continuar si no es tu estudiante." />
            <p>Puedes avisarnos para que cancelemos esta invitación, o escribirnos a <a href="mailto:ayuda@example.invalid" className="lp-link">ayuda@example.invalid</a> para revisar tu caso.</p>
            <button type="button" className="lp-btn lp-btn-outline lp-cta" id="report-mismatch-btn" aria-disabled={mismatchBusy ? "true" : "false"} aria-busy={mismatchBusy ? "true" : "false"} onClick={() => void reportMismatch()}>Informar que no es mi estudiante</button>
          </div>
        </section>

        <div id="decision-rest" hidden={subject === "no"}>
          <section className="lp-card lp-card-default lp-decision-section" aria-labelledby="authority-h2">
            <h2 id="authority-h2">Tu autoridad para decidir</h2>
            <div className="lp-form-group">
              <label className="lp-label" htmlFor="relationship-select">¿Cuál es tu relación con el estudiante?</label>
              <select
                className="lp-input lp-decision-relationship-select"
                id="relationship-select"
                aria-describedby="relationship-help err-relationship"
                aria-invalid={invalidRelationship ? "true" : "false"}
                value={relationship}
                onChange={(e) => {
                  setRelationship(e.target.value);
                  setErrRelationship(false);
                  setInvalidRelationship(false);
                }}
              >
                <option value="" disabled>Selecciona una opción</option>
                {state.relationshipRefs.map((ref) => <option key={ref} value={ref}>{ref}</option>)}
              </select>
              <p className="lp-legal-note" id="relationship-help">[LEGAL DECISION — enum de relación pendiente de DEC-BR-003 / EXT-A / LD-01; opción (b) de Carlos: lista de valores por configuración]</p>
              <p className="lp-field-error" id="err-relationship" hidden={!errRelationship}><span aria-hidden="true">⚠ </span>Elige una opción.</p>
            </div>
            <label className="lp-decision-checkbox-row" htmlFor="authority-declared">
              <input
                type="checkbox"
                id="authority-declared"
                className="lp-decision-checkbox"
                aria-labelledby="authority-declared-label"
                aria-describedby="err-authority"
                checked={authority}
                onChange={(e) => {
                  setAuthority(e.target.checked);
                  setErrAuthority(false);
                }}
              />
              <span id="authority-declared-label">[LEGAL DECISION — enunciado de autoridad pendiente de DEC-BR-003 / EXT-A / LD-01] Declaro que tengo la autoridad para tomar esta decisión por el estudiante.</span>
            </label>
            <p className="lp-field-error" id="err-authority" hidden={!errAuthority}><span aria-hidden="true">⚠ </span>Marca la casilla para continuar.</p>
          </section>

          <section className="lp-card lp-card-default lp-decision-section" aria-labelledby="purposes-h2">
            <h2 id="purposes-h2">Finalidades</h2>
            <p className="lp-legal-note">[LEGAL DECISION — carácter obligatorio de las 4 finalidades y consecuencia de no aceptar alguna: copy pendiente de aprobación de Carlos]</p>
            <p>Las 4 finalidades son necesarias para participar en el Estudio Beta. Si no aceptas alguna, el estudiante no participará.</p>
            <p className="lp-legal-note">[LEGAL DECISION — las descripciones de cada finalidad son borrador UX; texto legal definitivo pendiente de aprobación de Carlos]</p>
            {PURPOSES.map((p, index) => (
              <div className="lp-decision-purpose" data-purpose={p.purpose} id={`purpose-${p.purpose}`} key={p.purpose} data-invalid={invalidPurposes.has(p.purpose) ? "true" : undefined}>
                <h3>{index + 1}. {p.title}</h3>
                <p>{p.description}</p>
                <p className="lp-legal-note">[LEGAL DECISION — descripción de finalidad, borrador UX grounded en el protocolo; texto legal definitivo pendiente de aprobación de Carlos]</p>
                <div className="lp-decision-chip-pair lp-decision-group" role="radiogroup" aria-label={p.title} aria-describedby={`err-${p.purpose}`}>
                  <button type="button" className="lp-decision-chip" role="radio" aria-checked={choices[p.purpose] === "GRANT" ? "true" : "false"} data-purpose-choice={p.purpose} data-choice="GRANT" id={chipIds.has(p.purpose) ? `first-${p.purpose}` : undefined} onClick={() => selectPurpose(p.purpose, "GRANT")}>Acepto</button>
                  <button type="button" className="lp-decision-chip" role="radio" aria-checked={choices[p.purpose] === "DECLINE" ? "true" : "false"} data-purpose-choice={p.purpose} data-choice="DECLINE" onClick={() => selectPurpose(p.purpose, "DECLINE")}>No acepto</button>
                </div>
                <p className="lp-field-error" id={`err-${p.purpose}`} hidden={!errPurposes.has(p.purpose)}><span aria-hidden="true">⚠ </span>Elige una opción.</p>
              </div>
            ))}
          </section>

          <div role="status" aria-live="polite" className="lp-alert-info" id="decline-notice" hidden={!anyDecline}>
            <AlertHead icon="info" title="Elegiste no aceptar al menos una finalidad." />
            <p>Al enviar, registraremos que el estudiante no participará en el Estudio Beta.</p>
            <p className="lp-legal-note">[LEGAL DECISION — efecto de no aceptar una finalidad (Q-13): copy pendiente de aprobación de Carlos]</p>
          </div>

          <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-validation" tabIndex={-1} hidden={banner !== "validation"} ref={validationRef}>
            <AlertHead icon="error" title="Falta completar algo antes de enviar." />
            <p id="error-validation-detail">{validationDetail}</p>
            <ul className="lp-error-list" id="error-validation-list">
              {summary.map((item) => (
                <li key={item.targetId}>
                  <a
                    href={`#${item.targetId}`}
                    onClick={(ev) => {
                      const target = document.getElementById(item.targetId);
                      if (target) {
                        ev.preventDefault();
                        target.focus();
                      }
                    }}
                  >
                    {item.text}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          <div className="lp-decision-submit-row">
            <button type="button" className="lp-btn lp-btn-primary lp-cta lp-decision-cta" id="submit-btn" aria-disabled={submitDisabled ? "true" : "false"} aria-busy={busy ? "true" : "false"} onClick={() => void submitDecision()}>
              {busy ? "Enviando…" : "Enviar decisión"}
            </button>
            <p role="status" aria-live="polite" id="submit-helper">{helper}</p>
          </div>
        </div>
        <HelpLink />
      </div>

      <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-conflict" hidden={banner !== "conflict"}>
        <AlertHead icon="error" title="No pudimos registrar esta decisión." />
        <p id="error-conflict-detail">Esta decisión ya no está disponible para cambios. Si crees que esto es un error, contáctanos.</p>
      </div>

      <NetworkAlert hidden={banner !== "network"} buttonClassName="lp-btn lp-btn-primary lp-cta lp-decision-cta" onRetry={retry} />

      <UniformAlert hidden={banner !== "uniform"} title="No pudimos continuar con esta decisión.">
        <p>El enlace puede no ser válido o haber expirado. Si crees que esto es un error, contáctanos.</p>
      </UniformAlert>

      <RegisteredState kind="granted" receipt={terminal === "granted" ? receipt : ""} headingRef={grantedHeadingRef} hidden={terminal !== "granted"} />
      <RegisteredState kind="declined" receipt={terminal === "declined" ? receipt : ""} headingRef={declinedHeadingRef} hidden={terminal !== "declined"} />
      <div role="status" aria-live="polite" id="state-mismatch" hidden={terminal !== "mismatch"}>
        <span className="lp-hero-icon" aria-hidden="true">•</span>
        <h1 id="mismatch-heading" tabIndex={-1} ref={mismatchHeadingRef}>Registramos tu aviso</h1>
        <p>Cancelamos esta invitación.</p>
        <p>Indicaste que no es tu estudiante. No se registró ninguna decisión.</p>
        <p>Puedes cerrar esta ventana.</p>
      </div>
    </main>
  );
}
