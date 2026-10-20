import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DecisionPage } from "../../src/pages/decision.tsx";
import { navigation } from "../../src/router.ts";
import { empty, expectNoInlineStyleOrScript, expectPostHeaders, json, offline, postBody, setCsrfCookie, stubRoutes, type Routes } from "../b-helpers.ts";

const SERVED = { consentVersion: "v1", privacyNoticeVersion: "v1", text: "[LEGAL DECISION — texto de consentimiento pendiente de aprobación de Carlos]" };
const STATE = { relationshipRefs: ["SYNTHETIC_GUARDIAN", "SYNTHETIC_TUTOR"], servedVersion: SERVED, subjectLabel: "Alumno de prueba 7" };
const PURPOSE_TITLES = ["Participar en el Estudio Beta", "Grabación de audio", "Análisis automatizado", "Revisión humana"];
const PURPOSE_IDS = ["STUDY_PARTICIPATION", "AUDIO_RECORDING", "AUTOMATED_ANALYSIS", "HUMAN_REVIEW"];

beforeEach(() => {
  setCsrfCookie();
  vi.spyOn(navigation, "assign").mockImplementation(() => undefined);
});
afterEach(() => vi.unstubAllGlobals());

function ready(extra: Routes = {}, state: unknown = STATE) {
  return stubRoutes({ "GET /decision/page-state": json(state), ...extra });
}

async function renderReady(extra: Routes = {}, state: unknown = STATE) {
  const stub = ready(extra, state);
  const view = render(<DecisionPage pageState="ready" />);
  await screen.findByRole("heading", { level: 2, name: "Texto del consentimiento" });
  return { ...stub, ...view };
}

const choiceButtons = (name: "Acepto" | "No acepto") => screen.getAllByRole("radio", { name });

async function fillAll(choice: "Acepto" | "No acepto" = "Acepto") {
  await userEvent.click(screen.getByRole("radio", { name: "Sí, es correcto" }));
  await userEvent.selectOptions(screen.getByLabelText("¿Cuál es tu relación con el estudiante?"), "SYNTHETIC_GUARDIAN");
  await userEvent.click(document.getElementById("authority-declared")!);
  for (const b of choiceButtons(choice)) await userEvent.click(b);
}

const OK_STEPS: Routes = { "POST /decision/steps": [json({ result: "RECORDED" }), json({ servedVersion: SERVED }), json({}), json({})] };

describe("/decision (equivale a decision-page.ts + decision.js)", () => {
  it("TEST-CNS-1912: pide GET /decision/page-state y renderiza copy, ids, roles, ARIA y opciones del SSR sin preseleccionar nada", async () => {
    const { calls, container } = await renderReady();
    expect(calls[0]).toMatchObject({ method: "GET", path: "/decision/page-state" });
    expect(calls[0]!.init.credentials).toBe("same-origin");
    expect(document.title).toBe("Revisa y decide · Consent App");
    const main = screen.getByRole("main");
    expect(main).toHaveClass("lp-page-container", "lp-decision-page");
    expect(main).toHaveAccessibleName("Revisa y decide");
    expect(screen.getByText("Paso 2 de 3 · Revisa y decide")).toBeInTheDocument();
    expect(screen.getByText("Colegio Ejemplo — Estudio Beta de LectorPro. Estás revisando esta decisión para el estudiante.")).toBeInTheDocument();
    expect(container.querySelector("#consent-version-help")).toHaveTextContent("Versión vigente del texto: v1 · Aviso de privacidad: v1");
    expect(container.querySelector("#consent-text-box")).toHaveTextContent(SERVED.text);
    expect(container.querySelector("#consent-text-box")).toHaveClass("lp-decision-legal-box");
    expect(container.querySelector("#subject-ref")).toHaveTextContent("Alumno de prueba 7 · Colegio Ejemplo");
    const group = container.querySelector("#subject-radiogroup")!;
    expect(group).toHaveAttribute("role", "radiogroup");
    expect(group).toHaveAttribute("aria-labelledby", "subject-h2");
    expect(group).toHaveAttribute("aria-describedby", "err-subject");
    for (const name of ["Sí, es correcto", "No es mi estudiante"]) expect(screen.getByRole("radio", { name })).toHaveAttribute("aria-checked", "false");
    const select = screen.getByLabelText("¿Cuál es tu relación con el estudiante?");
    expect(select).toHaveAttribute("aria-invalid", "false");
    expect(select).toHaveAttribute("aria-describedby", "relationship-help err-relationship");
    expect(select).toHaveValue("");
    expect(within(select).getAllByRole("option").map((o) => o.textContent)).toEqual(["Selecciona una opción", "SYNTHETIC_GUARDIAN", "SYNTHETIC_TUTOR"]);
    expect(within(select).getByRole("option", { name: "Selecciona una opción" })).toBeDisabled();
    const checkbox = document.getElementById("authority-declared") as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    expect(checkbox).toHaveAttribute("aria-labelledby", "authority-declared-label");
    expect(container.querySelector("#authority-declared-label")).toHaveTextContent("Declaro que tengo la autoridad para tomar esta decisión por el estudiante.");
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual(PURPOSE_TITLES.map((t, i) => `${i + 1}. ${t}`));
    for (const id of PURPOSE_IDS) {
      const card = container.querySelector(`#purpose-${id}`)!;
      expect(card).toHaveAttribute("data-purpose", id);
      expect(card.querySelector("[role=radiogroup]")).toHaveAttribute("aria-describedby", `err-${id}`);
    }
    for (const b of [...choiceButtons("Acepto"), ...choiceButtons("No acepto")]) {
      expect(b).toHaveAttribute("aria-checked", "false");
      expect(b).toHaveClass("lp-decision-chip");
    }
    const submit = screen.getByRole("button", { name: "Enviar decisión" });
    expect(submit).toHaveAttribute("aria-disabled", "true");
    expect(submit).toHaveAttribute("aria-busy", "false");
    expect(submit).toHaveClass("lp-btn", "lp-btn-primary", "lp-cta", "lp-decision-cta");
    expect(container.querySelector("#submit-helper")).toHaveTextContent("Completa todas las secciones para continuar.");
    expect(container.querySelectorAll("[data-legal], .lp-legal-note").length).toBeGreaterThanOrEqual(7);
    for (const id of ["err-subject", "err-relationship", "err-authority", ...PURPOSE_IDS.map((p) => `err-${p}`), "subject-mismatch-note", "decline-notice", "error-validation", "error-conflict", "error-network", "error-uniform", "state-granted", "state-declined", "state-mismatch"]) {
      expect(container.querySelector(`#${id}`), id).toHaveAttribute("hidden");
    }
    expect(container.querySelector("#error-validation")).toHaveAttribute("tabindex", "-1");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expectNoInlineStyleOrScript(container);
  });

  it("TEST-CNS-1912: sin subjectLabel no hay #subject-ref; el estado de carga no inventa copy y respeta el orden de foco (chips -> select -> casilla -> finalidades -> enviar)", async () => {
    stubRoutes({ "GET /decision/page-state": new Promise<Response>(() => undefined) as unknown as Response });
    const loading = render(<DecisionPage pageState="ready" />);
    expect(screen.getByRole("main")).toHaveAttribute("aria-busy", "true");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    loading.unmount();
    vi.unstubAllGlobals();
    const { container } = await renderReady({}, { relationshipRefs: ["SYNTHETIC_GUARDIAN"], servedVersion: SERVED });
    expect(container.querySelector("#subject-ref")).toBeNull();
    const order = [...container.querySelectorAll<HTMLElement>("button, select, input, a[href]")].filter((el) => !el.closest("[hidden]")).map((el) => el.id || el.textContent);
    expect(order.slice(0, 6)).toEqual(["subject-yes", "subject-no", "relationship-select", "authority-declared", "Acepto", "No acepto"]);
    expect(order.at(-2)).toBe("submit-btn");
  });

  it("TEST-CNS-2065: los marcadores [LEGAL DECISION] de /decision (finalidades, enum de relación, enunciado de autoridad, texto servido) son texto visible, nunca solo un comentario (sustituye TEST-CNS-568/584 del SSR)", async () => {
    const { container } = await renderReady();
    const text = container.textContent ?? "";
    expect(text).toContain("[LEGAL DECISION — las descripciones de cada finalidad son borrador UX; texto legal definitivo pendiente de aprobación de Carlos]");
    expect(text).toContain("[LEGAL DECISION — enum de relación pendiente de DEC-BR-003 / EXT-A / LD-01; opción (b) de Carlos: lista de valores por configuración]");
    expect(text).toContain("[LEGAL DECISION — enunciado de autoridad pendiente de DEC-BR-003 / EXT-A / LD-01]");
    expect(text).toContain(SERVED.text);
    const perPurpose = "[LEGAL DECISION — descripción de finalidad, borrador UX grounded en el protocolo; texto legal definitivo pendiente de aprobación de Carlos]";
    expect(text.split(perPurpose).length - 1).toBe(PURPOSE_IDS.length);
  });

  it("TEST-CNS-1913: 'Enviar decisión' con campos pendientes (aria-disabled) muestra el resumen con enlaces y errores inline, enfoca el resumen y no envía nada", async () => {
    const { calls, container } = await renderReady();
    await userEvent.click(screen.getByRole("button", { name: "Enviar decisión" }));
    const summary = await screen.findByRole("alert");
    expect(summary).toHaveAttribute("id", "error-validation");
    expect(summary).toHaveFocus();
    expect(summary).toHaveTextContent("Falta completar algo antes de enviar.");
    expect(container.querySelector("#error-validation-detail")).toHaveTextContent("Revisa las secciones marcadas y vuelve a intentarlo.");
    const links = within(summary).getAllByRole("link");
    expect(links.map((l) => l.textContent)).toEqual([
      "Confirma si es tu estudiante.",
      "Indica tu relación con el estudiante.",
      "Marca la casilla de autoridad.",
      ...PURPOSE_TITLES.map((t, i) => `Elige una opción en: ${i + 1}. ${t}`),
    ]);
    expect(links.map((l) => l.getAttribute("href"))).toEqual(["#subject-yes", "#relationship-select", "#authority-declared", ...PURPOSE_IDS.map((p) => `#first-${p}`)]);
    for (const id of ["err-subject", "err-relationship", "err-authority", ...PURPOSE_IDS.map((p) => `err-${p}`)]) expect(container.querySelector(`#${id}`), id).not.toHaveAttribute("hidden");
    expect(screen.getByLabelText("¿Cuál es tu relación con el estudiante?")).toHaveAttribute("aria-invalid", "true");
    expect(container.querySelector("#subject-radiogroup")).toHaveAttribute("data-invalid", "true");
    expect(container.querySelector("#purpose-AUDIO_RECORDING")).toHaveAttribute("data-invalid", "true");
    await userEvent.click(links[1]!);
    expect(screen.getByLabelText("¿Cuál es tu relación con el estudiante?")).toHaveFocus();
    await userEvent.click(links[3]!);
    expect(choiceButtons("Acepto")[0]).toHaveFocus();
    expect(choiceButtons("Acepto")[0]).toHaveAttribute("id", "first-STUDY_PARTICIPATION");
    // Elegir una opción borra solo su error inline.
    await userEvent.click(choiceButtons("Acepto")[0]!);
    expect(container.querySelector("#err-STUDY_PARTICIPATION")).toHaveAttribute("hidden");
    expect(container.querySelector("#err-AUDIO_RECORDING")).not.toHaveAttribute("hidden");
    expect(calls).toHaveLength(1); // solo el GET de page-state
  });

  it("TEST-CNS-1914: flujo feliz GRANTED: 4 POST /decision/steps + /decision/submit con cabeceras CSRF y cuerpos exactos; reemplaza el formulario y enfoca el encabezado de confirmación", async () => {
    const { calls, container } = await renderReady({ ...OK_STEPS, "POST /decision/submit": json({ state: "GRANTED", receiptRef: "RCPT-SYN-1" }) });
    await fillAll("Acepto");
    expect(screen.getByRole("button", { name: "Enviar decisión" })).toHaveAttribute("aria-disabled", "false");
    expect(container.querySelector("#submit-helper")).toHaveTextContent("Todo listo para enviar.");
    await userEvent.click(screen.getByRole("button", { name: "Enviar decisión" }));
    const heading = await screen.findByRole("heading", { level: 1, name: "Listo, registramos tu decisión" });
    expect(heading).toHaveFocus();
    expect(heading).toHaveAttribute("id", "granted-heading");
    expect(heading).toHaveAttribute("tabindex", "-1");
    const posts = calls.filter((c) => c.method === "POST");
    expect(posts.map((c) => c.path)).toEqual(["/decision/steps", "/decision/steps", "/decision/steps", "/decision/steps", "/decision/submit"]);
    posts.forEach(expectPostHeaders);
    expect(posts.slice(0, 4).map(postBody)).toEqual([
      { stepKind: "CONTEXT_INFORMATION_VIEWED" },
      { stepKind: "CONSENT_VERSION_VIEWED" },
      { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true },
      { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true },
    ]);
    expect(postBody(posts[4]!)).toEqual({ purposes: PURPOSE_IDS.map((purpose) => ({ purpose, choice: "GRANT" })) });
    expect(container.querySelector("#decision-form")).toHaveAttribute("hidden");
    const state = container.querySelector("#state-granted")!;
    expect(state).not.toHaveAttribute("hidden");
    expect(state).toHaveAttribute("role", "status");
    expect(container.querySelector("#granted-receipt")).toHaveTextContent("RCPT-SYN-1");
    expect(container.querySelector("#declined-receipt")).toBeEmptyDOMElement();
    expect(within(state as HTMLElement).getByText("Paso 3 de 3 · Registro")).toBeInTheDocument();
    expect(within(state as HTMLElement).getByText("Registrado")).toHaveClass("lp-badge-success");
    expect(within(state as HTMLElement).getByText("Marca de agua IT0 · comprobante de prueba")).toBeInTheDocument();
    expect(within(state as HTMLElement).getAllByRole("listitem")).toHaveLength(3);
    expect(within(state as HTMLElement).getByText("Colegio Ejemplo — Estudio Beta de LectorPro.")).toBeInTheDocument();
    expect(container.querySelector("#state-declined")).toHaveAttribute("hidden");
    expectNoInlineStyleOrScript(container);
  });

  it("TEST-CNS-1915: 'No acepto' muestra #decline-notice (status) y el envío termina en DECLINED con el texto, comprobante y sin el paso de gestión", async () => {
    const { container } = await renderReady({ ...OK_STEPS, "POST /decision/submit": json({ state: "DECLINED", receiptRef: "RCPT-SYN-2" }) });
    await fillAll("Acepto");
    expect(container.querySelector("#decline-notice")).toHaveAttribute("hidden");
    await userEvent.click(choiceButtons("No acepto")[2]!);
    expect(choiceButtons("No acepto")[2]).toHaveAttribute("aria-checked", "true");
    expect(choiceButtons("Acepto")[2]).toHaveAttribute("aria-checked", "false");
    expect(container.querySelector("#decline-notice")).not.toHaveAttribute("hidden");
    expect(container.querySelector("#decline-notice")).toHaveTextContent("Elegiste no aceptar al menos una finalidad.");
    await userEvent.click(screen.getByRole("button", { name: "Enviar decisión" }));
    const heading = await screen.findByRole("heading", { level: 1, name: "Registramos tu decisión" });
    expect(heading).toHaveFocus();
    const state = container.querySelector("#state-declined") as HTMLElement;
    expect(state).not.toHaveAttribute("hidden");
    expect(within(state).getByText("El estudiante no participará en el Estudio Beta.")).toBeInTheDocument();
    expect(within(state).getAllByRole("listitem")).toHaveLength(2);
    expect(container.querySelector("#declined-receipt")).toHaveTextContent("RCPT-SYN-2");
    expect(state.querySelector(".lp-hero-icon")).toHaveTextContent("•");
  });

  it("TEST-CNS-1916: 'No es mi estudiante' oculta autoridad y finalidades, bloquea el envío y NO cancela por sí solo; el botón explícito hace POST /decision/subject-mismatch y enfoca 'Registramos tu aviso'", async () => {
    const { calls, container } = await renderReady({ "POST /decision/subject-mismatch": json({ result: "INVITATION_CANCELLED" }) });
    await userEvent.click(screen.getByRole("radio", { name: "No es mi estudiante" }));
    expect(container.querySelector("#decision-rest")).toHaveAttribute("hidden");
    expect(container.querySelector("#subject-mismatch-note")).not.toHaveAttribute("hidden");
    expect(container.querySelector("#subject-mismatch-note")).toHaveAttribute("role", "alert");
    expect(container.querySelector("#submit-helper")).toHaveTextContent("No podemos continuar: indicaste que no es tu estudiante.");
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "Informar que no es mi estudiante" }));
    const heading = await screen.findByRole("heading", { level: 1, name: "Registramos tu aviso" });
    expect(heading).toHaveFocus();
    expect(heading).toHaveAttribute("id", "mismatch-heading");
    expect(calls.filter((c) => c.method === "POST").map((c) => c.path)).toEqual(["/decision/subject-mismatch"]);
    expectPostHeaders(calls.at(-1)!);
    expect(container.querySelector("#decision-form")).toHaveAttribute("hidden");
    expect(screen.getByText("Cancelamos esta invitación.")).toBeInTheDocument();
    expect(screen.getByText("Indicaste que no es tu estudiante. No se registró ninguna decisión.")).toBeInTheDocument();
  });

  it("TEST-CNS-1916: subject-mismatch con respuesta distinta de 200 -> error uniforme y formulario oculto; con red -> aviso de conexión y el formulario sigue", async () => {
    stubRoutes({ "GET /decision/page-state": json(STATE), "POST /decision/subject-mismatch": [empty(404), offline()] });
    const { container } = render(<DecisionPage pageState="ready" />);
    await screen.findByRole("radio", { name: "No es mi estudiante" });
    await userEvent.click(screen.getByRole("radio", { name: "No es mi estudiante" }));
    const report = screen.getByRole("button", { name: "Informar que no es mi estudiante" });
    await userEvent.click(report);
    expect((await screen.findAllByRole("alert")).some((a) => a.id === "error-uniform")).toBe(true);
    expect(container.querySelector("#decision-form")).toHaveAttribute("hidden");
    expect(report).toHaveAttribute("aria-busy", "false");
  });

  it("TEST-CNS-1916: subject-mismatch con red muestra #error-network y deja el formulario visible", async () => {
    stubRoutes({ "GET /decision/page-state": json(STATE), "POST /decision/subject-mismatch": offline() });
    const { container } = render(<DecisionPage pageState="ready" />);
    await screen.findByRole("radio", { name: "No es mi estudiante" });
    await userEvent.click(screen.getByRole("radio", { name: "No es mi estudiante" }));
    await userEvent.click(screen.getByRole("button", { name: "Informar que no es mi estudiante" }));
    await waitFor(() => expect(container.querySelector("#error-network")).not.toHaveAttribute("hidden"));
    expect(container.querySelector("#decision-form")).not.toHaveAttribute("hidden");
  });

  it("TEST-CNS-1917: 409 -> #error-conflict, 404 -> #error-uniform, 422 -> #error-validation (sin enlaces); la secuencia se detiene y el botón vuelve a habilitarse", async () => {
    for (const [status, id] of [[409, "error-conflict"], [404, "error-uniform"], [422, "error-validation"]] as const) {
      const { calls, container, unmount } = await renderReady({ "POST /decision/steps": [json({}), empty(status)] });
      await fillAll();
      await userEvent.click(screen.getByRole("button", { name: "Enviar decisión" }));
      await waitFor(() => expect(container.querySelector(`#${id}`)).not.toHaveAttribute("hidden"));
      expect(calls.filter((c) => c.method === "POST")).toHaveLength(2);
      expect(screen.getByRole("button", { name: "Enviar decisión" })).toHaveAttribute("aria-disabled", "false");
      expect(screen.getByRole("button", { name: "Enviar decisión" })).toHaveAttribute("aria-busy", "false");
      if (id === "error-validation") {
        expect(within(container.querySelector("#error-validation") as HTMLElement).queryAllByRole("link")).toHaveLength(0);
        expect(container.querySelector("#error-validation-detail")).toHaveTextContent("Revisa las secciones marcadas y vuelve a intentarlo.");
      }
      unmount();
      vi.unstubAllGlobals();
    }
  });

  it("TEST-CNS-1917: falla de red a mitad del envío -> #error-network; 'Reintentar' repite la secuencia y la versión servida de CONSENT_VERSION_VIEWED reemplaza el texto", async () => {
    const newServed = { consentVersion: "v2", privacyNoticeVersion: "v3", text: "[LEGAL DECISION — otro texto]" };
    const { calls, container } = await renderReady({
      "POST /decision/steps": [offline(), json({}), json({ servedVersion: newServed }), json({}), json({})],
      "POST /decision/submit": json({ state: "GRANTED", receiptRef: "R" }),
    });
    await fillAll();
    await userEvent.click(screen.getByRole("button", { name: "Enviar decisión" }));
    const net = await screen.findByRole("alert");
    expect(net).toHaveAttribute("id", "error-network");
    expect(net).toHaveClass("lp-alert-warning");
    expect(screen.getByRole("button", { name: "Enviar decisión" })).toHaveAttribute("aria-busy", "false");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await screen.findByRole("heading", { name: "Listo, registramos tu decisión" });
    expect(container.querySelector("#consent-text-box")).toHaveTextContent("[LEGAL DECISION — otro texto]");
    expect(container.querySelector("#consent-version-help")).toHaveTextContent("Versión vigente del texto: v2 · Aviso de privacidad: v3");
    expect(calls.filter((c) => c.path === "/decision/steps")).toHaveLength(5);
  });

  it("TEST-CNS-1917: mientras envía el botón muestra 'Enviando…' con aria-busy/aria-disabled y no duplica", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => { release = r; });
    const { calls } = await renderReady({ "POST /decision/steps": async () => { await gate; return json({}); }, "POST /decision/submit": json({ state: "GRANTED", receiptRef: "R" }) });
    await fillAll();
    await userEvent.click(screen.getByRole("button", { name: "Enviar decisión" }));
    const busy = await screen.findByRole("button", { name: "Enviando…" });
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await userEvent.click(busy);
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
    release();
    await screen.findByRole("heading", { name: "Listo, registramos tu decisión" });
  });

  it("TEST-CNS-1918: pageState uniform-error o page-state 404 -> solo h1, alerta uniforme y ayuda; page-state caído -> aviso de conexión con Reintentar que vuelve a pedirlo", async () => {
    const uniform = render(<DecisionPage pageState="uniform-error" />);
    expect(screen.getByRole("alert")).toHaveTextContent("No pudimos continuar con esta decisión.");
    expect(screen.getByRole("alert")).toHaveAttribute("id", "error-uniform");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveAccessibleName("Revisa y decide");
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toBeInTheDocument();
    uniform.unmount();
    vi.unstubAllGlobals();

    const first = stubRoutes({ "GET /decision/page-state": empty(404) });
    const second = render(<DecisionPage pageState="ready" />);
    expect((await screen.findByRole("alert")).id).toBe("error-uniform");
    expect(first.calls).toHaveLength(1);
    second.unmount();
    vi.unstubAllGlobals();

    const third = stubRoutes({ "GET /decision/page-state": [offline(), json(STATE)] });
    render(<DecisionPage pageState="ready" />);
    expect((await screen.findByRole("alert")).id).toBe("error-network");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await screen.findByRole("heading", { level: 2, name: "Texto del consentimiento" });
    expect(third.calls).toHaveLength(2);
  });

  it("TEST-CNS-1918: una respuesta de page-state fuera del contrato se trata como no disponible (no renderiza datos inventados)", async () => {
    stubRoutes({ "GET /decision/page-state": json({ relationshipRefs: "x" }) });
    render(<DecisionPage pageState="ready" />);
    expect((await screen.findByRole("alert")).id).toBe("error-network");
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
  });
});
