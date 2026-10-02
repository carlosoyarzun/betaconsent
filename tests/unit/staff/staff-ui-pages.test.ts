// Gobierna: REQ-CNS-036 AC-03..AC-09, AC-13, AC-17..AC-21, UX-CNS-005, DEC-BR-019, diseno Figma 90:2 (handoff §0-§13), WCAG 2.2 AA.
// Pruebas de las vistas HTML del colegio sin servidor. TEST-CNS-1100 (etiqueta y accion por estado), 1101 (accesibilidad basica),
// 1102 (escape y sin PII en URLs), 1103 (marcador legal y copy), 1104 (CSS: clases usadas existen; sin color de feedback en texto).
// Solo datos sinteticos.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { STAFF_INVITATION_STATUSES, type StaffInvitationStatus } from "../../../src/server/ports/staff-roster.port.ts";
import { renderStaffUiPage, STAFF_LEGAL_MARKER, type StaffUiErrorVariant, type StaffUiView } from "../../../src/server/entrypoints/http/staff-ui-pages.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";

const CSRF = "csrf-fixture-token";
const SUBJECT = fixtureUuid("ui-subject");
const PART = fixtureUuid("ui-part");
const EMAIL = "apoderado1@example.invalid";
const student = { label: "Alumno de prueba 1", subjectRef: SUBJECT, participationRef: PART };

const LABELS: Record<StaffInvitationStatus, string> = {
  NOT_INVITED: "Sin invitar",
  PENDING_SEND: "Envío incompleto",
  SENT: "Enviada",
  DECISION_RECORDED: "Decisión registrada",
  CLOSED_WITHOUT_DECISION: "Cerrada sin decisión",
};

const ERROR_VARIANTS: readonly StaffUiErrorVariant[] = ["generic", "session", "csrf", "permission", "not-current", "not-configured", "list-unavailable", "query"];

function allViews(): Array<{ name: string; view: StaffUiView }> {
  const listItems = STAFF_INVITATION_STATUSES.map((status, i) => ({
    label: `Alumno de prueba ${i + 1}`,
    subjectRef: fixtureUuid(`ui-s-${i}`),
    participationRef: status === "NOT_INVITED" ? fixtureUuid(`ui-p-${i}`) : null,
    status,
  }));
  return [
    { name: "entry", view: { kind: "entry", devLogin: false } },
    { name: "entry-dev", view: { kind: "entry", devLogin: true } },
    { name: "list", view: { kind: "list", csrfToken: CSRF, items: listItems, nextCursor: "c1.abcdefghijklmnopqrstuvwxyzabcdefghijklmnop" } },
    { name: "list-empty", view: { kind: "list", csrfToken: CSRF, items: [], nextCursor: null } },
    { name: "form", view: { kind: "form", csrfToken: CSRF, student } },
    { name: "form-format", view: { kind: "form", csrfToken: CSRF, student, error: "format" } },
    { name: "form-reserved", view: { kind: "form", csrfToken: CSRF, student, error: "reserved" } },
    { name: "review", view: { kind: "review", csrfToken: CSRF, student, email: EMAIL } },
    { name: "sent", view: { kind: "sent", csrfToken: CSRF, label: "Alumno de prueba 1" } },
    { name: "active", view: { kind: "active", csrfToken: CSRF, label: "Alumno de prueba 3" } },
    ...ERROR_VARIANTS.map((variant) => ({ name: `error-${variant}`, view: { kind: "error", variant, partial: true, csrfToken: CSRF } as StaffUiView })),
  ];
}

const count = (html: string, re: RegExp): number => (html.match(re) ?? []).length;

test("TEST-CNS-1100 etiqueta exacta por estado de API-CNS-116; solo NOT_INVITED con participacion ofrece Invitar; el resto 'Sin acciones'; sin reenviar/cancelar/reintentar", () => {
  assert.deepEqual([...STAFF_INVITATION_STATUSES].sort(), Object.keys(LABELS).sort());
  for (const status of STAFF_INVITATION_STATUSES) {
    const html = renderStaffUiPage({
      kind: "list",
      csrfToken: CSRF,
      items: [{ label: "Alumno de prueba 1", subjectRef: SUBJECT, participationRef: status === "NOT_INVITED" ? PART : null, status }],
      nextCursor: null,
    });
    assert.ok(html.includes(`</span>${LABELS[status]}</span>`), `${status} -> ${LABELS[status]}`);
    for (const [other, label] of Object.entries(LABELS)) {
      if (other !== status) assert.ok(!html.includes(`</span>${label}</span>`), `${status} no debe mostrar ${label}`);
    }
    assert.equal(html.includes(">Invitar</button>"), status === "NOT_INVITED", `accion Invitar solo en NOT_INVITED (${status})`);
    assert.equal(html.includes("Sin acciones"), status !== "NOT_INVITED", `Sin acciones (${status})`);
    for (const forbidden of ["Reenviar", "Cancelar", "Reinvitar", "Reintentar", "Vencida", "canjeada", "abierta", "aceptada", "rechazada"]) {
      assert.ok(!html.toLowerCase().includes(forbidden.toLowerCase()), `${status}: sin ${forbidden}`);
    }
  }
  // Envio incompleto con participacion: se puede retomar desde Invitar.
  const resume = renderStaffUiPage({ kind: "list", csrfToken: CSRF, items: [{ label: "Alumno de prueba 1", subjectRef: SUBJECT, participationRef: PART, status: "PENDING_SEND" }], nextCursor: null });
  assert.ok(resume.includes(">Invitar</button>") && resume.includes("Envío incompleto"));
  // NOT_INVITED sin participationRef: sin boton, texto neutro.
  const none = renderStaffUiPage({ kind: "list", csrfToken: CSRF, items: [{ label: null, subjectRef: SUBJECT, participationRef: null, status: "NOT_INVITED" }], nextCursor: null });
  assert.ok(!none.includes(">Invitar</button>") && none.includes("Invitación no disponible por ahora") && none.includes("Alumno sin etiqueta"));
  // Nombre accesible del boton contiene el texto visible (2.5.3).
  const withBtn = renderStaffUiPage({ kind: "list", csrfToken: CSRF, items: [{ label: "Alumno de prueba 2", subjectRef: SUBJECT, participationRef: PART, status: "NOT_INVITED" }], nextCursor: null });
  assert.match(withBtn, /aria-label="Invitar — Alumno de prueba 2"[^>]*>Invitar<\/button>/);
});

test("TEST-CNS-1101 accesibilidad basica de todas las vistas: lang, un h1, landmarks, labels, describedby validos, tabla con caption y th scope, roles de alerta, sin JS ni estilos inline", () => {
  for (const { name, view } of allViews()) {
    const html = renderStaffUiPage(view);
    assert.match(html, /<html lang="es">/, name);
    assert.equal(count(html, /<h1[\s>]/g), 1, `${name}: un solo h1`);
    assert.equal(count(html, /<main[\s>]/g), 1, `${name}: un main`);
    assert.ok(html.includes('role="banner"'), `${name}: banner`);
    assert.ok(/<title>[^<]+<\/title>/.test(html), `${name}: title`);
    // ids unicos y referencias aria/for resueltas
    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]!);
    assert.equal(new Set(ids).size, ids.length, `${name}: ids unicos`);
    for (const m of html.matchAll(/aria-(?:describedby|labelledby)="([^"]+)"/g)) {
      for (const ref of m[1]!.split(" ")) assert.ok(ids.includes(ref), `${name}: ${ref} existe`);
    }
    for (const m of html.matchAll(/<label[^>]*for="([^"]+)"/g)) assert.ok(ids.includes(m[1]!), `${name}: label for ${m[1]}`);
    // controles de formulario visibles con etiqueta
    for (const m of html.matchAll(/<input(?![^>]*type="hidden")[^>]*\sid="([^"]+)"/g)) assert.match(html, new RegExp(`<label[^>]*for="${m[1]}"`), `${name}: input ${m[1]} con label`);
    // sin JS, estilos inline, handlers ni recursos externos
    assert.ok(!/<script|<style|\sstyle=|\son[a-z]+=|https?:\/\//i.test(html), `${name}: sin JS/estilo inline/externos`);
    // migajas: ultima con aria-current (excepto entrada y errores)
    if (html.includes("<nav")) {
      assert.match(html, /<nav class="lp-staff-crumbs" aria-label="Ruta de navegación">/, name);
      assert.equal(count(html, /aria-current="page"/g), 1, `${name}: una migaja actual`);
    }
  }
  const list = renderStaffUiPage(allViews().find((v) => v.name === "list")!.view);
  assert.match(list, /<caption class="lp-sr-only">[^<]+<\/caption>/);
  assert.equal(count(list, /<th scope="col">/g), 3);
  assert.equal(count(list, /<th scope="row"/g), STAFF_INVITATION_STATUSES.length);
  assert.ok(!list.includes('role="status"'), "el badge no es un role=status: el estado es texto");
  assert.ok(list.includes('aria-hidden="true"'), "el punto del badge es decorativo");
  // errores: role=alert con foco inicial
  for (const variant of ERROR_VARIANTS) {
    const html = renderStaffUiPage({ kind: "error", variant, partial: false });
    assert.match(html, /role="alert" tabindex="-1" autofocus/, variant);
    assert.ok(!html.includes("Cerrar sesión"), `${variant}: sin sesion no hay boton de cerrar sesion`);
  }
  // formulario con error: input invalido, asociado a su mensaje, con foco
  const bad = renderStaffUiPage({ kind: "form", csrfToken: CSRF, student, error: "reserved" });
  assert.match(bad, /aria-describedby="guardian-email-help guardian-email-error" aria-invalid="true" autofocus/);
  assert.match(bad, /id="guardian-email-error" class="lp-staff-field-error" role="alert">Error: este correo no es válido para la fase de prueba\. Usa un correo que termine en @example\.invalid\./);
  const fmt = renderStaffUiPage({ kind: "form", csrfToken: CSRF, student, error: "format" });
  assert.ok(fmt.includes("Error: escribe un correo con el formato nombre@dominio."));
  const form = renderStaffUiPage({ kind: "form", csrfToken: CSRF, student });
  assert.match(form, /type="email" autocomplete="off" required/);
  assert.ok(!/checked|<input[^>]*type="checkbox"/.test(form), "sin casillas ni preseleccion");
  assert.ok(!/<input[^>]*name="guardian_email"[^>]*value=/.test(form), "sin valor preseleccionado");
  // entrada: boton deshabilitado anunciable
  const entry = renderStaffUiPage({ kind: "entry", devLogin: false });
  assert.match(entry, /aria-disabled="true" aria-describedby="login-help"/);
  assert.ok(entry.includes('id="login-help"'));
});

test("TEST-CNS-1102 escape de todo valor dinamico; sin subjectRef/participationRef/cursor/email en hrefs, actions, titulos ni en la lista/confirmacion/errores", () => {
  const evil = '"><img src=x onerror=alert(1)>';
  const html = renderStaffUiPage({ kind: "review", csrfToken: evil, student: { label: evil, subjectRef: evil, participationRef: evil }, email: evil });
  assert.ok(!html.includes("<img"), "sin inyeccion");
  assert.ok(html.includes("&lt;img"));
  const views = allViews();
  for (const { name, view } of views) {
    const out = renderStaffUiPage(view);
    for (const m of out.matchAll(/(?:href|action|formaction)="([^"]*)"/g)) {
      assert.ok(!m[1]!.includes(SUBJECT) && !m[1]!.includes(PART), `${name}: refs fuera de URLs`);
      assert.ok(!m[1]!.includes("@") || m[1]!.startsWith("mailto:ayuda@example.invalid"), `${name}: sin email en URLs`);
    }
    assert.ok(!/<title>[^<]*(@|[0-9a-f]{8}-[0-9a-f]{4})/.test(out), `${name}: titulo sin PII`);
    if (view.kind !== "review" && view.kind !== "form") assert.ok(!out.includes(EMAIL), `${name}: sin email`);
  }
  // El correo solo en el resumen (no en el formulario sin edicion previa).
  assert.ok(renderStaffUiPage({ kind: "review", csrfToken: CSRF, student, email: EMAIL }).includes(`Correo del apoderado: ${EMAIL}`));
  assert.ok(!renderStaffUiPage({ kind: "form", csrfToken: CSRF, student }).includes(EMAIL));
  // Con error el valor no se refleja (ni siquiera si viniera en la vista).
  const reflected = renderStaffUiPage({ kind: "form", csrfToken: CSRF, student, error: "reserved", email: "apoderado1@gmail.com" });
  assert.ok(!reflected.includes("apoderado1@gmail.com"));
  // "Volver a editar": el correo vuelve prellenado, escapado.
  assert.ok(renderStaffUiPage({ kind: "form", csrfToken: CSRF, student, email: EMAIL }).includes(`value="${EMAIL}"`));
});

test("TEST-CNS-1103 marcador legal literal en resumen y confirmacion; resumen con Enviar y Volver a editar de igual peso, sin casilla; copy sin ref de soporte inventada", () => {
  const review = renderStaffUiPage({ kind: "review", csrfToken: CSRF, student, email: EMAIL });
  const sent = renderStaffUiPage({ kind: "sent", csrfToken: CSRF, label: "Alumno de prueba 1" });
  for (const html of [review, sent]) {
    assert.ok(html.includes("COPY LEGAL PENDIENTE — Carlos"), "marcador legal");
    assert.ok(html.includes(STAFF_LEGAL_MARKER));
  }
  assert.match(review, /<button type="submit" class="lp-btn lp-staff-btn lp-staff-btn-secondary">Enviar invitación<\/button>/);
  assert.match(review, /<button type="submit" formaction="\/staff\/students\/invite" class="lp-btn lp-staff-btn lp-staff-btn-secondary">Volver a editar<\/button>/);
  assert.ok(!review.includes("lp-btn-primary") && !/type="checkbox"/.test(review));
  assert.ok(!sent.includes(EMAIL) && sent.includes("El enlace no se muestra aquí por seguridad."));
  assert.ok(sent.includes('role="status" aria-live="polite"') && /<h1[^>]*tabindex="-1"/.test(sent));
  // Formulario: el primario lleva al resumen, no envia.
  assert.ok(renderStaffUiPage({ kind: "form", csrfToken: CSRF, student }).includes(">Revisar invitación</button>"));
  for (const variant of ERROR_VARIANTS) {
    const html = renderStaffUiPage({ kind: "error", variant, partial: true });
    assert.ok(!/REF-0000|Referencia de soporte|Reintentar/.test(html), `${variant}: sin referencia ilustrativa ni Reintentar`);
    assert.ok(!html.includes(EMAIL) && !html.includes("@gmail.com"));
  }
  // Cadena parcial: avisa que puede retomarse con Invitar y, si se repite, contactar soporte; sin codigos internos.
  const partial = renderStaffUiPage({ kind: "error", variant: "not-configured", partial: true });
  assert.ok(partial.includes("retomarla con «Invitar»") && partial.includes("contacta a soporte") && !partial.includes("reinvitarse"));
  const generic = renderStaffUiPage({ kind: "error", variant: "generic", partial: true });
  assert.ok(generic.includes("retómala con «Invitar»") && !generic.includes("No la repitas"));
  const already = renderStaffUiPage({ kind: "sent", csrfToken: CSRF, label: "Alumno de prueba 1", alreadySent: true });
  assert.ok(already.includes("La invitación ya había sido enviada.") && already.includes("No se envió una nueva.") && !already.includes("Enviamos la invitación"));
  assert.ok(!/ERR-|GUARD_|INVITATION_/.test(partial));
  // Activa (409): sin formulario.
  const active = renderStaffUiPage({ kind: "active", csrfToken: CSRF, label: "Alumno de prueba 3" });
  assert.ok(active.includes("Este alumno ya tiene una invitación activa.") && !active.includes("<form method=\"post\" action=\"/staff/students/review\""));
  // Aviso persistente IT0 en todas las pantallas (AC-03).
  for (const { name, view } of allViews()) assert.ok(renderStaffUiPage(view).includes("Iteración 0 · Solo datos sintéticos"), `${name}: aviso IT0`);
});

test("TEST-CNS-1104 CSS: toda clase lp-staff-* usada por las vistas existe en app.css; los colores de feedback solo en borde/fondo/punto, nunca como color de texto; sin outline:none", () => {
  const css = readFileSync(fileURLToPath(new URL("../../../src/server/entrypoints/http/assets/app.css", import.meta.url)), "utf8");
  const used = new Set<string>();
  for (const { view } of allViews()) {
    for (const m of renderStaffUiPage(view).matchAll(/class="([^"]+)"/g)) for (const c of m[1]!.split(/\s+/)) if (c.startsWith("lp-staff-") || c === "lp-sr-only") used.add(c);
  }
  assert.ok(used.size > 20);
  for (const c of used) assert.ok(new RegExp(`\\.${c}(?![\\w-])`).test(css), `app.css define .${c}`);
  const staffCss = css.slice(css.indexOf("Consola del colegio (REQ-CNS-036"));
  for (const decl of staffCss.matchAll(/(^|[;{\s])color:\s*([^;}]+)/g)) {
    assert.ok(!/feedback/.test(decl[2]!), `color de texto con feedback: ${decl[0].trim()}`);
  }
  assert.ok(!/outline:\s*none/.test(staffCss), "nunca outline:none sin reemplazo");
  assert.ok(/@media \(max-width: 640px\)/.test(staffCss) && /overflow:\s*visible/.test(staffCss), "tabla apilada bajo 640px");
  assert.ok(/min-height:\s*44px/.test(staffCss));
  // Tokens: solo var(--lp-*) (aparte de los dos literales documentados).
  const hexes = staffCss.match(/#[0-9a-fA-F]{3,8}\b/g) ?? [];
  assert.deepEqual(hexes, [], "sin colores hex literales");
});
