// Gobierna: REQ-CNS-036 / UX-CNS-005 (aprobados por Carlos, 2026-10-02), DEC-BR-019 (Notion), diseno Figma 90:2
// (frames 90:12 entrada, 90:33 lista, 90:116 formulario, 93:3 resumen, 90:156 confirmacion, 90:185 correo invalido,
// 90:222 invitacion activa, 90:244 error generico, 90:267 vacio), API-CNS-116 (la lista consume su proyeccion colapsada).
//
// HTML server-rendered SIN JS, SIN CDN y SIN estilos inline (CSP script-src 'none'; style-src 'self'): el CSS vive en
// /assets/design-system/index.css y /assets/app.css (clases `lp-staff-*`). Todo valor dinamico pasa por escapeHtml.
//
// Privacidad (P-1/P-2, D10): ningun subjectRef/participationRef va en una URL o en un <title>; las refs viajan solo como
// campos ocultos de formularios POST con CSRF. El correo del apoderado aparece SOLO en el formulario (si se vuelve a
// editar) y en el resumen; nunca en la lista ni en la confirmacion ni en los mensajes de error (no se refleja).
// Copy legal: se renderiza el marcador "COPY LEGAL PENDIENTE" tal cual; no se redacta copy legal (LEGAL DECISION, Carlos).
// El estado de cada fila se mapea por el enum de API-CNS-116 (nunca por texto).

import type { StaffInvitationStatus } from "../../ports/staff-roster.port.ts";
import { escapeHtml } from "./welcome-page.ts";

export const STAFF_ENTRY_PATH = "/staff";
export const STAFF_LIST_PATH = "/staff/students";
export const STAFF_INVITE_PATH = "/staff/students/invite";
export const STAFF_REVIEW_PATH = "/staff/students/review";
export const STAFF_SEND_PATH = "/staff/students/send";
export const STAFF_SENT_PATH = "/staff/students/sent";
export const STAFF_LOGOUT_PATH = "/staff/logout";
export const STAFF_DEV_LOGIN_PATH = "/staff/dev-login";

/** Marcador legal (handoff §4/§6): placeholder, NO es copy final. LEGAL DECISION, Carlos. */
export const STAFF_LEGAL_MARKER =
  "COPY LEGAL PENDIENTE — Carlos (texto sobre quién invita, para qué y bajo qué responsabilidad del colegio). LEGAL DECISION.";

export const STAFF_IT0_NOTICE = "Iteración 0 · Solo datos sintéticos · Copy en borrador";

export const SUBJECT_UNLABELED = "Alumno sin etiqueta";

/** Etiqueta y tono por estado de API-CNS-116 (handoff §2). Record exhaustivo: un estado nuevo no compila sin su fila. */
const STATUS_VIEW: Readonly<Record<StaffInvitationStatus, { readonly label: string; readonly tone: "neutral" | "warning" | "info" | "success" }>> = {
  NOT_INVITED: { label: "Sin invitar", tone: "neutral" },
  PENDING_SEND: { label: "Envío incompleto", tone: "warning" },
  SENT: { label: "Enviada", tone: "info" },
  DECISION_RECORDED: { label: "Decisión registrada", tone: "success" },
  CLOSED_WITHOUT_DECISION: { label: "Cerrada sin decisión", tone: "neutral" },
};

export interface StaffUiStudent {
  /** Etiqueta sintetica ya validada ("Alumno de prueba N") o null. */
  readonly label: string | null;
  readonly subjectRef: string;
  readonly participationRef: string | null;
}

export interface StaffUiListItem extends StaffUiStudent {
  readonly status: StaffInvitationStatus;
}

export type StaffUiErrorVariant =
  | "generic" // 5xx / resultado inesperado durante el envio (handoff 90:244)
  | "session" // 404 uniforme: sesion vencida o alumno no disponible (AC-19)
  | "csrf" // 403 CSRF/origen (AC-19)
  | "permission" // 403 ACTOR_NOT_ALLOWED (AC-02)
  | "not-current" // participacion o estudio no vigente (AC-20)
  | "not-configured" // servicio no configurado, ERR-CM-12 (AC-20)
  | "list-unavailable" // 503 al leer la lista
  | "query"; // 422 de la lista (cursor invalido/expirado)

export type StaffUiView =
  | { readonly kind: "entry"; readonly devLogin: boolean }
  | { readonly kind: "list"; readonly csrfToken: string; readonly items: readonly StaffUiListItem[]; readonly nextCursor: string | null }
  | { readonly kind: "form"; readonly csrfToken: string; readonly student: StaffUiStudent; readonly error?: "format" | "reserved"; readonly email?: string }
  | { readonly kind: "review"; readonly csrfToken: string; readonly student: StaffUiStudent; readonly email: string }
  | { readonly kind: "sent"; readonly csrfToken: string; readonly label: string | null }
  | { readonly kind: "active"; readonly csrfToken: string; readonly label: string | null }
  | {
      readonly kind: "error";
      readonly variant: StaffUiErrorVariant;
      /** El fallo ocurrio en I1/I2/I3: puede haber quedado una invitacion a medias (AC-18, D2/D7). */
      readonly partial: boolean;
      /** Con sesion vigente se muestra "Cerrar sesion"; sin ella solo la marca. */
      readonly csrfToken?: string;
    };

const e = escapeHtml;

function labelOf(label: string | null): string {
  return label ?? SUBJECT_UNLABELED;
}

function hidden(name: string, value: string): string {
  return `<input type="hidden" name="${name}" value="${e(value)}">`;
}

function header(csrfToken: string | undefined): string {
  const session =
    csrfToken === undefined
      ? ""
      : `
    <div class="lp-staff-session">
      <span class="lp-staff-session-name">Administrador del colegio de prueba</span>
      <form method="post" action="${STAFF_LOGOUT_PATH}">
        ${hidden("csrf_token", csrfToken)}
        <button type="submit" class="lp-staff-btn-text">Cerrar sesión</button>
      </form>
    </div>`;
  return `<header class="lp-staff-header" role="banner">
    <div class="lp-staff-brand">
      <span class="lp-staff-brand-name">Consent App</span>
      <span class="lp-staff-brand-sub">Colegio de prueba · Invitaciones</span>
    </div>${session}
  </header>`;
}

interface Crumb {
  readonly text: string;
  readonly href?: string;
}

function breadcrumb(crumbs: readonly Crumb[]): string {
  const items = crumbs
    .map((c, i) => {
      const last = i === crumbs.length - 1;
      if (last) return `<li><span aria-current="page">${e(c.text)}</span></li>`;
      return c.href ? `<li><a class="lp-link" href="${c.href}">${e(c.text)}</a></li>` : `<li>${e(c.text)}</li>`;
    })
    .join("\n        ");
  return `<nav class="lp-staff-crumbs" aria-label="Ruta de navegación">
      <ol>
        ${items}
      </ol>
    </nav>`;
}

const CRUMB_ROOT: Crumb = { text: "Colegio de prueba" };
const CRUMB_LIST: Crumb = { text: "Invitaciones", href: STAFF_LIST_PATH };

function shell(opts: { readonly title: string; readonly width: "narrow" | "form" | "wide"; readonly csrfToken?: string; readonly body: string }): string {
  return `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${e(opts.title)} · Consent App</title>
  <link rel="stylesheet" href="/assets/design-system/index.css">
  <link rel="stylesheet" href="/assets/app.css">
</head>
<body class="lp-staff-body">
  <a class="lp-staff-skip" href="#main">Saltar al contenido</a>
  ${header(opts.csrfToken)}
  <main class="lp-staff-main" id="main">
    <div class="lp-staff-content lp-staff-content--${opts.width}">
    <p class="lp-staff-banner">${e(STAFF_IT0_NOTICE)}</p>
    ${opts.body}
    </div>
  </main>
</body>
</html>
`;
}

const BACK_LINK = `<a class="lp-link lp-verify-tap-target" href="${STAFF_LIST_PATH}">← Volver a la lista de alumnos</a>`;

function studentCard(label: string | null): string {
  return `<section class="lp-card lp-staff-card" role="group" aria-labelledby="student-card-label">
      <p id="student-card-label" class="lp-staff-card-label">Alumno</p>
      <p class="lp-staff-card-value">${e(labelOf(label))}</p>
    </section>`;
}

function legalMarker(): string {
  return `<p class="lp-staff-legal-marker">${e(STAFF_LEGAL_MARKER)}</p>`;
}

function statusBadge(status: StaffInvitationStatus): string {
  const v = STATUS_VIEW[status];
  return `<span class="lp-staff-badge lp-staff-badge--${v.tone}"><span class="lp-staff-dot" aria-hidden="true"></span>${e(v.label)}</span>`;
}

function renderEntry(devLogin: boolean): string {
  const dev = devLogin
    ? `
      <form method="post" action="${STAFF_DEV_LOGIN_PATH}" class="lp-staff-dev-login">
        <p class="lp-staff-help">Solo desarrollo local: usa el administrador sintético del colegio de prueba. No existe fuera de LOCAL.</p>
        <button type="submit" class="lp-btn lp-staff-btn lp-staff-btn-secondary">Entrar (solo desarrollo)</button>
      </form>`
    : "";
  return shell({
    title: "Consola del colegio",
    width: "narrow",
    body: `<h1 class="lp-staff-h1">Consola del colegio</h1>
    <p class="lp-staff-lead">Entra para crear y enviar invitaciones del Estudio Beta a los apoderados de tu colegio.</p>
    <section class="lp-card lp-staff-card" aria-labelledby="access-title">
      <h2 id="access-title" class="lp-staff-h2">Acceso del colegio</h2>
      <div class="lp-staff-placeholder">
        <p class="lp-staff-placeholder-title">Aquí irá el acceso con la identidad del colegio.</p>
        <p class="lp-staff-help">Pendiente APR-IDP (Carlos / studio). Esta propuesta no pide usuario ni contraseña.</p>
      </div>
      <button type="button" class="lp-btn lp-staff-btn lp-staff-btn-disabled" aria-disabled="true" aria-describedby="login-help">No disponible: acceso del colegio pendiente</button>
      <p id="login-help" class="lp-staff-note">Este botón está deshabilitado porque el acceso con la identidad del colegio (APR-IDP) aún no está definido. Se activará cuando esté listo. Acceso solo para personal del colegio con permiso de invitar.</p>${dev}
    </section>
    <p class="lp-staff-help">¿Problemas para entrar? Contacta al equipo del estudio (enlace placeholder).</p>`,
  });
}

function renderList(view: Extract<StaffUiView, { kind: "list" }>): string {
  const crumbs = breadcrumb([CRUMB_ROOT, { text: "Invitaciones" }]);
  if (view.items.length === 0 && view.nextCursor === null) {
    return shell({
      title: "Alumnos del colegio",
      width: "wide",
      csrfToken: view.csrfToken,
      body: `${crumbs}
    <h1 class="lp-staff-h1">Alumnos del colegio</h1>
    <section class="lp-card lp-staff-card lp-staff-empty" aria-labelledby="empty-title">
      <h2 id="empty-title" class="lp-staff-h2">Todavía no hay alumnos en este colegio</h2>
      <p class="lp-staff-lead">Cuando el estudio cargue alumnos de prueba, aparecerán aquí. Si esperabas verlos, contacta al equipo del estudio.</p>
      <a class="lp-btn lp-staff-btn lp-staff-btn-secondary" href="mailto:ayuda@example.invalid">Contactar al equipo del estudio (placeholder)</a>
    </section>`,
    });
  }
  const rows = view.items
    .map((item) => {
      const name = labelOf(item.label);
      let action: string;
      if (item.status === "NOT_INVITED" && item.participationRef !== null) {
        action = `<form method="post" action="${STAFF_INVITE_PATH}" class="lp-staff-row-form">
            ${hidden("csrf_token", view.csrfToken)}
            ${hidden("subject", item.subjectRef)}
            ${hidden("participation", item.participationRef)}
            <button type="submit" class="lp-btn lp-btn-primary lp-staff-btn" aria-label="${e(`Invitar — ${name}`)}">Invitar</button>
          </form>`;
      } else if (item.status === "NOT_INVITED") {
        action = `<span class="lp-staff-muted">Invitación no disponible por ahora</span>`;
      } else {
        action = `<span class="lp-staff-muted">Sin acciones</span>`;
      }
      return `<tr>
          <th scope="row">${e(name)}</th>
          <td>${statusBadge(item.status)}</td>
          <td>${action}</td>
        </tr>`;
    })
    .join("\n        ");
  const more =
    view.nextCursor === null
      ? ""
      : `<p><a class="lp-link lp-verify-tap-target" href="${STAFF_LIST_PATH}?cursor=${e(encodeURIComponent(view.nextCursor))}">Ver más alumnos</a></p>`;
  return shell({
    title: "Alumnos del colegio",
    width: "wide",
    csrfToken: view.csrfToken,
    body: `${crumbs}
    <h1 class="lp-staff-h1">Alumnos del colegio</h1>
    <p class="lp-staff-lead">Elige un alumno para invitar a su apoderado. Solo se muestran alumnos de prueba.</p>
    <div class="lp-table-container lp-staff-table-container">
      <table class="lp-table lp-table-comfortable lp-staff-table">
        <caption class="lp-sr-only">Alumnos del colegio y estado de su invitación</caption>
        <thead>
          <tr>
            <th scope="col">Alumno</th>
            <th scope="col">Estado de la invitación</th>
            <th scope="col">Acción</th>
          </tr>
        </thead>
        <tbody>
        ${rows}
        </tbody>
      </table>
    </div>
    ${more}`,
  });
}

function emailErrorText(kind: "format" | "reserved"): string {
  return kind === "format"
    ? "Error: escribe un correo con el formato nombre@dominio."
    : "Error: este correo no es válido para la fase de prueba. Usa un correo que termine en @example.invalid.";
}

function renderForm(view: Extract<StaffUiView, { kind: "form" }>): string {
  const name = labelOf(view.student.label);
  const err = view.error;
  const topAlert = err
    ? `<div class="lp-staff-alert lp-staff-alert--error" role="alert">
      <p class="lp-staff-alert-title">Revisa el correo del apoderado</p>
      <p>Hay 1 campo por corregir: <a class="lp-link" href="#guardian-email">Correo del apoderado</a>.</p>
    </div>`
    : "";
  const describedBy = err ? "guardian-email-help guardian-email-error" : "guardian-email-help";
  const errorBlock = err ? `<div id="guardian-email-error" class="lp-staff-field-error" role="alert">${e(emailErrorText(err))}</div>` : "";
  const value = view.email !== undefined && !err ? ` value="${e(view.email)}"` : "";
  return shell({
    title: "Invitar apoderado",
    width: "form",
    csrfToken: view.csrfToken,
    body: `${topAlert}
    ${breadcrumb([CRUMB_ROOT, CRUMB_LIST, { text: "Invitar apoderado" }])}
    <h1 class="lp-staff-h1">Invitar al apoderado de ${e(name)}</h1>
    ${studentCard(view.student.label)}
    <form method="post" action="${STAFF_REVIEW_PATH}" novalidate class="lp-card lp-staff-card lp-staff-form">
      ${hidden("csrf_token", view.csrfToken)}
      ${hidden("subject", view.student.subjectRef)}
      ${hidden("participation", view.student.participationRef ?? "")}
      <div class="lp-form-group">
        <label for="guardian-email" class="lp-label lp-staff-label">Correo del apoderado <span class="lp-staff-optional">(obligatorio)</span></label>
        <input id="guardian-email" name="guardian_email" type="email" autocomplete="off" required maxlength="254" class="lp-input lp-staff-input" aria-describedby="${describedBy}"${err ? ' aria-invalid="true" autofocus' : ""}${value}>
        <p id="guardian-email-help" class="lp-staff-help">Escribe el correo donde el apoderado recibirá el enlace de la invitación. Durante la fase de prueba solo se aceptan correos de ejemplo que terminan en @example.invalid.</p>
        ${errorBlock}
      </div>
      <div class="lp-staff-actions">
        <button type="submit" class="lp-btn lp-btn-primary lp-staff-btn">Revisar invitación</button>
        <a class="lp-btn lp-staff-btn lp-staff-btn-secondary" href="${STAFF_LIST_PATH}">Cancelar</a>
      </div>
    </form>
    ${BACK_LINK}`,
  });
}

function renderReview(view: Extract<StaffUiView, { kind: "review" }>): string {
  const name = labelOf(view.student.label);
  return shell({
    title: "Revisar invitación",
    width: "form",
    csrfToken: view.csrfToken,
    body: `${breadcrumb([CRUMB_ROOT, CRUMB_LIST, { text: "Invitar apoderado" }, { text: "Resumen" }])}
    <h1 class="lp-staff-h1">Revisa la invitación antes de enviarla</h1>
    ${studentCard(view.student.label)}
    <form method="post" action="${STAFF_SEND_PATH}" class="lp-card lp-staff-card lp-staff-form">
      ${hidden("csrf_token", view.csrfToken)}
      ${hidden("subject", view.student.subjectRef)}
      ${hidden("participation", view.student.participationRef ?? "")}
      ${hidden("guardian_email", view.email)}
      <section class="lp-staff-review" aria-labelledby="review-title">
        <h2 id="review-title" class="lp-staff-h3">Revisa antes de enviar</h2>
        <p>Alumno: ${e(name)}</p>
        <p>Correo del apoderado: ${e(view.email)}</p>
        <p class="lp-staff-help">Se enviará un correo con un enlace personal al apoderado. El enlace no se muestra en esta pantalla.</p>
        ${legalMarker()}
      </section>
      <div class="lp-staff-actions">
        <button type="submit" class="lp-btn lp-staff-btn lp-staff-btn-secondary">Enviar invitación</button>
        <button type="submit" formaction="${STAFF_INVITE_PATH}" class="lp-btn lp-staff-btn lp-staff-btn-secondary">Volver a editar</button>
      </div>
    </form>
    ${BACK_LINK}`,
  });
}

function renderSent(view: Extract<StaffUiView, { kind: "sent" }>): string {
  const name = labelOf(view.label);
  return shell({
    title: "Invitación enviada",
    width: "form",
    csrfToken: view.csrfToken,
    body: `${breadcrumb([CRUMB_ROOT, CRUMB_LIST, { text: "Invitación enviada" }])}
    <h1 class="lp-staff-h1" id="sent-h1" tabindex="-1" autofocus>Invitación enviada</h1>
    <div class="lp-staff-alert lp-staff-alert--success" role="status" aria-live="polite">
      <p class="lp-staff-alert-title">Enviamos la invitación al apoderado.</p>
      <p>Estado de ${e(name)}: Enviada. El enlace no se muestra aquí por seguridad.</p>
    </div>
    <section class="lp-card lp-staff-card" aria-labelledby="summary-title">
      <h2 id="summary-title" class="lp-staff-h3">Resumen</h2>
      <p>Alumno: ${e(name)}</p>
      ${legalMarker()}
    </section>
    <div class="lp-staff-actions">
      <a class="lp-btn lp-btn-primary lp-staff-btn" href="${STAFF_LIST_PATH}">Volver a la lista</a>
      <a class="lp-btn lp-staff-btn lp-staff-btn-secondary" href="${STAFF_LIST_PATH}">Invitar a otro alumno</a>
    </div>`,
  });
}

function renderActive(view: Extract<StaffUiView, { kind: "active" }>): string {
  const name = labelOf(view.label);
  return shell({
    title: "Invitación activa",
    width: "form",
    csrfToken: view.csrfToken,
    body: `${breadcrumb([CRUMB_ROOT, CRUMB_LIST, { text: "Invitar apoderado" }])}
    <h1 class="lp-staff-h1">Invitar al apoderado de ${e(name)}</h1>
    <div class="lp-staff-alert lp-staff-alert--warning" role="alert" tabindex="-1" autofocus>
      <p class="lp-staff-alert-title">Este alumno ya tiene una invitación activa.</p>
      <p>${e(name)} ya tiene una invitación en curso, por eso no se puede crear otra. Revisa su estado en la lista.</p>
    </div>
    <div class="lp-staff-actions">
      <a class="lp-btn lp-btn-primary lp-staff-btn" href="${STAFF_LIST_PATH}">Volver a la lista</a>
    </div>`,
  });
}

const PARTIAL_NOTICE =
  "Es posible que la invitación haya quedado a medias. No la repitas por tu cuenta; contacta a soporte. En esta etapa un alumno con una invitación a medias no puede reinvitarse.";

interface ErrorCopy {
  readonly h1: string;
  readonly title: string;
  readonly body: string;
  readonly action: { readonly text: string; readonly href: string };
}

const ERROR_COPY: Readonly<Record<StaffUiErrorVariant, ErrorCopy>> = {
  generic: {
    h1: "No pudimos completar el envío",
    title: "Algo salió mal de nuestro lado.",
    body: "El alumno puede haber quedado en un estado intermedio: la invitación pudo crearse a medias. No la repitas por tu cuenta; contacta a soporte.",
    action: { text: "Volver a la lista", href: STAFF_LIST_PATH },
  },
  session: {
    h1: "No pudimos abrir esta página",
    title: "Tu sesión venció o el alumno ya no está disponible.",
    body: "Entra de nuevo desde la entrada de la consola. No se hizo ningún cambio.",
    action: { text: "Ir a la entrada", href: STAFF_ENTRY_PATH },
  },
  csrf: {
    h1: "No pudimos procesar el formulario",
    title: "El formulario no pasó la verificación de seguridad.",
    body: "Recarga la página e inténtalo de nuevo. No se hizo ningún cambio.",
    action: { text: "Volver a la lista", href: STAFF_LIST_PATH },
  },
  permission: {
    h1: "No tienes permiso para esta acción",
    title: "Tu usuario no puede crear invitaciones.",
    body: "Solo el personal del colegio con permiso de invitar puede hacerlo. No se hizo ningún cambio.",
    action: { text: "Ir a la entrada", href: STAFF_ENTRY_PATH },
  },
  "not-current": {
    h1: "No pudimos completar el envío",
    title: "La participación o el estudio no está vigente.",
    body: "Por eso no se pudo crear la invitación. Contacta al equipo del estudio si crees que es un error.",
    action: { text: "Volver a la lista", href: STAFF_LIST_PATH },
  },
  "not-configured": {
    h1: "No pudimos completar el envío",
    title: "El servicio de invitaciones no está configurado.",
    body: "Contacta al equipo del estudio.",
    action: { text: "Volver a la lista", href: STAFF_LIST_PATH },
  },
  "list-unavailable": {
    h1: "No pudimos mostrar los alumnos",
    title: "Algo salió mal de nuestro lado.",
    body: "Vuelve a intentarlo en unos minutos. Si sigue pasando, contacta a soporte.",
    action: { text: "Volver a la lista", href: STAFF_LIST_PATH },
  },
  query: {
    h1: "No pudimos mostrar esa página",
    title: "La página que pediste no es válida o ya venció.",
    body: "Vuelve a la lista para empezar de nuevo.",
    action: { text: "Volver a la lista", href: STAFF_LIST_PATH },
  },
};

function renderError(view: Extract<StaffUiView, { kind: "error" }>): string {
  const copy = ERROR_COPY[view.variant];
  // "generic" ya dice que pudo quedar a medias; el resto lo agrega solo si el fallo fue despues de EN0 (I1/I2/I3).
  const showPartial = view.partial && view.variant !== "generic";
  const partial = showPartial ? `\n      <p>${e(PARTIAL_NOTICE)}</p>` : "";
  return shell({
    title: copy.h1,
    width: "form",
    ...(view.csrfToken !== undefined ? { csrfToken: view.csrfToken } : {}),
    body: `<h1 class="lp-staff-h1">${e(copy.h1)}</h1>
    <div class="lp-staff-alert lp-staff-alert--error" role="alert" tabindex="-1" autofocus>
      <p class="lp-staff-alert-title">${e(copy.title)}</p>
      <p>${e(copy.body)}</p>${partial}
    </div>
    <div class="lp-staff-actions">
      <a class="lp-btn lp-btn-primary lp-staff-btn" href="${copy.action.href}">${e(copy.action.text)}</a>
    </div>`,
  });
}

export function renderStaffUiPage(view: StaffUiView): string {
  switch (view.kind) {
    case "entry":
      return renderEntry(view.devLogin);
    case "list":
      return renderList(view);
    case "form":
      return renderForm(view);
    case "review":
      return renderReview(view);
    case "sent":
      return renderSent(view);
    case "active":
      return renderActive(view);
    case "error":
      return renderError(view);
  }
}
