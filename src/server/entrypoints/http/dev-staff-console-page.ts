// Gobierna: CA-125 + aprobación de Carlos 2026-10-01 (consola dev del colegio, SOLO LOCAL).
// HTML server-rendered sin JS ni CDN. Reutiliza el CSS del design-system y de la app (mismo patrón
// que welcome-page.ts) más las clases `lp-dev-console*` de app.css (sin <style> inline, ADR-001 §3). Todo valor dinámico pasa por escapeHtml.

import { escapeHtml } from "./html-escape.ts";

export interface DevStaffConsoleFormView {
  readonly kind: "form";
  readonly loggedIn: boolean;
  readonly csrfToken: string;
  readonly students: readonly { readonly label: string; readonly subjectRef: string }[];
  readonly contextRef: string;
  readonly selectedSubjectRef?: string;
  readonly error?: string;
  readonly progress?: string;
}

export type DevStaffConsoleView =
  | DevStaffConsoleFormView
  | { readonly kind: "sent"; readonly invitationPath?: string; readonly otpSinkPath: string; readonly consolePath: string };

const HEAD = `<meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Consola de desarrollo del colegio · Consent App</title>
  <link rel="stylesheet" href="/assets/design-system/index.css">
  <link rel="stylesheet" href="/assets/app.css">
  <link rel="stylesheet" href="/assets/dev-console.css">`;

function shell(body: string): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body class="lp-dev-console">
  <main aria-labelledby="dev-h1">
    <p class="dev-banner" role="note">Herramienta de desarrollo, solo local, con datos inventados. No es una pantalla de producto.</p>
    <h1 id="dev-h1">Consola de desarrollo del colegio</h1>
    ${body}
  </main>
</body>
</html>
`;
}

export function renderDevStaffConsolePage(view: DevStaffConsoleView): string {
  if (view.kind === "sent") {
    const link = view.invitationPath
      ? `<p><a href="${escapeHtml(view.invitationPath)}">Abrir enlace de invitación (apoderado)</a></p>`
      : `<p>La invitación se envió, pero el enlace no está disponible en el sink de esta instalación.</p>`;
    return shell(`<div role="status" aria-live="polite">
      <h2>Invitación enviada</h2>
      <p>Se creó la participación, la invitación y se envió al sink de desarrollo (sin correo real).</p>
      ${link}
      <p><a href="${escapeHtml(view.otpSinkPath)}">Ver el código de verificación (OTP) emitido</a> (aparece cuando el apoderado pulsa "Continuar").</p>
      <p><a href="${escapeHtml(view.consolePath)}">Volver a la consola</a></p>
    </div>`);
  }

  const error = view.error
    ? `<div class="dev-error" role="alert" id="dev-error" tabindex="-1"><p>${escapeHtml(view.error)}</p>${view.progress ? `<p>${escapeHtml(view.progress)}</p>` : ""}</div>`
    : "";

  if (!view.loggedIn) {
    return shell(`${error}
    <p>Paso 1. Entra con el administrador sintético del colegio de prueba.</p>
    <form method="post" action="/__dev/staff-console/login">
      <button type="submit" class="lp-btn lp-btn-primary">Entrar como administrador del colegio de prueba</button>
    </form>`);
  }

  return shell(`${error}
    <p>Paso 2. Crea y envía la invitación para el alumno de prueba.</p>
    <form method="post" action="/__dev/staff-console/invite">
      <input type="hidden" name="csrf_token" value="${escapeHtml(view.csrfToken)}">
      <label for="student">Alumno sintético</label>
      <select id="student" name="student" required>${view.students.map((st) => `<option value="${escapeHtml(st.subjectRef)}"${st.subjectRef === view.selectedSubjectRef ? " selected" : ""}>${escapeHtml(st.label)}</option>`).join("")}</select>
      <p id="student-help">Cada alumno admite una sola invitación activa; si ya la tiene, se avisa.</p>
      <label for="guardian_email">Correo del apoderado (inventado)</label>
      <input id="guardian_email" name="guardian_email" type="email" required autocomplete="off" placeholder="apoderado1@example.invalid" aria-describedby="email-help"${view.error ? ` aria-invalid="true"` : ""}>
      <p id="email-help">Solo se aceptan correos inventados de dominio reservado (por ejemplo example.invalid).</p>
      <button type="submit" class="lp-btn lp-btn-primary">Crear y enviar invitación</button>
    </form>`);
}
