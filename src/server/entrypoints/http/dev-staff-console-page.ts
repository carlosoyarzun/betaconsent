// Gobierna: CA-125 + aprobación de Carlos 2026-10-01 (consola dev del colegio, SOLO LOCAL).
// HTML server-rendered sin JS ni CDN. Reutiliza el CSS del design-system y de la app (mismo patrón
// que welcome-page.ts) más un <style> mínimo inline. Todo valor dinámico pasa por escapeHtml.

import { escapeHtml } from "./welcome-page.ts";

export interface DevStaffConsoleFormView {
  readonly kind: "form";
  readonly loggedIn: boolean;
  readonly csrfToken: string;
  readonly subjectRef: string;
  readonly participationRef: string;
  readonly contextRef: string;
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
  <style>
    main { max-width: 560px; margin: 0 auto; padding: 24px; }
    label { display: block; margin-top: 16px; font-weight: 600; }
    input[type=email], input[readonly] { display: block; width: 100%; min-height: 44px; box-sizing: border-box; padding: 8px; }
    button { min-height: 44px; margin-top: 16px; padding: 0 16px; }
    :focus-visible { outline: 3px solid #1a56db; outline-offset: 2px; }
    .dev-banner { border: 2px dashed #b45309; padding: 8px; }
    .dev-error { border: 2px solid #b91c1c; padding: 8px; margin: 16px 0; }
    dl { word-break: break-all; }
  </style>`;

function shell(body: string): string {
  return `<!doctype html>
<html lang="es">
<head>
  ${HEAD}
</head>
<body>
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
      <label for="subject">Alumno sintético (precargado)</label>
      <input id="subject" type="text" readonly value="${escapeHtml(view.subjectRef)}">
      <label for="participation">Participación sintética (precargada)</label>
      <input id="participation" type="text" readonly value="${escapeHtml(view.participationRef)}">
      <label for="guardian_email">Correo del apoderado (inventado)</label>
      <input id="guardian_email" name="guardian_email" type="email" required autocomplete="off" placeholder="apoderado1@example.invalid" aria-describedby="email-help"${view.error ? ` aria-invalid="true"` : ""}>
      <p id="email-help">Solo se aceptan correos inventados de dominio reservado (por ejemplo example.invalid).</p>
      <button type="submit" class="lp-btn lp-btn-primary">Crear y enviar invitación</button>
    </form>`);
}
