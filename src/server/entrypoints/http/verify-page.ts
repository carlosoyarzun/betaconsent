// Gobierna: CLAUDE.md (UX-CNS-001, /welcome): "Si no existe todavía una pantalla de OTP,
// redirige a /verify y deja un placeholder mínimo servido por el servidor". No hay handoff de
// ravena-ux ni frame de Figma para /verify todavía (UX-CNS-001 solo cubre /welcome); este
// placeholder es deliberadamente mínimo y no debe tomarse como la pantalla final de OTP.

export function renderVerifyPlaceholderPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Verificación · Consent App</title>
  <link rel="stylesheet" href="/assets/design-system/index.css">
  <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
  <main class="lp-page-container lp-welcome-page" aria-labelledby="verify-h1">
    <h1 id="verify-h1">Verificación</h1>
    <p>Esta es la siguiente pantalla pendiente del flujo (código de verificación). Todavía no está implementada.</p>
  </main>
</body>
</html>
`;
}
