# Reglas del Design System Agnóstico (HTML+CSS) para Agentes de IA

Este documento contiene directrices obligatorias para cualquier modelo o agente de IA que construya o modifique interfaces dentro de este proyecto.

## Directrices Críticas

1. **Inclusión de Estilos**: Toda página HTML debe incluir el paquete de estilos del Design System en su cabecera `<head>`:
   ```html
   <link rel="stylesheet" href="design-system/index.css">
   ```
2. **No Duplicación ni Estilos Ad-hoc**: Está terminantemente prohibido escribir reglas CSS duplicadas en hojas de estilo locales o utilizar atributos `style="..."` con colores hexadecimales o píxeles directos.
3. **Uso Obligatorio de Clases `.lp-*`**:
   - **Botones**: Utiliza `<button class="lp-btn lp-btn-primary">` (o variantes `lp-btn-secondary`, `lp-btn-outline`, `lp-btn-ghost`, `lp-btn-danger`).
   - **Formularios**: Encapsula controles en `<div class="lp-form-group">` usando `<label class="lp-label">`, `<input class="lp-input">` y `<select class="lp-select">`.
   - **Tablas**: Estructura tablas usando `<div class="lp-table-container"><table class="lp-table lp-table-comfortable">`.
   - **Insignias**: Utiliza `<span class="lp-badge lp-badge-success">` con `<span class="lp-status-dot">` para estados de estudiantes o entregas.
   - **Tarjetas**: Utiliza `<div class="lp-card lp-card-default">` o tarjetas estadísticas `<div class="lp-stat-card">`.
4. **Layout Estandarizado**: Reutiliza las clases del layout base (`.lp-app-shell`, `.lp-sidebar`, `.lp-topbar`, `.lp-page-container`, `.lp-page-header`, `.lp-breadcrumbs`).
5. **Uso de CSS Custom Properties**: Si necesitas escribir una regla CSS personalizada específica de una vista, utiliza ÚNICAMENTE las variables CSS `--lp-*` expuestas en `design-system/css/tokens.css`.
