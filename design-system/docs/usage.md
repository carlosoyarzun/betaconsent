# LectorPro Design System Agnóstico — Guía de Uso (HTML + CSS)

Esta guía describe cómo utilizar el sistema de diseño agnóstico en HTML + CSS Vanilla para crear pantallas consistentes, modernas y accesibles.

## Principios Clave

1. **Sin dependencias externas**: Funciona de forma nativa en cualquier navegador web moderno sin requerir React, Vue, Angular o Node.js.
2. **Tokens semánticos por CSS Custom Properties**: Todos los colores, tipografías, sombras y espaciados están expuestos mediante variables `--lp-*` con soporte nativo para Tema Claro y Oscuro.
3. **Componentes basados en clases `.lp-*`**: Clases CSS modulares y limpias para botones, campos de texto, tablas, avatares, modales y tarjetas.

---

## Estructura de Archivos del Design System

```
design-system/
├── index.css           # Archivo maestro de distribución (Importa todo)
├── css/
│   ├── tokens.css      # Variables CSS Custom Properties (:root, theme light/dark)
│   ├── layouts.css     # Estilos de AppShell, Sidebar, TopBar, Container
│   ├── components.css  # Botones, Tarjetas, Inputs, Tablas, Badges, Modales
│   └── patterns.css    # Barra de filtros, barra de herramientas, estadísticas
└── docs/
    ├── html-guide.md   # Referencia completa con snippets HTML
    ├── usage.md        # Guía de uso general
    └── agent-rules.md  # Reglas para agentes de IA
```

---

## Cómo Incluir en tu Mini Aplicación

Solo necesitas enlazar el archivo `index.css`:

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mi Mini App — LectorPro</title>
  <link rel="stylesheet" href="design-system/index.css">
</head>
<body>

  <div class="lp-app-shell">
    <!-- Tu contenido HTML siguiendo la guía html-guide.md -->
  </div>

</body>
</html>
```

---

## Soporte para Tema Oscuro / Claro

El sistema de diseño detecta automáticamente la preferencia del sistema operativo (`prefers-color-scheme`). Además, puedes forzar el tema en cualquier elemento o a nivel global añadiendo el atributo `data-theme`:

```html
<!-- Forzar Modo Oscuro -->
<html data-theme="dark">

<!-- Forzar Modo Claro -->
<html data-theme="light">
```

---

## Contraste (WCAG 2.2 AA)

Regla: los colores `--lp-color-feedback-*` (success/warning/error/info y sus `-bg`) son de marca de estado y se usan SOLO para puntos (`.lp-status-dot`), iconos, bordes decorativos y fondos. Nunca como color de texto ni como fondo de texto blanco (error 3.76:1, warning 2.15:1, success 2.54:1, info 3.68:1 sobre blanco). Para esos roles existen tokens semánticos que cumplen 4.5:1 (texto, 1.4.3) y 3:1 (no-texto, 1.4.11). El test `tests/unit/design-system/contrast.test.ts` (TEST-CNS-1130..1133) lee `tokens.css` y falla si un par baja de esos umbrales.

| Token (claro / oscuro) | Rol | Ratio claro (peor superficie) |
|---|---|---|
| `--lp-text-error` `#B91C1C` / `#FCA5A5` | texto de error, `.lp-input-error-msg`, `.lp-badge-error`, `.lp-alert-error` | 6.47 sobre blanco; 5.53 sobre `-bg`; 5.08 sobre `-bg` en bg-subtle |
| `--lp-text-warning` `#92400E` / `#FCD34D` | texto de aviso, `.lp-badge-warning`, `.lp-alert-warning` | 7.09; 6.47 sobre `-bg`; 5.95 en bg-subtle |
| `--lp-text-success` `#047857` / `#6EE7B7` | texto de éxito, `.lp-badge-success`, `.lp-alert-success` | 5.48; 4.90 sobre `-bg`; 4.51 en bg-subtle |
| `--lp-text-info` `#1D4ED8` / `#93C5FD` | texto informativo, `.lp-badge-info`, `.lp-alert-info` | 6.70; 5.84 sobre `-bg`; 5.37 en bg-subtle |
| `--lp-border-control` `#7B8BA0` / `#7C8DA6` | borde en reposo de controles (`.lp-input`, `.lp-select`, `.lp-btn-outline`, chips) | 3.48 sobre blanco; 3.17 sobre bg-subtle |
| `--lp-action-danger` `#DC2626`, `-hover` `#B91C1C`, `-text` `#FFFFFF` | fondo de `.lp-btn-danger` con texto blanco | 4.83 / 6.47 |

Valor cambiado: `--lp-text-muted` claro `#64748B` -> `#5B6B80` (solo se usa como texto; antes 4.34:1 sobre bg-subtle, ahora 4.97; sobre blanco 5.44) y oscuro `#94A3B8` -> `#A3B1C6` (4.04 -> 4.76 sobre surface-elevated).

Sin cambios: `--lp-border-default` (1.23:1) y `--lp-border-strong` quedan para bordes decorativos (tarjetas, separadores, tablas), donde el contenido ya se distingue por sí mismo; no usarlos como único borde de un control. Los `--lp-color-feedback-*` siguen igual.

Componentes nuevos: `.lp-alert-error|warning|success|info` (borde y fondo de feedback, texto `--lp-text-*`).

Brecha conocida (tema oscuro): el borde de foco `--lp-action-primary` `#2563EB` sobre `#1E293B` da 2.83:1 (< 3:1); fuera de alcance, Consent App no usa el tema oscuro.
