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
