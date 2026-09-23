# LectorPro Design System — Guía de Marcado HTML Semántico (Agnóstico)

Esta guía documenta los fragmentos de código HTML semántico y las clases CSS exactas para utilizar el sistema de diseño LectorPro en **cualquier mini aplicación de HTML + CSS puro** sin React ni librerías adicionales.

---

## 1. Importación del Sistema de Diseño

Añade el archivo CSS empaquetado en la etiqueta `<head>` de tus páginas HTML:

```html
<link rel="stylesheet" href="design-system/index.css">
```

---

## 2. Estructura de Layout de Página (AppShell)

Todas las pantallas del portal autenticado deben estructurarse con la plantilla base:

```html
<div class="lp-app-shell">
  <!-- Barra Lateral (Sidebar) -->
  <aside class="lp-sidebar">
    <div class="lp-sidebar-header">
      <a href="#" class="lp-sidebar-brand">
        <img src="assets/lectorpro_mark.png" alt="LectorPro" class="lp-sidebar-logo" />
        <div>
          <h1 class="lp-sidebar-title">LectorPro</h1>
          <div class="lp-sidebar-subtitle">Portal Docente</div>
        </div>
      </a>
    </div>
    
    <nav class="lp-sidebar-nav">
      <a href="#" class="lp-nav-item lp-active">Inicio</a>
      <a href="#" class="lp-nav-item">Mis Cursos</a>
      <a href="#" class="lp-nav-item">Estudiantes</a>
      <a href="#" class="lp-nav-item">Reportes</a>
    </nav>
  </aside>

  <!-- Contenido Principal -->
  <div class="lp-app-shell-main">
    <!-- TopBar Superior -->
    <header class="lp-topbar">
      <div><!-- Slot Izquierdo --></div>
      <div>
        <span class="lp-badge lp-badge-default">Profesor Activo</span>
      </div>
    </header>

    <!-- Page Container -->
    <main class="lp-page-container">
      <!-- Page Header -->
      <div class="lp-page-header">
        <div class="lp-page-header-content">
          <ul class="lp-breadcrumbs">
            <li><a href="#" class="lp-breadcrumb-item">Inicio</a></li>
            <li class="lp-breadcrumb-separator">›</li>
            <li><span class="lp-breadcrumb-item lp-active">Evaluaciones</span></li>
          </ul>
          <h2 class="lp-page-header-title">Gestión de Cursos</h2>
          <p class="lp-page-header-description">Monitoreo de desempeño lector y fluidez oral.</p>
        </div>

        <div class="lp-page-header-actions">
          <button class="lp-btn lp-btn-secondary">Exportar CSV</button>
          <button class="lp-btn lp-btn-primary">+ Nueva Evaluación</button>
        </div>
      </div>

      <!-- Tu contenido aquí -->
    </main>
  </div>
</div>
```

---

## 3. Componentes UI

### Botones (`.lp-btn`)

```html
<!-- Variantes -->
<button class="lp-btn lp-btn-primary">Botón Primario</button>
<button class="lp-btn lp-btn-secondary">Botón Secundario</button>
<button class="lp-btn lp-btn-outline">Botón Delineado</button>
<button class="lp-btn lp-btn-ghost">Botón Fantasma</button>
<button class="lp-btn lp-btn-danger">Eliminar</button>

<!-- Tamaños -->
<button class="lp-btn lp-btn-primary lp-btn-sm">Pequeño</button>
<button class="lp-btn lp-btn-primary lp-btn-md">Mediano</button>
<button class="lp-btn lp-btn-primary lp-btn-lg">Grande</button>
```

### Insignias de Estado (`.lp-badge`, `.lp-status-dot`)

```html
<span class="lp-badge lp-badge-success">
  <span class="lp-status-dot"></span>Completado
</span>

<span class="lp-badge lp-badge-warning">
  <span class="lp-status-dot"></span>Pendiente
</span>

<span class="lp-badge lp-badge-error">
  <span class="lp-status-dot"></span>Requiere Ayuda
</span>

<span class="lp-badge lp-badge-info">
  <span class="lp-status-dot"></span>Al Día
</span>
```

### Tarjetas de Estadísticas (`.lp-stat-card`)

```html
<div class="lp-stat-card">
  <div class="lp-stat-card-icon">📊</div>
  <div>
    <p class="lp-stat-card-label">PROMEDIO PALABRAS/MIN</p>
    <h3 class="lp-stat-card-value">118 PML</h3>
  </div>
</div>
```

### Formulario e Inputs (`.lp-form-group`, `.lp-input`, `.lp-select`)

```html
<div class="lp-form-group">
  <label class="lp-label" for="student-search">Buscar Alumno</label>
  <input type="text" id="student-search" class="lp-input" placeholder="Nombre o RUT..." />
</div>

<div class="lp-form-group">
  <label class="lp-label" for="course-filter">Filtrar por Curso</label>
  <select id="course-filter" class="lp-select">
    <option value="">Todos los Cursos</option>
    <option value="3a">3° Básico A</option>
    <option value="4b">4° Básico B</option>
  </select>
</div>
```

### Tablas de Datos (`.lp-table`)

```html
<div class="lp-table-container">
  <table class="lp-table lp-table-comfortable">
    <thead>
      <tr>
        <th>Estudiante</th>
        <th>Curso</th>
        <th>Estado</th>
        <th>Fluidez (PML)</th>
        <th>Acción</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>
          <div style="display: flex; align-items: center; gap: 10px;">
            <div class="lp-avatar-wrapper">
              <div class="lp-avatar">MC</div>
              <span class="lp-avatar-indicator"></span>
            </div>
            <span>María Contrereas</span>
          </div>
        </td>
        <td><span class="lp-badge lp-badge-neutral">3° Básico A</span></td>
        <td><span class="lp-badge lp-badge-success"><span class="lp-status-dot"></span>Al Día</span></td>
        <td><strong>124 PML</strong></td>
        <td><button class="lp-btn lp-btn-ghost lp-btn-sm">Ver Detalle</button></td>
      </tr>
    </tbody>
  </table>
  
  <div class="lp-table-pagination">
    <span>Mostrando 1 de 10 estudiantes</span>
    <div>
      <button class="lp-btn lp-btn-outline lp-btn-sm">Anterior</button>
      <button class="lp-btn lp-btn-outline lp-btn-sm">Siguiente</button>
    </div>
  </div>
</div>
```
