// Gobierna: ADR-001 rev. 8 §3 (CSP: `script-src`/`style-src 'self'`, sin scripts ni estilos inline) y F1
// (React + TypeScript, SPA estática servida por el backend; decisión de Carlos 2026-10-18, fase A).
// CSP ÚNICA de toda respuesta HTML del proceso web (SSR del invitado, SPA, consola staff y consola dev):
// ninguna página puede traer <style>, style="" ni <script> inline. Este archivo es la única fuente del texto.

export const HTML_CONTENT_SECURITY_POLICY =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

// F-E2E-02: todo HTML de titulares (SSR, SPA y consola dev) lleva `nosniff` (la consola staff ya lo traía en su propio
// mapa de cabeceras). Valor único para que ninguna ruta lo omita.
export const HTML_X_CONTENT_TYPE_OPTIONS = "nosniff";
