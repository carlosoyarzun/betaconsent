// Gobierna: ADR-001 rev. 8 §3 (CSP: `script-src`/`style-src 'self'`, sin scripts ni estilos inline) y F1
// (React + TypeScript, SPA estática servida por el backend; decisión de Carlos 2026-10-18, fase A).
// CSP ÚNICA de toda respuesta HTML del proceso web (SSR del invitado, SPA, consola staff y consola dev):
// ninguna página puede traer <style>, style="" ni <script> inline. Este archivo es la única fuente del texto.

export const HTML_CONTENT_SECURITY_POLICY =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
