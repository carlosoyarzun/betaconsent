// Gobierna: ADR-001 rev. 8 §3 (CSP: `script-src`/`style-src 'self'`, sin scripts ni estilos inline) y F1
// (React + TypeScript, SPA estática servida por el backend; decisión de Carlos 2026-10-18, fase A).
// CSP ÚNICA de toda respuesta HTML del proceso web (SSR del invitado, SPA, consola staff y consola dev):
// ninguna página puede traer <style>, style="" ni <script> inline. Este archivo es la única fuente del texto.

export const HTML_CONTENT_SECURITY_POLICY =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/** SEC-UI-1: consola staff y consola dev no ejecutan JS; misma base que la CSP única pero `script-src 'none'`, para que una
 * inyección de HTML (datos de roster) no pueda cargar welcome.js ni el bundle de la SPA del mismo origen. */
export const STAFF_HTML_CONTENT_SECURITY_POLICY = HTML_CONTENT_SECURITY_POLICY.replace("script-src 'self'", "script-src 'none'");
