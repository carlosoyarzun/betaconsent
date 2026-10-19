// origen: src/server/entrypoints/http/dist-validation.ts@9345b78 (sin cambios de lógica).
// (Movido desde tools/guardrails/dist-csp.ts; SEC-UI R2: lo usan el CLI de CI y el arranque del web en modo spa.)
// Gobierna: ADR-001 rev. 8 F1 y §3 (CSP script-src/style-src 'self', sin scripts ni estilos inline). Lógica pura que
// valida el build de la SPA (dist/): index.html sin <style>, style="", handlers on*=, <script> inline, ni data:/javascript:
// en scripts; todo script/hoja referenciado es un archivo local bajo /assets/ y existe en el build.

export interface DistFiles {
  readonly indexHtml: string;
  /** Rutas `/assets/<archivo>` presentes en dist/assets/. */
  readonly assetPaths: ReadonlySet<string>;
  /** Contenido de los .css del build (para detectar @import remotos). */
  readonly cssContents: readonly string[];
}

export function checkDist(dist: DistFiles): string[] {
  const v: string[] = [];
  const html = dist.indexHtml;
  if (/<style[\s>]/i.test(html)) v.push("index.html contiene <style> inline");
  if (/\sstyle\s*=/i.test(html)) v.push('index.html contiene atributos style="" inline');
  if (/\son[a-z]+\s*=/i.test(html)) v.push("index.html contiene manejadores on*= inline");
  if (/href\s*=\s*["']?\s*javascript:/i.test(html)) v.push("index.html contiene URLs javascript:");
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attrs = m[1] ?? "";
    const body = (m[2] ?? "").trim();
    const src = /\ssrc\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1];
    if (!src) v.push("index.html contiene <script> inline (sin src)");
    else if (body) v.push(`<script src="${src}"> con cuerpo inline`);
  }
  const refs = [...html.matchAll(/<(?:script|link)\b[^>]*?\s(?:src|href)\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1] as string);
  for (const ref of refs) {
    if (!ref.startsWith("/assets/")) v.push(`referencia fuera de /assets/: ${ref}`);
    else if (!dist.assetPaths.has(ref)) v.push(`referencia a un asset que no existe en el build: ${ref}`);
  }
  if (!/<script\b[^>]*\ssrc=/i.test(html)) v.push("index.html no referencia ningún script del bundle");
  if (!/<meta\s+name="cns-page-state"\s+content="ready"\s*>/i.test(html)) v.push('index.html no contiene <meta name="cns-page-state" content="ready">');
  for (const css of dist.cssContents) {
    if (/@import\s+(?:url\()?\s*["']?(?:https?:)?\/\//i.test(css)) v.push("un .css del build importa recursos remotos");
  }
  return v;
}
