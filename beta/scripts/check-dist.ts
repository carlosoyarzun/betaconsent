// Gobierna: plan de reconstrucción mínima H1-10 (DEC "Reconstrucción mínima", 2026-10-19); criterio CSP sin inline de
// ADR-001 §3. Uso: node scripts/check-dist.ts (tras `npm run build:frontend`). Chequeo propio: no importa tools/ ni src/.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const DIST = resolve(import.meta.dirname, "..", "dist");
const fail: string[] = [];
const read = (p: string): string => readFileSync(join(DIST, p), "utf8");

if (!existsSync(join(DIST, ".vite", "manifest.json"))) fail.push("falta dist/.vite/manifest.json");
if (!existsSync(join(DIST, "index.html"))) fail.push("falta dist/index.html");
else {
  const html = read("index.html");
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (!/\bsrc\s*=/.test(m[1] ?? "") || (m[2] ?? "").trim() !== "") fail.push("index.html: <script> inline");
  }
  if (/<style\b/i.test(html)) fail.push("index.html: <style> inline");
  if (/\sstyle\s*=/i.test(html)) fail.push("index.html: atributo style=");
  if (/\son[a-z]+\s*=/i.test(html)) fail.push("index.html: manejador on*=");
  for (const m of html.matchAll(/\b(?:src|href)="([^"]+)"/g)) {
    const ref = m[1] ?? "";
    if (/^(?:https?:)?\/\//.test(ref)) fail.push(`index.html: recurso remoto ${ref}`);
    else if (ref.startsWith("/assets/") && !existsSync(join(DIST, ref))) fail.push(`index.html: asset inexistente ${ref}`);
  }
}
const assets = existsSync(join(DIST, "assets")) ? readdirSync(join(DIST, "assets")) : [];
if (assets.length === 0) fail.push("dist/assets vacío");
for (const n of assets) {
  if (!/-[A-Za-z0-9_-]{6,}\.[a-z0-9]+$/.test(n)) fail.push(`asset sin hash: ${n}`);
  if (n.endsWith(".css")) {
    const css = read(join("assets", n));
    if (/@import\s+(?:url\()?\s*["']?(?:https?:)?\/\//i.test(css)) fail.push(`${n}: @import remoto`);
    if (/url\(\s*["']?data:/i.test(css)) fail.push(`${n}: asset embebido data:`);
  }
}
if (fail.length > 0) {
  console.error(`[check-dist] FALLÓ (${fail.length}):\n${fail.map((f) => `  - ${f}`).join("\n")}`);
  process.exit(1);
}
console.log(`[check-dist] OK — manifest presente, index.html sin inline, ${assets.length} asset(s) con hash.`);
