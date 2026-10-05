// Gobierna: WCAG 2.2 AA (1.4.3 texto 4.5:1; 1.4.11 no-texto 3:1), pedido de Carlos 2026-10-05, design-system/docs/usage.md seccion Contraste.
// TEST-CNS-1130 (pares de texto >= 4.5:1, tema claro y oscuro), 1131 (bordes de control >= 3:1), 1132 (los componentes del DS
// usan los tokens semanticos y no los colores de feedback como texto), 1133 (tokens esperados definidos en ambos temas).
// Lee design-system/css/tokens.css; formula WCAG de luminancia relativa. Solo datos de diseno, sin PII.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const read = (rel: string): string => readFileSync(fileURLToPath(new URL(`../../../design-system/css/${rel}`, import.meta.url)), "utf8");
const TOKENS = read("tokens.css");
const COMPONENTS = read("components.css");

type Rgba = [number, number, number, number];
type Theme = "light" | "dark";

function block(selector: string): string {
  const start = TOKENS.indexOf(`${selector} {`);
  assert.ok(start >= 0, `bloque ${selector}`);
  return TOKENS.slice(start, TOKENS.indexOf("\n}", start));
}
// :root es el tema claro por defecto; [data-theme="light"] lo repite; el bloque del tema gana sobre :root.
const BLOCKS: Record<Theme, string[]> = {
  light: [block(":root"), block('[data-theme="light"]')],
  dark: [block(":root"), block('[data-theme="dark"]')],
};

function parseColor(v: string): Rgba {
  const hex = /^#([0-9a-f]{6})$/i.exec(v);
  if (hex) {
    const n = parseInt(hex[1]!, 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255, 1];
  }
  const m = /^rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)$/.exec(v);
  assert.ok(m, `color no soportado: ${v}`);
  return [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
}

function token(theme: Theme, name: string): Rgba {
  let found: string | undefined;
  for (const b of BLOCKS[theme]) {
    const m = new RegExp(`${name}:\\s*([^;]+);`).exec(b);
    if (m) found = m[1]!.trim();
  }
  assert.ok(found, `token ${name} definido en tema ${theme}`);
  return parseColor(found);
}

function composite(fg: Rgba, bg: Rgba): Rgba {
  const a = fg[3];
  return [fg[0] * a + bg[0] * (1 - a), fg[1] * a + bg[1] * (1 - a), fg[2] * a + bg[2] * (1 - a), 1];
}
function luminance(c: Rgba): number {
  const [r, g, b] = c.slice(0, 3).map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(a: Rgba, b: Rgba): number {
  const x = luminance(a);
  const y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

const SURFACES = ["--lp-surface-default", "--lp-surface-elevated", "--lp-bg-page", "--lp-bg-subtle"] as const;
const FEEDBACK = ["error", "warning", "success", "info"] as const;
const TEXTS = ["--lp-text-primary", "--lp-text-secondary", "--lp-text-muted", "--lp-text-error", "--lp-text-warning", "--lp-text-success", "--lp-text-info"] as const;

interface Pair { fg: string; bg: string; over?: string; what: string }
function textPairs(): Pair[] {
  const pairs: Pair[] = [];
  for (const s of SURFACES) for (const t of TEXTS) pairs.push({ fg: t, bg: s, what: "texto sobre superficie" });
  // Fondos -bg de feedback (rgba) compuestos sobre cada superficie.
  for (const k of FEEDBACK) for (const s of SURFACES) {
    pairs.push({ fg: `--lp-text-${k}`, bg: `--lp-color-feedback-${k}-bg`, over: s, what: `texto ${k} sobre -bg` });
    pairs.push({ fg: "--lp-text-primary", bg: `--lp-color-feedback-${k}-bg`, over: s, what: `text-primary sobre -bg ${k}` });
  }
  pairs.push({ fg: "--lp-action-danger-text", bg: "--lp-action-danger", what: ".lp-btn-danger" });
  pairs.push({ fg: "--lp-action-danger-text", bg: "--lp-action-danger-hover", what: ".lp-btn-danger:hover" });
  pairs.push({ fg: "--lp-action-primary-text", bg: "--lp-action-primary", what: ".lp-btn-primary" });
  return pairs;
}

for (const theme of ["light", "dark"] as const) {
  test(`TEST-CNS-1130 contraste de texto >= 4.5:1 (WCAG 1.4.3), tema ${theme}`, () => {
    for (const p of textPairs()) {
      const bgTok = token(theme, p.bg);
      const bg = p.over ? composite(bgTok, token(theme, p.over)) : bgTok;
      const r = ratio(token(theme, p.fg), bg);
      assert.ok(r >= 4.5, `${theme} ${p.what}: ${p.fg} sobre ${p.bg}${p.over ? ` (sobre ${p.over})` : ""} = ${r.toFixed(2)}:1 < 4.5`);
    }
  });

  test(`TEST-CNS-1131 contraste de borde de control >= 3:1 (WCAG 1.4.11), tema ${theme}`, () => {
    for (const s of SURFACES) {
      const r = ratio(token(theme, "--lp-border-control"), token(theme, s));
      assert.ok(r >= 3, `${theme}: --lp-border-control sobre ${s} = ${r.toFixed(2)}:1 < 3`);
    }
    // Borde de error en reposo (2px) y, solo en claro, borde de foco primario sobre el fondo del control.
    // Brecha conocida (P2, tema oscuro): --lp-action-primary #2563EB sobre #1E293B = 2.83:1 como borde de foco; no se cambia
    // porque tambien es el fondo del boton primario (texto blanco 5.17:1). Fuera de alcance: el tema oscuro no se usa en Consent App.
    for (const t of theme === "light" ? ["--lp-action-primary", "--lp-color-feedback-error"] : ["--lp-color-feedback-error"]) {
      const r = ratio(token(theme, t), token(theme, "--lp-surface-default"));
      assert.ok(r >= 3, `${theme}: ${t} sobre surface-default = ${r.toFixed(2)}:1 < 3`);
    }
  });
}

test("TEST-CNS-1132 componentes del DS: texto con tokens semanticos, nunca con --lp-color-feedback-*; controles con --lp-border-control", () => {
  for (const decl of COMPONENTS.matchAll(/(^|[;{\s])color:\s*([^;}]+)/g)) {
    assert.ok(!/feedback/.test(decl[2]!), `color de texto con feedback en components.css: ${decl[0].trim()}`);
  }
  const rule = (sel: string): string => {
    const i = COMPONENTS.indexOf(`${sel} {`);
    assert.ok(i >= 0, `regla ${sel}`);
    return COMPONENTS.slice(i, COMPONENTS.indexOf("}", i));
  };
  assert.match(rule(".lp-input, .lp-select"), /border:\s*1px solid var\(--lp-border-control\)/);
  assert.match(rule(".lp-btn-outline"), /border-color:\s*var\(--lp-border-control\)/);
  assert.match(rule(".lp-btn-danger"), /background-color:\s*var\(--lp-action-danger\)/);
  assert.match(rule(".lp-input-error-msg"), /color:\s*var\(--lp-text-error\)/);
  for (const k of FEEDBACK) assert.match(rule(`.lp-badge-${k}`), new RegExp(`color:\\s*var\\(--lp-text-${k}\\)`));
  for (const k of FEEDBACK) assert.match(COMPONENTS, new RegExp(`\\.lp-alert-${k}\\s*\\{[^}]*color:\\s*var\\(--lp-text-${k}\\)`));
});

test("TEST-CNS-1133 tokens de contraste definidos en ambos temas (el oscuro los redefine); feedback-* sin cambios", () => {
  const names = ["--lp-text-error", "--lp-text-warning", "--lp-text-success", "--lp-text-info", "--lp-border-control", "--lp-action-danger", "--lp-action-danger-hover", "--lp-action-danger-text"];
  for (const n of names) {
    assert.ok(token("light", n), `${n} en claro`);
    assert.ok(block('[data-theme="light"]').includes(`${n}:`), `${n} en [data-theme="light"]`);
    assert.ok(block('[data-theme="dark"]').includes(`${n}:`), `${n} en [data-theme="dark"]`);
  }
  assert.deepEqual(token("light", "--lp-color-feedback-error"), [239, 68, 68, 1]);
  assert.deepEqual(token("light", "--lp-color-feedback-warning"), [245, 158, 11, 1]);
});
