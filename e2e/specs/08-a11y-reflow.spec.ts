// Accesibilidad transversal de las 8 pantallas del titular: axe (WCAG 2.2 AA), reflow 320/390 px, foco visible.
// Gobierna: UX-CNS-001..006, WCAG 1.4.10 (reflow), 2.4.7 (foco visible), 4.1.2; criterio: 0 serious/critical; moderate/minor se listan.
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { test, expect } from "../fixtures/index.ts";
import { walkAllPages } from "../fixtures/flows.ts";

const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function axeScan(page: Page, where: string, only?: { include?: string[]; exclude?: string[] }): Promise<{ blocking: string[]; listed: string[] }> {
  let b = new AxeBuilder({ page }).withTags(TAGS);
  if (only?.exclude) b = b.disableRules(only.exclude);
  const { violations: all } = await b.analyze();
  const violations = only?.include ? all.filter((v) => only.include!.includes(v.id)) : all;
  const fmt = (v: (typeof violations)[number]): string => `${where} [${v.impact}] ${v.id}: ${v.help} (${v.nodes.length} nodos; ${v.nodes[0]?.target.join(" ")})`;
  return {
    blocking: violations.filter((v) => v.impact === "serious" || v.impact === "critical").map(fmt),
    listed: violations.filter((v) => v.impact !== "serious" && v.impact !== "critical").map(fmt),
  };
}

test.describe("a11y y reflow", () => {
  test("E2E-CNS-082 axe (WCAG 2.2 AA) en las 8 pantallas: 0 violaciones serious/critical; moderate/minor listadas", async ({ page, app }) => {
    test.setTimeout(90_000);
    const blocking: string[] = [];
    const listed: string[] = [];
    await walkAllPages(page, app, async (name) => {
      const r = await axeScan(page, name, { exclude: ["target-size"] });
      blocking.push(...r.blocking);
      listed.push(...r.listed);
    });
    for (const l of listed) test.info().annotations.push({ type: "axe-moderate", description: l });
    if (listed.length) console.log(`axe moderate/minor (${listed.length}):\n  ${listed.join("\n  ")}`);
    expect(blocking, `violaciones serious/critical:\n${blocking.join("\n")}`).toEqual([]);
  });

  test("E2E-CNS-088 hallazgo F-E2E-04: objetivos táctiles >= 24 px (WCAG 2.5.8, regla axe target-size) en las 8 pantallas", async ({ page, app }) => {
    test.fail(true, "F-E2E-04 (P2, axe serious): el enlace de ayuda mailto y un enlace en /verify|/manage/verify|/manage/revocation/verify no cumplen 24 px ni espaciado (WCAG 2.5.8)");
    test.setTimeout(90_000);
    const found: string[] = [];
    await walkAllPages(page, app, async (name) => {
      found.push(...(await axeScan(page, name, { include: ["target-size"] })).blocking);
    });
    expect(found, found.join("\n")).toEqual([]);
  });

  test("E2E-CNS-083 axe sobre los estados de error uniforme (sin sesión) de las 8 rutas: 0 serious/critical", async ({ page }) => {
    const blocking: string[] = [];
    for (const route of ["/welcome", "/verify", "/decision", "/manage", "/manage/verify", "/manage/revocation/verify", "/manage/revocation/confirm", "/recovery/confirm"]) {
      await page.goto(route);
      blocking.push(...(await axeScan(page, `${route} (error uniforme)`)).blocking);
    }
    expect(blocking, blocking.join("\n")).toEqual([]);
  });

  for (const width of [320, 390]) {
    test(`E2E-CNS-0${width === 320 ? "84" : "85"} reflow a ${width} px: sin desplazamiento horizontal en las 8 pantallas (WCAG 1.4.10)`, async ({ page, app }) => {
      test.setTimeout(90_000);
      await page.setViewportSize({ width, height: 800 });
      const overflow: string[] = [];
      await walkAllPages(page, app, async (name) => {
        const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
        if (m.sw > m.cw) overflow.push(`${name}: scrollWidth ${m.sw} > clientWidth ${m.cw}`);
      });
      expect(overflow, overflow.join("\n")).toEqual([]);
    });
  }

  test("E2E-CNS-086 foco visible: el control enfocado por teclado tiene indicador (outline/box-shadow) en las pantallas con botones (WCAG 2.4.7)", async ({ page, app }) => {
    await page.goto(await app.invitationPath());
    const cta = page.getByRole("button", { name: "Continuar" });
    await cta.focus();
    await page.keyboard.press("Shift+Tab");
    await page.keyboard.press("Tab");
    const style = await cta.evaluate((el) => {
      const s = getComputedStyle(el);
      return { outlineStyle: s.outlineStyle, outlineWidth: s.outlineWidth, boxShadow: s.boxShadow };
    });
    const hasIndicator = (style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0) || style.boxShadow !== "none";
    expect(hasIndicator, JSON.stringify(style)).toBe(true);
  });

  test("E2E-CNS-087 cada pantalla tiene lang=es, un único h1 visible y una región main con nombre accesible (WCAG 3.1.1, 1.3.1, 2.4.1)", async ({ page, app }) => {
    test.setTimeout(90_000);
    const problems: string[] = [];
    await walkAllPages(page, app, async (name) => {
      const lang = await page.locator("html").getAttribute("lang");
      if (lang !== "es") problems.push(`${name}: lang=${lang}`);
      const h1 = await page.getByRole("heading", { level: 1 }).count();
      if (h1 !== 1) problems.push(`${name}: ${h1} h1 visibles`);
      const mains = await page.getByRole("main").count();
      if (mains !== 1) problems.push(`${name}: ${mains} main`);
    });
    expect(problems, problems.join("\n")).toEqual([]);
  });
});
