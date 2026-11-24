// Capturas de tela das páginas (login, senhas, projetos, janelas) com o Supabase simulado: serve para olhar o design.
// Uso: node shots.mjs [pasta-de-saida]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT, launch, startServer } from "./lib.mjs";

const out = process.argv[2] || join(ROOT, "tests", "shots");
mkdirSync(out, { recursive: true });
const FAKE = readFileSync(join(ROOT, "tests", "fake-supabase.js"), "utf8");
const server = await startServer();
const br = await launch();

async function ctx(viewport, theme = "dark") {
  const c = await br.newContext({ viewport, deviceScaleFactor: 1 });
  await c.addInitScript({ content: FAKE });
  await c.addInitScript((t) => localStorage.setItem("cofre-theme", t), theme);
  await c.route("**/vendor/supabase-js-*.js", (r) => r.abort());
  return c;
}

try {
  // logo em PNG a partir do SVG
  {
    const c = await br.newContext({ viewport: { width: 512, height: 512 } });
    const p = await c.newPage();
    await p.goto(server.url + "/img/logo.svg");
    await p.screenshot({ path: join(ROOT, "img", "logo.png"), omitBackground: true });
    await c.close();
  }

  for (const [name, viewport, theme] of [["desktop", { width: 1440, height: 900 }, "dark"], ["mobile", { width: 390, height: 844 }, "dark"], ["claro", { width: 1440, height: 900 }, "light"]]) {
    const c = await ctx(viewport, theme);
    const p = await c.newPage();
    p.on("dialog", (d) => d.accept());
    await p.goto(server.url + "/index.html");
    await p.screenshot({ path: join(out, `${name}-1-login.png`) });
    await p.click("#tab-signup");
    await p.fill("#signup-email", "ana@exemplo.com");
    await p.fill("#signup-password", "Cavalo-Grampo-Bateria-9");
    await p.fill("#signup-password-confirm", "Cavalo-Grampo-Bateria-9");
    await p.screenshot({ path: join(out, `${name}-2-cadastro.png`) });
    await p.click("#signup-submit");
    await p.locator("#recovery-code-modal").waitFor({ state: "visible" });
    await p.screenshot({ path: join(out, `${name}-3-chave.png`) });
    await p.check("#recovery-code-confirm");
    await p.click("#recovery-code-continue");
    await p.waitForURL("**/vault.html");
    const items = [["Gmail", "ana@exemplo.com", "https://mail.google.com"], ["Netflix", "ana.silva", "https://www.netflix.com"], ["Sistema interno", "planejamento.operacional", ""], ["Painel do site", "admin", "https://painel.exemplo.com"], ["Banco", "12345-6", ""], ["Nuvem", "ana@exemplo.com", "https://nuvem.exemplo.com"]];
    for (const [title, user, url] of items) {
      await p.click("#btn-new-credential");
      await p.fill("#cred-title", title);
      await p.fill("#cred-username", user);
      await p.fill("#cred-password", "Pw-123456!");
      if (url) await p.fill("#cred-url", url);
      if (title === "Painel do site") await p.screenshot({ path: join(out, `${name}-5-modal-credencial.png`) });
      await p.click("#btn-save-credential");
      await p.locator("#credential-modal").waitFor({ state: "hidden" });
    }
    await p.screenshot({ path: join(out, `${name}-4-senhas.png`) });
    await p.click("#account-menu-trigger");
    await p.screenshot({ path: join(out, `${name}-6-menu.png`) });
    await p.keyboard.press("Escape");
    await p.click("#account-menu-trigger").catch(() => {});
    await p.locator('a[data-nav][href="projects.html"]').click();
    await p.waitForURL("**/projects.html");
    await p.locator("#btn-new-project").waitFor();
    await p.screenshot({ path: join(out, `${name}-7-projetos-vazio.png`) });
    for (const [n, d] of [["Gerenciador de Senhas", "Cofre de senhas com Supabase"], ["Site pessoal", "Portfólio estático"]]) {
      await p.click("#btn-new-project");
      await p.fill('#project-body .field:has-text("Nome do projeto") input', n);
      await p.fill('#project-body .field:has-text("Descrição") textarea', d);
      if (n.startsWith("Gerenc")) await p.screenshot({ path: join(out, `${name}-8-projeto-editor.png`) });
      await p.click("#btn-save-project");
      await p.locator("#project-modal").waitFor({ state: "hidden" });
    }
    await p.screenshot({ path: join(out, `${name}-9-projetos.png`) });
    await p.click("#account-menu-trigger");
    await p.click("#btn-lock-now");
    await p.locator("#lock-overlay").waitFor({ state: "visible" });
    await p.screenshot({ path: join(out, `${name}-10-bloqueado.png`) });
    await c.close();
    if (name === "mobile" || name === "claro") continue;
  }
  console.log("capturas em", out);
} finally {
  await br.close();
  await server.close();
}
