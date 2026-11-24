// Testes do "manter desbloqueado ao recarregar" e do bloqueio automático de 3 horas (relógio simulado).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT, done, launch, ok, startServer, until } from "./lib.mjs";

const FAKE = readFileSync(join(ROOT, "tests", "fake-supabase.js"), "utf8");
const MASTER = "Cavalo-Grampo-Bateria-9";

console.log("\n== Desbloqueio: recarregar (F5) e bloqueio de 3 horas");
const server = await startServer({ KEEP_UNLOCKED: true, AUTO_LOCK_MINUTES: 180 });
const br = await launch();

const hasStoredKey = (page) => page.evaluate(() => new Promise((resolve) => {
  const open = indexedDB.open("cofre-handoff", 1);
  open.onsuccess = () => {
    const get = open.result.transaction("h").objectStore("h").get("r");
    get.onsuccess = () => resolve(!!get.result);
    get.onerror = () => resolve(false);
  };
  open.onerror = () => resolve(false);
}));
const expireStoredKey = (page) => page.evaluate(() => new Promise((resolve) => {
  const open = indexedDB.open("cofre-handoff", 1);
  open.onsuccess = () => {
    const tx = open.result.transaction("h", "readwrite");
    const store = tx.objectStore("h");
    const get = store.get("r");
    get.onsuccess = () => { store.put({ ...get.result, expiresAt: Date.now() - 1000 }, "r"); };
    tx.oncomplete = () => resolve(true);
  };
}));
const cards = (page) => page.locator(".cred-card__title").allInnerTexts();

try {
  const ctx = await br.newContext({ viewport: { width: 1100, height: 800 } });
  await ctx.addInitScript({ content: FAKE });
  await ctx.route("**/vendor/supabase-js-*.js", (r) => r.abort());
  const page = await ctx.newPage();
  page.on("dialog", (d) => d.accept());

  await page.goto(server.url + "/index.html");
  await page.click("#tab-signup");
  await page.fill("#signup-email", "ana@exemplo.com");
  await page.fill("#signup-password", MASTER);
  await page.fill("#signup-password-confirm", MASTER);
  await page.click("#signup-submit");
  await page.locator("#recovery-code-modal").waitFor({ state: "visible" });
  await page.check("#recovery-code-confirm");
  await page.click("#recovery-code-continue");
  await page.waitForURL("**/vault.html");
  await page.click("#btn-new-credential");
  await page.fill("#cred-title", "Gmail");
  await page.fill("#cred-username", "ana");
  await page.fill("#cred-password", "Pw-123456!");
  await page.click("#btn-save-credential");
  await page.locator("#credential-modal").waitFor({ state: "hidden" });

  ok(await hasStoredKey(page), "depois de entrar, a chave (não exportável) fica guardada só para sobreviver ao F5");
  await page.reload();
  await page.locator(".cred-card").first().waitFor({ timeout: 10000 });
  ok(!(await page.locator("#lock-overlay").isVisible()) && (await cards(page)).includes("Gmail"), "atualizar a página NÃO bloqueia: a lista volta aberta, sem pedir a senha mestra");
  await page.reload();
  await page.reload();
  ok(!(await page.locator("#lock-overlay").isVisible()), "e continua aberto em várias atualizações seguidas");

  // outra página do app também abre sem pedir a senha
  await page.locator('a[data-nav][href="projects.html"]').click();
  await page.waitForURL("**/projects.html");
  await page.reload();
  await page.locator("#btn-new-project").waitFor();
  ok(!(await page.locator("#lock-overlay").isVisible()), "em Projetos, atualizar a página também não bloqueia");
  await page.locator('a[data-nav][href="vault.html"]').click();
  await page.waitForURL("**/vault.html");

  // bloquear agora: apaga a chave guardada, e o F5 não desbloqueia
  await page.click("#account-menu-trigger");
  await page.click("#btn-lock-now");
  await page.locator("#lock-overlay").waitFor({ state: "visible" });
  ok(await until(async () => !(await hasStoredKey(page))), "Bloquear agora apaga a chave guardada");
  await page.reload();
  await page.locator("#lock-overlay").waitFor({ state: "visible" });
  ok(true, "depois de bloquear manualmente, atualizar a página continua pedindo a senha mestra");
  await page.fill("#unlock-password", MASTER);
  await page.press("#unlock-password", "Enter");
  await page.locator(".cred-card").first().waitFor();
  ok(await hasStoredKey(page), "desbloquear de novo guarda a chave outra vez");

  // chave vencida: o F5 pede a senha
  await expireStoredKey(page);
  await page.reload();
  await page.locator("#lock-overlay").waitFor({ state: "visible" });
  ok(true, "se a validade da chave guardada vencer, atualizar a página volta a pedir a senha mestra");
  await page.fill("#unlock-password", MASTER);
  await page.press("#unlock-password", "Enter");
  await page.locator(".cred-card").first().waitFor();

  // sair apaga a chave
  await page.click("#account-menu-trigger");
  await page.click("#btn-logout");
  await page.waitForURL("**/index.html");
  ok(await until(async () => !(await hasStoredKey(page))), "Sair apaga a chave guardada");
  await ctx.close();

  // bloqueio por inatividade: 3 horas (relógio simulado)
  {
    const c2 = await br.newContext({ viewport: { width: 1100, height: 800 } });
    await c2.addInitScript({ content: FAKE });
    await c2.route("**/vendor/supabase-js-*.js", (r) => r.abort());
    const p2 = await c2.newPage();
    await p2.clock.install();
    await p2.goto(server.url + "/index.html");
    await p2.click("#tab-signup");
    await p2.fill("#signup-email", "bia@exemplo.com");
    await p2.fill("#signup-password", MASTER);
    await p2.fill("#signup-password-confirm", MASTER);
    await p2.click("#signup-submit");
    await p2.locator("#recovery-code-modal").waitFor({ state: "visible" });
    await p2.check("#recovery-code-confirm");
    await p2.click("#recovery-code-continue");
    await p2.waitForURL("**/vault.html");
    await p2.locator(".empty-state, .cred-card").first().waitFor({ state: "attached" });
    await p2.clock.fastForward("00:30:00");
    await p2.clock.fastForward("00:30:00");
    await p2.clock.fastForward("01:30:00");
    ok(!(await p2.locator("#lock-overlay").isVisible()), "depois de 2h30 sem mexer, o cofre continua aberto (não bloqueia a cada poucos minutos)");
    await p2.clock.fastForward("00:40:00");
    ok(await until(async () => await p2.locator("#lock-overlay").isVisible(), 4000), "passadas 3 horas sem atividade, o cofre bloqueia sozinho");
    ok((await p2.evaluate(() => VaultSession.key)) === null, "e a chave sai da memória");
    await c2.close();
  }
} finally {
  await br.close();
  await server.close();
}
done("Desbloqueio");
