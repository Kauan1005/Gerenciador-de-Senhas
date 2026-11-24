// Testes de ponta a ponta no navegador (sem tocar no seu Supabase: usa o simulado de tests/fake-supabase.js),
// servindo o site com os mesmos cabeçalhos de segurança (CSP) do Netlify.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { FAKE_HOST, ROOT, done, launch, ok, startServer, until } from "./lib.mjs";

const C = createRequire(import.meta.url)("../js/crypto.js");
const FAKE = readFileSync(join(ROOT, "tests", "fake-supabase.js"), "utf8");
const MASTER = "Cavalo-Grampo-Bateria-9";
const EMAIL = "teste@exemplo.com";

console.log("\n== Cofre: ponta a ponta");
const server = await startServer();
const br = await launch();
const cspErrors = [];
const foreignRequests = [];

/** Contexto novo (localStorage próprio = banco simulado próprio). seed = conteúdo inicial do "banco". */
async function open({ seed = null, viewport = { width: 1100, height: 800 } } = {}) {
  const ctx = await br.newContext({ viewport, acceptDownloads: true });
  await ctx.addInitScript({ content: FAKE });
  if (seed) await ctx.addInitScript((s) => { if (!localStorage.getItem("__fakedb")) localStorage.setItem("__fakedb", JSON.stringify(s)); }, seed);
  await ctx.route("**/vendor/supabase-js-*.js", (r) => r.abort()); // o simulado substitui a biblioteca real
  const page = await ctx.newPage();
  page.on("console", (m) => { if (m.type() === "error" && /Content Security Policy/i.test(m.text())) cspErrors.push(m.text().slice(0, 160)); });
  page.on("request", (r) => { const u = new URL(r.url()); if (!u.href.startsWith(server.url) && u.protocol.startsWith("http")) foreignRequests.push(u.host); });
  page.on("dialog", (d) => d.accept());
  return { ctx, page };
}

const db = (page) => page.evaluate(() => JSON.parse(localStorage.getItem("__fakedb")));
const setDb = (page, fn) => page.evaluate((src) => { const d = JSON.parse(localStorage.getItem("__fakedb")); new Function("d", src)(d); localStorage.setItem("__fakedb", JSON.stringify(d)); }, fn.toString().replace(/^[^{]*\{|\}$/g, ""));
const toast = (page) => page.locator("#toast").innerText().catch(() => "");

let lastRecovery = "";
let modalChecked = false;
// A tela de cadastro mostra a chave de recuperação e só segue depois de a pessoa confirmar que guardou.
async function confirmRecovery(page) {
  await page.locator("#recovery-code-modal").waitFor({ state: "visible" });
  const code = (await page.locator("#recovery-code-display").innerText()).trim();
  if (!modalChecked) {
    modalChecked = true;
    ok(await page.locator("#recovery-code-continue").isDisabled(), "cadastro: o botão Continuar só libera depois de confirmar que a chave de recuperação foi guardada");
  }
  await page.check("#recovery-code-confirm");
  await page.click("#recovery-code-continue");
  return code;
}
async function signup(page, email = EMAIL, pw = MASTER) {
  await page.goto(server.url + "/index.html");
  await page.click("#tab-signup");
  await page.fill("#signup-email", email);
  await page.fill("#signup-password", pw);
  await page.fill("#signup-password-confirm", pw);
  await page.click("#signup-submit");
  lastRecovery = await confirmRecovery(page);
  await page.waitForURL("**/vault.html");
}
async function login(page, email = EMAIL, pw = MASTER) {
  await page.goto(server.url + "/index.html");
  await page.fill("#login-email", email);
  await page.fill("#login-password", pw);
  await page.click("#login-submit");
  await page.waitForURL("**/vault.html");
}
async function unlock(page, pw = MASTER) {
  await page.locator("#lock-overlay").waitFor({ state: "visible" });
  await page.fill("#unlock-password", pw);
  await page.press("#unlock-password", "Enter");
}
async function addCredential(page, c) {
  await page.click("#btn-new-credential");
  await page.fill("#cred-title", c.title);
  await page.fill("#cred-username", c.username || "user");
  await page.fill("#cred-password", c.password || "Pw-123456!");
  if (c.url) await page.fill("#cred-url", c.url);
  await page.click("#btn-save-credential");
  await page.locator("#credential-modal").waitFor({ state: "hidden" });
}
const fld = (scope, label) => scope.locator(".field", { has: scope.page().locator(".field__label", { hasText: new RegExp("^" + label) }) }).locator("input, textarea, select").first();
const cards = (page) => page.locator(".cred-card__title").allInnerTexts();
const menu = async (page, id) => { await page.click("#account-menu-trigger"); await page.click("#" + id); };

/** Monta uma conta ANTIGA no formato real do banco do dono: DEK embrulhada pela senha mestra e pela chave de recuperação,
 *  senha do Supabase = senha mestra, itens sem AAD (versão 1). */
async function legacyAccount({ schema, items, iterations = 150000 }) {
  const userId = crypto.randomUUID();
  const salt = C.generateSaltBase64();
  const kek = await C.deriveKey(MASTER, salt, iterations);
  const dekBuf = C.generateDEK();
  const dek = await C.importRawAesKey(dekBuf, false);
  const own = await C.wrapBytes(kek, dekBuf);
  const recoveryCode = C.generateRecoveryCode();
  const rec = await C.wrapBytes(await C.importRawAesKey(C.recoveryCodeToKeyBytes(recoveryCode), false), dekBuf);
  const rows = [];
  for (const it of items) {
    const enc = await C.encryptJSON(dek, it); // v1: sem AAD
    const row = { id: crypto.randomUUID(), user_id: userId, encrypted_data: enc.ciphertext, iv: enc.iv, created_at: new Date().toISOString() };
    if (schema.itemVersion) { row.version = 1; row.updated_at = row.created_at; }
    rows.push(row);
  }
  const cfg = { user_id: userId, salt, kdf_iterations: iterations, wrapped_dek: own.wrapped, wrapped_dek_iv: own.iv, recovery_wrapped_dek: rec.wrapped, recovery_wrapped_dek_iv: rec.iv, created_at: new Date().toISOString() };
  if (schema.authVersion) cfg.auth_version = 1;
  return { users: [{ id: userId, email: EMAIL, password: MASTER }], tables: { vault_config: [cfg], vault_items: rows, vault_projects: [] }, schema, flags: {}, passwordsSeen: [], recoveryCode };
}

try {
  // ================= 1) cadastro novo (v2): a senha mestra nunca chega ao servidor
  {
    const { ctx, page } = await open();
    const res = await page.goto(server.url + "/index.html");
    const h = res.headers();
    ok(/default-src 'none'/.test(h["content-security-policy"] || "") && h["x-frame-options"] === "DENY" && h["x-content-type-options"] === "nosniff" && h["referrer-policy"] === "no-referrer", "o site responde com CSP, X-Frame-Options, nosniff e Referrer-Policy");
    ok(!(h["content-security-policy"] || "").includes("__SUPABASE_HOST__") && (h["content-security-policy"] || "").includes(`connect-src 'self' https://${FAKE_HOST}`), "a CSP só deixa falar com o próprio site e com o Supabase");
    await signup(page);
    const d = await db(page);
    ok(!d.passwordsSeen.includes(MASTER) && d.users[0].password !== MASTER && d.users[0].password.length === 44, "cadastro: o servidor recebeu um segredo derivado, NUNCA a senha mestra");
    ok(!(await page.locator("#lock-overlay").isVisible()), "depois do cadastro o cofre abre direto (a chave passa à próxima página, sem pedir a senha duas vezes)");
    ok(d.tables.vault_config[0].auth_version === 2, "o cofre novo já nasce no login v2");
    const cfg0 = d.tables.vault_config[0];
    ok(/^([0-9A-F]{4}-){15}[0-9A-F]{4}$/.test(lastRecovery) && cfg0.wrapped_dek && cfg0.recovery_wrapped_dek && !JSON.stringify(d).includes(lastRecovery), "cadastro: a chave de recuperação é mostrada uma vez; o servidor guarda só a chave do cofre embrulhada, nunca a chave em texto");

    await addCredential(page, { title: "Gmail pessoal", username: "kauan@exemplo.com", password: "Sup3r-Segredo-Gmail!", url: "https://mail.google.com" });
    ok((await cards(page)).includes("Gmail pessoal"), "a credencial aparece na lista");
    const d2 = await db(page);
    const raw = JSON.stringify(d2.tables);
    ok(d2.tables.vault_items[0].version === 2 && !raw.includes("Gmail") && !raw.includes("Sup3r-Segredo") && !raw.includes("kauan@exemplo"), "no servidor só há blobs cifrados (versão 2), sem texto puro");

    await page.reload();
    await page.locator("#lock-overlay").waitFor({ state: "visible" });
    ok(true, "recarregar a página bloqueia o cofre");
    await page.fill("#unlock-password", "senha-errada-123456");
    await page.press("#unlock-password", "Enter");
    ok(await until(async () => (await page.locator("#unlock-error").innerText()).includes("incorreta")), "senha errada não desbloqueia");
    await unlock(page);
    ok(await until(async () => (await cards(page)).includes("Gmail pessoal")), "senha certa desbloqueia e a lista volta");

    // XSS: nome com HTML vira texto, nunca elemento
    await addCredential(page, { title: `<img src=x onerror="window.__pwned=1">`, username: "<b>x</b>", url: "javascript:alert(1)" });
    ok(await until(async () => (await cards(page)).some((t) => t.includes("<img"))) && !(await page.evaluate(() => window.__pwned)) && (await page.locator(".cred-card img").count()) === 0, "XSS: HTML digitado numa credencial é mostrado como texto e não executa");
    ok((await page.locator('.cred-card:has-text("<img") [data-action="open-url"]').count()) === 0, "uma URL \"javascript:\" não vira botão de abrir");
    await page.evaluate(() => { const s = document.createElement("script"); s.textContent = "window.__inline = 1"; document.head.appendChild(s); });
    ok(!(await page.evaluate(() => window.__inline)) && cspErrors.length > 0, "a CSP bloqueia script inline injetado (e registra a violação)");
    cspErrors.length = 0;

    // auto-bloqueio: botão e inatividade
    await menu(page, "btn-lock-now");
    ok(await page.locator("#lock-overlay").isVisible() && (await page.evaluate(() => VaultSession.key)) === null && (await page.locator(".cred-card").count()) === 0, "Bloquear agora apaga a chave da memória e a lista da tela");
    await unlock(page);
    await page.locator(".cred-card").first().waitFor();

    // exportar em texto puro exige confirmar a senha mestra
    await addCredential(page, { title: "Planilha", username: "u", password: "=1+1" });
    await menu(page, "btn-export-csv");
    await page.locator("#reauth-modal").waitFor({ state: "visible" });
    await page.fill("#reauth-password", "errada-errada-123");
    await page.press("#reauth-password", "Enter");
    ok(await until(async () => (await page.locator("#reauth-error").innerText()).includes("incorreta")), "exportar: senha mestra errada é recusada");
    const [dl] = await Promise.all([page.waitForEvent("download"), (async () => { await page.fill("#reauth-password", MASTER); await page.press("#reauth-password", "Enter"); })()]);
    const csv = readFileSync(await dl.path(), "utf8");
    ok(csv.startsWith("﻿Site,") && csv.includes("Sup3r-Segredo-Gmail!"), "exportar CSV (com a senha mestra confirmada) gera o arquivo em texto puro");
    ok(csv.includes("'=1+1") && !/,=1\+1/.test(csv), "exportar: célula que começa com = ganha apóstrofo (sem injeção de fórmula no Excel)");

    // importar CSV em lote, sem duplicar
    const importCsv = 'Site,Usuário,Senha,URL,Notas\nGitHub,kauan,s3nh@!,https://github.com,\n"Com, vírgula",u,p,x,"linha1\nlinha2"\n';
    await page.setInputFiles("#import-file-input", { name: "senhas.csv", mimeType: "text/csv", buffer: Buffer.from(importCsv) });
    ok(await until(async () => (await toast(page)).includes("2 adicionada")), "importar CSV: 2 credenciais novas (aspas e vírgula dentro do campo funcionam)");
    await page.setInputFiles("#import-file-input", { name: "senhas.csv", mimeType: "text/csv", buffer: Buffer.from(importCsv) });
    ok(await until(async () => (await toast(page)).includes("0 adicionada") && (await toast(page)).includes("2 já existiam")), "importar de novo o mesmo arquivo não duplica");

    // backup cifrado e restauração idempotente
    const [bk] = await Promise.all([page.waitForEvent("download"), menu(page, "btn-backup")]);
    const backup = JSON.parse(readFileSync(await bk.path(), "utf8"));
    const braw = JSON.stringify(backup);
    ok(backup.format === "cofre-backup" && backup.version === 2 && backup.items.length >= 4 && !braw.includes("Gmail") && !braw.includes("github"), "backup v2: guarda ids e versões e continua sem texto puro");
    const before = (await db(page)).tables.vault_items.length;
    await page.setInputFiles("#restore-file-input", { name: "b.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(backup)) });
    ok(await until(async () => (await toast(page)).includes("Backup restaurado")), "restaurar o backup funciona");
    ok((await db(page)).tables.vault_items.length === before, "restaurar o mesmo backup não duplica (mesmos ids)");

    // restaurar num OUTRO usuário (senha mestra diferente): pede a senha do backup e re-cifra
    const { ctx: ctxB, page: pageB } = await open();
    await signup(pageB, "outro@exemplo.com", "Outra-Senha-Mestra-77");
    await pageB.setInputFiles("#restore-file-input", { name: "b.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(backup)) });
    await pageB.locator("#reauth-modal").waitFor({ state: "visible" });
    await pageB.fill("#reauth-password", MASTER);
    await pageB.press("#reauth-password", "Enter");
    ok(await until(async () => (await cards(pageB)).includes("Gmail pessoal"), 15000), "backup restaurado em outra conta: pede a senha mestra de origem e as credenciais abrem na conta nova");
    const dB = await db(pageB);
    ok(dB.tables.vault_items.every((r) => r.user_id === dB.users[0].id && r.version === 2), "e ficam re-cifradas para o novo dono (AAD do novo usuário)");
    await ctxB.close();

    // ================= 2) Projetos
    await page.locator('a[data-nav][href="projects.html"]').click();
    await page.waitForURL("**/projects.html");
    ok(!(await page.locator("#lock-overlay").isVisible()) && (await page.locator("#projects-empty").isVisible()), "trocar para Projetos não pede a senha de novo (chave passada por até 20 s)");

    await page.click("#btn-new-project");
    await page.fill('#project-body .field:has-text("Nome do projeto") input', "Gerenciador de Senhas");
    await page.fill('#project-body .field:has-text("Descrição") textarea', "Cofre de senhas com Supabase");
    await page.click('.ptab:has-text("Banco de dados")');
    await page.click("text=+ Adicionar banco de dados");
    const dbBox = page.locator("fieldset.entry").first();
    await fld(dbBox, "Provedor$").fill("Supabase");
    await fld(dbBox, "Nome do banco").fill("Financeiro");
    await fld(dbBox, "Identificador").fill("drtrifievfcjhvgjepcq");
    await fld(dbBox, "Painel").fill("https://supabase.com/dashboard/project/drtrifievfcjhvgjepcq");
    await dbBox.locator(".linked summary").click();
    await dbBox.locator('.linked__item:has-text("Gmail pessoal") input').check();
    ok(await dbBox.locator('button.chip--key:has-text("Copiar senha: Gmail pessoal")').count() === 1, "banco de dados: senha do cofre ligada aparece como atalho para copiar");
    await page.click('.ptab:has-text("Hospedagem")');
    await page.click("text=+ Adicionar hospedagem");
    const hostBox = page.locator("fieldset.entry").first();
    await fld(hostBox, "Provedor$").fill("Netlify");
    await fld(hostBox, "Nome do site").fill("meu-site");
    await fld(hostBox, "Endereço público").fill("https://meu-site.netlify.app");
    await fld(hostBox, "Como publica").selectOption("Git automático");
    await page.click('.ptab:has-text("Arquivos")');
    const original = Buffer.concat([Buffer.from("PK\x03\x04instalador-de-teste-"), Buffer.alloc(300000, 7)]);
    await page.setInputFiles("#project-file-input", { name: "gerenciador-1.0.zip", mimeType: "application/zip", buffer: original });
    await page.locator(".file-row").waitFor();
    await page.fill('.file-row input[placeholder^="Versão"]', "1.0.0");
    await page.click("#btn-save-project");
    await page.locator("#project-modal").waitFor({ state: "hidden" });
    const card = page.locator(".proj-card", { hasText: "Gerenciador de Senhas" });
    ok(await until(async () => (await card.count()) === 1), "o projeto aparece na lista");
    const ctext = await card.innerText();
    ok(ctext.includes("Banco: Supabase") && ctext.includes("Hospedagem: Netlify") && ctext.includes("1 arquivo"), "o cartão mostra banco de dados, hospedagem e arquivos");

    const dp = await db(page);
    const praw = JSON.stringify(dp.tables.vault_projects);
    const sto = await page.evaluate(async () => { const out = []; for (const [k, b] of window.__fakeStorage) out.push([k, b.size, [...new Uint8Array(await b.arrayBuffer())].slice(0, 4).join(",")]); return out; });
    ok(!praw.includes("Supabase") && !praw.includes("meu-site") && !praw.includes("drtrifievfcjhvgjepcq"), "projetos: o servidor só guarda blob cifrado (sem provedor, nome ou identificador em claro)");
    ok(sto.length === 1 && sto[0][0].startsWith("project-files/" + dp.users[0].id + "/") && !sto[0][0].includes("gerenciador-1.0") && sto[0][1] > original.length && sto[0][2] !== "80,75,3,4", "arquivo: vai cifrado, com nome aleatório, na pasta do próprio usuário");

    // visão por banco de dados / por hospedagem
    await page.click('[data-group="database"]');
    ok((await page.locator(".proj-group__title").allInnerTexts()).some((t) => t.startsWith("Supabase")), "visão por banco de dados agrupa por provedor (Supabase)");
    await page.click('[data-group="hosting"]');
    ok((await page.locator(".proj-group__title").allInnerTexts()).some((t) => t.startsWith("Netlify")), "visão por hospedagem agrupa por provedor (Netlify)");
    await page.click('[data-group="project"]');

    // recarregar: bloqueia, desbloqueia e o projeto continua lá; baixar confere o conteúdo
    await page.reload();
    await unlock(page);
    await page.locator(".proj-card", { hasText: "Gerenciador de Senhas" }).click();
    await page.click('.ptab:has-text("Arquivos")');
    const [file] = await Promise.all([page.waitForEvent("download"), page.click('.file-row button:has-text("Baixar")')]);
    ok(readFileSync(await file.path()).equals(original) && file.suggestedFilename() === "gerenciador-1.0.zip", "baixar: o arquivo volta idêntico, com o nome original (cifrar/decifrar + SHA-256)");

    // alguém adultera o arquivo no servidor: o download é recusado
    const pristine = await page.evaluate(async () => [...new Uint8Array(await [...window.__fakeStorage.values()][0].arrayBuffer())].join(","));
    await page.evaluate(async () => {
      const [k, b] = [...window.__fakeStorage][0];
      const bytes = new Uint8Array(await b.arrayBuffer());
      bytes[bytes.length - 30] ^= 1;
      window.__fakeStorage.set(k, new Blob([bytes]));
    });
    let tamperedDownload = false;
    page.once("download", () => { tamperedDownload = true; });
    await page.click('.file-row button:has-text("Baixar")');
    ok(await until(async () => /Não foi possível baixar|não confere/.test(await toast(page))) && !tamperedDownload, "arquivo adulterado no servidor: download recusado, nada é salvo");

    await page.evaluate((csv) => { const [k] = [...window.__fakeStorage][0]; window.__fakeStorage.set(k, new Blob([Uint8Array.from(csv.split(","), Number)])); }, pristine); // devolve o original

    // projeto com HTML no nome e URL perigosa
    await page.click("#project-close");
    await page.click("#btn-new-project");
    await page.fill('#project-body .field:has-text("Nome do projeto") input', `<img src=x onerror="window.__pwned=2">`);
    await page.click('.ptab:has-text("Hospedagem")');
    await page.click("text=+ Adicionar hospedagem");
    await fld(page.locator("fieldset.entry").first(), "Endereço público").fill("javascript:alert(1)");
    await page.click("#btn-save-project");
    ok((await page.locator("#project-error").innerText()).includes("endereço inválido"), "projeto: endereço \"javascript:\" é recusado ao salvar");
    await fld(page.locator("fieldset.entry").first(), "Endereço público").fill("https://exemplo.com");
    await page.click("#btn-save-project");
    await page.locator("#project-modal").waitFor({ state: "hidden" });
    ok(!(await page.evaluate(() => window.__pwned)) && (await page.locator(".proj-card img").count()) === 0, "XSS: HTML no nome do projeto é texto, não executa");
    await page.click('[data-group="database"]');
    ok((await page.locator(".proj-group__title").allInnerTexts()).some((t) => t.startsWith("Sem banco de dados informado")), "projeto sem banco cai em \"Sem banco de dados informado\"");
    await page.click('[data-group="project"]');

    // trocar a senha mestra: atômico, re-cifra registros e projetos, NÃO re-cifra arquivos
    const fileBefore = await page.evaluate(async () => { const b = [...window.__fakeStorage.values()][0]; return [...new Uint8Array(await b.arrayBuffer())].join(","); });
    const secretBefore = (await db(page)).users[0].password;
    const rowsBefore = JSON.stringify(await page.evaluate(() => { const d = JSON.parse(localStorage.getItem("__fakedb")); return [d.tables.vault_items, d.tables.vault_projects]; }));
    await menu(page, "btn-change-master");
    await page.fill("#current-master-password", MASTER);
    await page.fill("#new-master-password", "Nova-Senha-Mestra-Bem-Longa-5");
    await page.fill("#new-master-password-confirm", "Nova-Senha-Mestra-Bem-Longa-5");
    await page.setViewportSize({ width: 1100, height: 800 });
    await page.click("#btn-save-change-master");
    ok(await until(async () => /Senha mestra alterada/.test(await toast(page)), 20000), "trocar a senha mestra funciona");
    const dn = await db(page);
    ok(dn.users[0].password !== secretBefore && !dn.passwordsSeen.includes("Nova-Senha-Mestra-Bem-Longa-5"), "e o servidor recebe só o novo segredo derivado, nunca a nova senha");
    ok(JSON.stringify([dn.tables.vault_items, dn.tables.vault_projects]) === rowsBefore, "trocar a senha mestra NÃO re-cifra nada: credenciais e projetos ficam byte a byte iguais (só a DEK é re-embrulhada)");
    const fileAfter = await page.evaluate(async () => { const b = [...window.__fakeStorage.values()][0]; return [...new Uint8Array(await b.arrayBuffer())].join(","); });
    ok(fileBefore === fileAfter, "os arquivos do Storage não foram tocados (a chave de cada arquivo está dentro do projeto)");
    await page.reload();
    await page.locator("#lock-overlay").waitFor({ state: "visible" });
    await page.fill("#unlock-password", MASTER);
    await page.press("#unlock-password", "Enter");
    ok(await until(async () => (await page.locator("#unlock-error").innerText()).includes("incorreta")), "a senha mestra antiga deixa de abrir o cofre");
    await page.fill("#unlock-password", "Nova-Senha-Mestra-Bem-Longa-5");
    await page.press("#unlock-password", "Enter");
    ok(await until(async () => (await page.locator(".proj-card").count()) >= 2), "a nova abre, e os projetos continuam lá");
    await page.locator(".proj-card", { hasText: "Gerenciador de Senhas" }).click();
    await page.click('.ptab:has-text("Arquivos")');
    const [again] = await Promise.all([page.waitForEvent("download"), page.click('.file-row button:has-text("Baixar")')]);
    ok(readFileSync(await again.path()).equals(original), "depois de trocar a senha mestra, o arquivo continua baixando idêntico");
    await page.click("#project-close");

    // troca de senha que falha no meio: nada muda
    await setDb(page, () => { d.flags.failUpdate = "vault_config"; });
    const cfgBefore = JSON.stringify((await db(page)).tables.vault_config);
    const pwdBefore = (await db(page)).users[0].password;
    await menu(page, "btn-change-master");
    await page.fill("#current-master-password", "Nova-Senha-Mestra-Bem-Longa-5");
    await page.fill("#new-master-password", "Terceira-Senha-Mestra-Longa-8");
    await page.fill("#new-master-password-confirm", "Terceira-Senha-Mestra-Longa-8");
    await page.click("#btn-save-change-master");
    ok(await until(async () => (await page.locator("#change-master-error").innerText()).includes("Nada foi alterado")), "se a gravação falhar, o app avisa que nada foi alterado");
    const after = await db(page);
    ok(JSON.stringify(after.tables.vault_config) === cfgBefore && after.users[0].password === pwdBefore, "e de fato nada mudou: configuração igual e segredo de login revertido");
    await page.click("#btn-cancel-change-master");

    // excluir o projeto apaga também os arquivos do Storage
    await page.locator(".proj-card", { hasText: "Gerenciador de Senhas" }).click();
    await page.click("#btn-delete-project");
    ok(await until(async () => (await page.locator(".proj-card", { hasText: "Gerenciador de Senhas" }).count()) === 0), "excluir o projeto tira o cartão da lista");
    ok((await page.evaluate(() => window.__fakeStorage.size)) === 0 && (await db(page)).tables.vault_projects.length === 1, "e apaga o arquivo cifrado do armazenamento (sobra só o outro projeto)");
    await ctx.close();
  }

  // ================= 3) conta ANTIGA em banco ANTIGO (sem as colunas/tabelas novas)
  {
    const seed = await legacyAccount({ schema: { itemVersion: false, authVersion: false, projects: false, rpc: false }, items: [{ title: "Banco Itaú", username: "123", password: "velha-senha-1", url: "", notes: "" }, { title: "Netflix", username: "n@x.com", password: "velha-senha-2", url: "", notes: "" }] });
    const { ctx, page } = await open({ seed });
    await login(page);
    ok(await until(async () => (await cards(page)).length === 2), "conta antiga: as credenciais que já estavam guardadas abrem (login antigo + formato v1)");
    ok((await page.locator("#upgrade-banner").innerText()).includes("schema.sql"), "banco antigo: o app avisa para rodar o schema.sql, sem quebrar");
    const d = await db(page);
    ok(d.users[0].password !== MASTER && d.users[0].password.length === 44, "e o login da conta foi migrado: a senha do servidor deixou de ser a senha mestra");
    await addCredential(page, { title: "Nova no banco antigo", password: "Pw-nova-1234" });
    const row = (await db(page)).tables.vault_items.at(-1);
    ok(!("version" in row), "no banco antigo, o app grava no formato antigo (compatível), sem a coluna version");
    await page.reload();
    await unlock(page);
    ok(await until(async () => (await cards(page)).length === 3), "e tudo continua abrindo depois de recarregar");
    await page.locator('a[data-nav][href="projects.html"]').click();
    await page.waitForURL("**/projects.html");
    ok((await page.locator("#upgrade-banner").innerText()).includes("tabela de projetos") && (await page.locator("#btn-new-project").isDisabled()), "Projetos no banco antigo: avisa o que falta e não deixa criar");
    await ctx.close();
  }

  // ================= 4) conta ANTIGA em banco NOVO: migração do login e dos registros
  {
    const seed = await legacyAccount({ schema: { itemVersion: true, authVersion: true, projects: true, rpc: true }, items: [{ title: "Conta antiga", username: "u", password: "senha-antiga-9", url: "https://exemplo.com", notes: "" }] });
    const { ctx, page } = await open({ seed });
    await login(page);
    ok(await until(async () => (await cards(page)).includes("Conta antiga")), "conta antiga em banco novo: o registro v1 abre");
    ok(await until(async () => (await toast(page)).includes("não é mais enviada")), "aviso: o login foi atualizado e a senha mestra não é mais enviada");
    let d = await db(page);
    ok(d.tables.vault_config[0].auth_version === 2 && d.tables.vault_items[0].version === 1, "login migrado (auth_version 2); o registro antigo continua versão 1 até ser editado");
    await page.locator('.cred-card:has-text("Conta antiga") [data-action="edit"]').click();
    await page.fill("#cred-notes", "editada agora");
    await page.click("#btn-save-credential");
    await page.locator("#credential-modal").waitFor({ state: "hidden" });
    d = await db(page);
    ok(d.tables.vault_items[0].version === 2, "ao editar, o registro sobe para a versão 2 (AAD)");
    // sair e entrar de novo: agora só o segredo derivado vai ao servidor
    await menu(page, "btn-logout");
    await page.waitForURL("**/index.html");
    const mark = (await db(page)).passwordsSeen.length;
    await login(page);
    d = await db(page);
    ok(!d.passwordsSeen.slice(mark).includes(MASTER), "depois de migrada, a conta entra sem nunca enviar a senha mestra");
    await ctx.close();
  }

  // ================= 5) freio contra tentativas e backup de KDF fraco
  {
    const { ctx, page } = await open();
    await signup(page);
    await menu(page, "btn-logout");
    await page.waitForURL("**/index.html");
    for (let i = 0; i < 3; i++) {
      await page.fill("#login-email", EMAIL);
      await page.fill("#login-password", "errada-errada-" + i + "xyz");
      await page.click("#login-submit");
      await until(async () => (await page.locator("#login-error").isVisible()), 8000);
    }
    await page.fill("#login-password", "errada-errada-final");
    await page.click("#login-submit");
    ok(await until(async () => (await page.locator("#login-error").innerText()).includes("Aguarde")), "depois de 3 tentativas erradas seguidas, o login espera antes de aceitar outra");
    await ctx.close();
  }

  // ================= 5b) senha mestra mínima de 5 caracteres
  {
    const { ctx, page } = await open();
    await page.goto(server.url + "/index.html");
    await page.click("#tab-signup");
    await page.fill("#signup-email", "curta@exemplo.com");
    await page.evaluate(() => { for (const id of ["signup-password", "signup-password-confirm"]) document.getElementById(id).removeAttribute("minlength"); }); // deixa o app (e não o navegador) validar
    await page.fill("#signup-password", "abcd");
    await page.fill("#signup-password-confirm", "abcd");
    await page.click("#signup-submit");
    ok(await until(async () => (await page.locator("#signup-error").innerText()).includes("pelo menos 5")), "cadastro: 4 caracteres é recusado, com a mensagem do mínimo de 5");
    ok((((await db(page)) || { users: [] }).users).length === 0, "e nada foi enviado ao servidor");
    await page.fill("#signup-password", "abcde");
    await page.fill("#signup-password-confirm", "abcde");
    await page.click("#signup-submit");
    await confirmRecovery(page);
    await page.waitForURL("**/vault.html");
    await addCredential(page, { title: "Com senha curta", password: "x" });
    await page.reload();
    await unlock(page, "abcde");
    ok(await until(async () => (await cards(page)).includes("Com senha curta")), "com 5 caracteres o cofre é criado, bloqueia e desbloqueia normalmente");
    await ctx.close();
  }

  // ================= 5c) esqueci a senha mestra: e-mail + chave de recuperação
  {
    const { ctx, page } = await open();
    await signup(page);
    const code = lastRecovery;
    await addCredential(page, { title: "Cartao do banco", username: "u", password: "Seg-Recuperavel-1" });
    const dbefore = await db(page);
    const rowsBefore = JSON.stringify(dbefore.tables.vault_items);
    const userId = dbefore.users[0].id;
    await menu(page, "btn-logout");
    await page.waitForURL("**/index.html");
    await page.fill("#login-email", EMAIL);
    await page.click("#btn-forgot-password");
    ok(await until(async () => (await page.locator("#forgot-password-message").innerText()).includes("link de recuperação")), "esqueci a senha: o app avisa que mandou o e-mail (sem revelar se o cofre existe)");
    const resets = (await db(page)).resets || [];
    ok(resets.length === 1 && resets[0].redirectTo === server.url + "/recovery.html", "o link do e-mail volta para a tela de recuperação do próprio site");

    // o clique no link do e-mail deixa uma sessão de recuperação aberta (simulada)
    await page.evaluate((s) => sessionStorage.setItem("__fakesession", JSON.stringify(s)), { access_token: "tok-" + userId, user: { id: userId, email: EMAIL } });
    await page.goto(server.url + "/recovery.html");
    await page.fill("#recovery-code-input", "0000-0000-0000");
    await page.fill("#recovery-new-password", "Senha-Nova-Recuperada-5");
    await page.fill("#recovery-new-password-confirm", "Senha-Nova-Recuperada-5");
    await page.click("#recovery-submit");
    ok(await until(async () => (await page.locator("#recovery-error").innerText()).includes("formato inválido")), "recuperar: chave com formato errado é recusada");
    await page.fill("#recovery-code-input", "0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000");
    await page.click("#recovery-submit");
    ok(await until(async () => (await page.locator("#recovery-error").innerText()).includes("incorreta")), "recuperar: chave errada (formato certo) é recusada");
    await page.fill("#recovery-code-input", code.toLowerCase());
    await page.click("#recovery-submit");
    await page.waitForURL("**/vault.html");
    ok(await until(async () => (await cards(page)).includes("Cartao do banco")), "recuperar com a chave certa: as credenciais antigas abrem, sem perder nada");
    const dr = await db(page);
    ok(JSON.stringify(dr.tables.vault_items) === rowsBefore && !dr.passwordsSeen.includes("Senha-Nova-Recuperada-5") && dr.users[0].password.length === 44, "e nada foi re-cifrado; o servidor só recebeu o segredo derivado da nova senha");
    await page.reload();
    await unlock(page, "Senha-Nova-Recuperada-5");
    ok(await until(async () => (await cards(page)).includes("Cartao do banco")), "a nova senha mestra passa a abrir o cofre");
    await menu(page, "btn-logout");
    await page.waitForURL("**/index.html");
    await page.fill("#login-email", EMAIL);
    await page.fill("#login-password", MASTER);
    await page.click("#login-submit");
    ok(await until(async () => (await page.locator("#login-error").innerText()).length > 0), "a senha mestra antiga deixa de entrar");
    await ctx.close();
  }

  // ================= 5d) conta ANTIGA real (DEK): gerar chave de recuperação nova e recuperar com ela
  {
    const seed = await legacyAccount({ schema: { itemVersion: true, authVersion: true, projects: true }, items: [{ title: "Do formato real", username: "u", password: "p-real-1", url: "", notes: "" }] });
    const { ctx, page } = await open({ seed });
    await login(page);
    ok(await until(async () => (await cards(page)).includes("Do formato real")), "conta real (DEK): abre com a senha mestra de sempre");
    // perdeu a chave de recuperação: gera outra de dentro do cofre (exige a senha mestra)
    await menu(page, "btn-new-recovery");
    await page.locator("#reauth-modal").waitFor({ state: "visible" });
    await page.fill("#reauth-password", "errada-errada-123");
    await page.press("#reauth-password", "Enter");
    ok(await until(async () => /incorreta/.test(await toast(page))), "nova chave de recuperação: senha mestra errada é recusada e nada muda");
    await menu(page, "btn-new-recovery");
    await page.locator("#reauth-modal").waitFor({ state: "visible" });
    await page.fill("#reauth-password", MASTER);
    await page.press("#reauth-password", "Enter");
    const newCode = await confirmRecovery(page);
    const cfgNew = (await db(page)).tables.vault_config[0];
    ok(/^([0-9A-F]{4}-){15}[0-9A-F]{4}$/.test(newCode) && newCode !== seed.recoveryCode && !JSON.stringify(await db(page)).includes(newCode) && cfgNew.recovery_wrapped_dek !== seed.__oldRec, "nova chave de recuperação gerada (a senha mestra e os dados não mudaram); o servidor não guarda a chave em texto");
    await menu(page, "btn-change-master");
    await page.fill("#current-master-password", MASTER);
    await page.fill("#new-master-password", "Senha-Trocada-Pos-Migracao-3");
    await page.fill("#new-master-password-confirm", "Senha-Trocada-Pos-Migracao-3");
    await page.click("#btn-save-change-master");
    ok(await until(async () => /Senha mestra alterada/.test(await toast(page)), 20000), "conta real: trocar a senha mestra funciona");
    const userId = (await db(page)).users[0].id;
    await menu(page, "btn-logout");
    await page.waitForURL("**/index.html");
    await page.evaluate((s) => sessionStorage.setItem("__fakesession", JSON.stringify(s)), { access_token: "tok-" + userId, user: { id: userId, email: EMAIL } });
    await page.goto(server.url + "/recovery.html");
    await page.fill("#recovery-code-input", seed.recoveryCode);
    await page.fill("#recovery-new-password", "Outra-Depois-Da-Troca-8");
    await page.fill("#recovery-new-password-confirm", "Outra-Depois-Da-Troca-8");
    await page.click("#recovery-submit");
    ok(await until(async () => (await page.locator("#recovery-error").innerText()).includes("incorreta")), "a chave de recuperação ANTIGA deixa de valer depois de gerar a nova");
    await page.fill("#recovery-code-input", newCode);
    await page.click("#recovery-submit");
    await page.waitForURL("**/vault.html");
    ok(await until(async () => (await cards(page)).includes("Do formato real")), "a chave NOVA continua valendo depois de trocar a senha mestra e recupera o cofre");
    await ctx.close();
  }

  // ================= 5e) planilha de exemplo de importação
  {
    const { ctx, page } = await open();
    await signup(page);
    const [ex] = await Promise.all([page.waitForEvent("download"), menu(page, "btn-import-example")]);
    ok(ex.suggestedFilename() === "arca-exemplo-importacao.xlsx", "menu: \"Baixar exemplo de importação\" baixa a planilha de exemplo (.xlsx)");
    const exPath = await ex.path();
    const info = await page.evaluate(async (b64) => {
      const wb = XLSX.read(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)), { type: "array" });
      const first = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { defval: "" });
      return { sheets: wb.SheetNames, cols: Object.keys(first[0] || {}), n: first.length };
    }, readFileSync(exPath).toString("base64"));
    ok(info.sheets[0] === "Senhas" && info.sheets.includes("Como usar") && info.cols.join(",") === "Site,Usuário,Senha,URL,Notas" && info.n === 3, "o exemplo tem a aba Senhas (com as 5 colunas e 3 linhas de exemplo) e a aba Como usar");
    await page.setInputFiles("#import-file-input", { name: "arca-exemplo-importacao.xlsx", mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", buffer: readFileSync(exPath) });
    ok(await until(async () => (await toast(page)).includes("3 adicionada")), "e o próprio exemplo é aceito pelo importador (ida e volta)");
    await ctx.close();
  }

  // ================= 6) auto-bloqueio por inatividade (relógio simulado)
  {
    const { ctx, page } = await open();
    await page.clock.install();
    await signup(page);
    await page.locator(".empty-state, .cred-card").first().waitFor({ state: "attached" });
    await page.clock.fastForward("04:30");
    ok(!(await page.locator("#lock-overlay").isVisible()), "antes do limite (5 min) o cofre continua aberto");
    await page.clock.fastForward("01:00");
    ok(await until(async () => await page.locator("#lock-overlay").isVisible(), 4000), "depois de 5 minutos sem atividade o cofre bloqueia sozinho");
    ok((await page.evaluate(() => VaultSession.key)) === null, "e a chave sai da memória");
    await ctx.close();
  }

  // ================= 7) geral
  ok(cspErrors.length === 0, "nenhuma violação de CSP durante o uso normal" + (cspErrors.length ? ": " + cspErrors[0] : ""));
  ok(foreignRequests.length === 0, "nenhuma requisição para fora do próprio site" + (foreignRequests.length ? ": " + [...new Set(foreignRequests)].join(", ") : ""));
  ok(!server.hits.some((p) => /config\.example|README|schema\.sql|\.git/.test(p)), "o servidor não entrega README, SQL nem arquivos de exemplo");
} finally {
  await br.close();
  await server.close();
}
done("Cofre: ponta a ponta");
