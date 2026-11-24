// Testes de ponta a ponta do armazenamento no Google Drive PESSOAL, com o Google SIMULADO (nenhuma requisição real).
// Imita: tela de consentimento (redireciona para a página de retorno do app), tokeninfo, Drive v3 (pasta, envio
// resumable, download, apagar), revogação. NÃO prova o comportamento do Google de verdade: isso só se vê com um
// Client ID real (ver README, seção do Google).
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT, done, launch, ok, startServer, until } from "./lib.mjs";

createRequire(import.meta.url);
const FAKE = readFileSync(join(ROOT, "tests", "fake-supabase.js"), "utf8");
const MASTER = "Cavalo-Grampo-Bateria-9";
const GID = "123456789-abcdef.apps.googleusercontent.com";
const GOOGLE_HOSTS = new Set(["accounts.google.com", "www.googleapis.com", "oauth2.googleapis.com"]);

console.log("\n== Google Drive pessoal: ponta a ponta (Google simulado)");
const server = await startServer({ GOOGLE_CLIENT_ID: GID });
const br = await launch();
const cspErrors = [];
const foreign = new Set();

// Estado do "Google" (um por teste)
const google = { files: new Map(), uploads: [], revoked: [], deleted: [], consentUrls: [], tokens: new Set(), refuse: false, bytesSent: 0 };

async function open() {
  const ctx = await br.newContext({ viewport: { width: 1100, height: 800 }, acceptDownloads: true });
  await ctx.addInitScript({ content: FAKE });
  await ctx.route("**/vendor/supabase-js-*.js", (r) => r.abort());
  const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS", "access-control-expose-headers": "Location" };
  const json = (route, body, status = 200, extra = {}) => route.fulfill({ status, contentType: "application/json", headers: { ...cors, ...extra }, body: JSON.stringify(body) });

  await ctx.route("https://accounts.google.com/**", (route) => {
    const u = new URL(route.request().url());
    google.consentUrls.push(u.toString());
    const back = u.searchParams.get("redirect_uri");
    const state = u.searchParams.get("state");
    const hash = google.refuse ? `error=access_denied&state=${state}` : `access_token=TOKEN-${google.tokens.size + 1}&expires_in=3599&token_type=Bearer&state=${state}`;
    if (!google.refuse) google.tokens.add(`TOKEN-${google.tokens.size + 1}`);
    route.fulfill({ status: 302, headers: { Location: back + "#" + hash } });
  });
  await ctx.route("https://oauth2.googleapis.com/**", (route) => {
    const req = route.request();
    const u = new URL(req.url());
    if (req.method() === "OPTIONS") return route.fulfill({ status: 204, headers: cors });
    if (u.pathname === "/tokeninfo") return json(route, { aud: GID, scope: "https://www.googleapis.com/auth/drive.file", expires_in: "3599" });
    if (u.pathname === "/revoke") { google.revoked.push(u.searchParams.get("token")); return json(route, {}); }
    return json(route, {}, 404);
  });
  await ctx.route("https://www.googleapis.com/**", async (route) => {
    const req = route.request();
    const u = new URL(req.url());
    if (req.method() === "OPTIONS") return route.fulfill({ status: 204, headers: cors });
    const auth = req.headers()["authorization"] || "";
    // a URL da sessão de envio (resumable) já carrega a autorização: o PUT não leva Bearer, como no Google de verdade
    if (!u.pathname.startsWith("/upload/session/") && !/^Bearer TOKEN-\d+$/.test(auth)) return json(route, {}, 401);
    if (u.pathname === "/drive/v3/about") return json(route, { user: { emailAddress: "ana@gmail.com", displayName: "Ana" }, storageQuota: { limit: String(15 * 1024 ** 3), usage: String(3 * 1024 ** 3) } });
    if (u.pathname === "/drive/v3/files" && req.method() === "GET") return json(route, { files: [...google.files.values()].filter((f) => f.folder).map((f) => ({ id: f.id })) });
    if (u.pathname === "/drive/v3/files" && req.method() === "POST") {
      const b = JSON.parse(req.postData());
      google.files.set("folder1", { id: "folder1", folder: true, name: b.name });
      return json(route, { id: "folder1" });
    }
    if (u.pathname === "/upload/drive/v3/files" && req.method() === "POST") {
      const meta = JSON.parse(req.postData());
      google.uploads.push(meta);
      return json(route, {}, 200, { Location: "https://www.googleapis.com/upload/session/" + meta.name });
    }
    if (u.pathname.startsWith("/upload/session/") && req.method() === "PUT") {
      const body = req.postDataBuffer();
      const id = "file" + (google.files.size + 1);
      google.files.set(id, { id, name: u.pathname.split("/").pop(), bytes: body });
      google.bytesSent += body.length;
      return json(route, { id });
    }
    const m = u.pathname.match(/^\/drive\/v3\/files\/([^/]+)$/);
    if (m && req.method() === "GET") {
      const f = google.files.get(m[1]);
      if (!f) return json(route, {}, 404);
      return route.fulfill({ status: 200, headers: cors, contentType: "application/octet-stream", body: f.bytes });
    }
    if (m && req.method() === "DELETE") {
      google.files.delete(m[1]);
      google.deleted.push(m[1]);
      return route.fulfill({ status: 204, headers: cors });
    }
    return json(route, {}, 404);
  });

  const page = await ctx.newPage();
  page.on("console", (msg) => { if (msg.type() === "error" && /Content Security Policy/i.test(msg.text())) cspErrors.push(msg.text().slice(0, 200)); });
  page.on("request", (r) => { const u = new URL(r.url()); if (!r.url().startsWith(server.url) && u.protocol.startsWith("http") && !GOOGLE_HOSTS.has(u.host)) foreign.add(u.host); });
  page.on("dialog", (d) => d.accept());
  return { ctx, page };
}

const fld = (scope, label) => scope.locator(".field", { has: scope.page().locator(".field__label", { hasText: new RegExp("^" + label) }) }).locator("input, textarea, select").first();
const toast = (page) => page.locator("#toast").innerText().catch(() => "");

try {
  const { ctx, page } = await open();
  await page.goto(server.url + "/index.html");
  await page.click("#tab-signup");
  await page.fill("#signup-email", "ana@exemplo.com");
  await page.fill("#signup-password", MASTER);
  await page.fill("#signup-password-confirm", MASTER);
  await page.click("#signup-submit");
  await page.waitForURL("**/vault.html");
  await page.locator('a[data-nav][href="projects.html"]').click();
  await page.waitForURL("**/projects.html");

  await page.click("#btn-new-project");
  await page.fill('#project-body .field:has-text("Nome do projeto") input', "App com instalador");
  await page.click('.ptab:has-text("Arquivos")');
  ok((await page.locator(".dropzone.is-disabled").count()) === 1 && (await page.locator("#project-file-input").isDisabled()), "sem conectar o Google, o envio de arquivos fica travado e pede para conectar");
  ok(/Google Drive|SEU Google Drive/.test(await page.locator(".drive-bar").innerText()), "a aba explica que os arquivos vão para o Drive da própria pessoa");

  // recusa no Google
  google.refuse = true;
  await page.click('.drive-bar button:has-text("Conectar")');
  ok(await until(async () => /não autorizou/.test(await toast(page)), 8000), "se a pessoa recusar no Google, o app avisa e continua desconectado");
  google.refuse = false;

  // conecta
  await page.click('.drive-bar button:has-text("Conectar")');
  ok(await until(async () => /ana@gmail\.com/.test(await page.locator(".drive-bar").innerText().catch(() => "")), 10000), "conecta: mostra a conta Google e o espaço livre do Drive dela");
  ok(/12([.,]00)? GB livres/.test(await page.locator(".drive-bar").innerText()), "mostra o espaço livre (15 GB - 3 GB)");
  const url = new URL(google.consentUrls.at(-1));
  ok(url.searchParams.get("scope") === "https://www.googleapis.com/auth/drive.file" && url.searchParams.get("response_type") === "token" && url.searchParams.get("client_id") === GID && url.searchParams.get("state").length >= 16, "o pedido ao Google usa só o escopo drive.file, o Client ID certo e um state aleatório");
  ok(url.searchParams.get("redirect_uri") === server.url + "/google-callback.html", "e volta para a página de retorno do próprio site");
  ok((await page.locator("#project-file-input").isDisabled()) === false, "depois de conectar, o envio é liberado");

  // envia
  const original = Buffer.concat([Buffer.from("PK\x03\x04instalador-"), Buffer.alloc(2500000, 9)]); // > 1 MiB: vários blocos
  await page.setInputFiles("#project-file-input", { name: "app-setup.zip", mimeType: "application/zip", buffer: original });
  await page.locator(".file-row").waitFor({ timeout: 20000 }).catch(async (e) => {
    console.log("TOAST:", await toast(page), "| BODY:", (await page.locator("#project-body").innerText()).slice(0, 500));
    throw e;
  });
  await page.click("#btn-save-project");
  await page.locator("#project-modal").waitFor({ state: "hidden" });

  const files = [...google.files.values()].filter((f) => !f.folder);
  ok(files.length === 1 && /^[0-9a-f-]{36}\.arca$/.test(files[0].name) && !files[0].name.includes("app-setup"), "no Drive vai um único arquivo com nome aleatório (.arca), sem o nome real");
  ok(files[0].bytes.length > original.length && !files[0].bytes.subarray(0, 4).equals(Buffer.from("PK\x03\x04")) && files[0].bytes.indexOf(Buffer.from("instalador-")) === -1, "e o conteúdo chega CIFRADO ao Google (não há texto original)");
  ok(google.uploads[0].parents[0] === "folder1" && google.files.get("folder1").name === "Arca (arquivos cifrados)", "fica na pasta própria do app, criada no Drive da pessoa");
  const stoCount = await page.evaluate(() => window.__fakeStorage.size);
  ok(stoCount === 0, "nada do arquivo vai para o armazenamento compartilhado do Supabase");
  const tokenStored = await page.evaluate(() => JSON.stringify({ l: { ...localStorage }, s: { ...sessionStorage } }));
  ok(!/TOKEN-\d/.test(tokenStored), "o token do Google não é gravado em localStorage nem sessionStorage (só memória)");

  // baixa
  await page.locator(".proj-card", { hasText: "App com instalador" }).click();
  await page.click('.ptab:has-text("Arquivos")');
  const [d1] = await Promise.all([page.waitForEvent("download"), page.click('.file-row button:has-text("Baixar")')]);
  ok(readFileSync(await d1.path()).equals(original) && d1.suggestedFilename() === "app-setup.zip", "baixar do Drive: volta idêntico, com o nome original (decifra e confere o SHA-256)");

  // adulterado no Drive
  const id = [...google.files.values()].find((f) => !f.folder).id;
  const good = Buffer.from(google.files.get(id).bytes);
  const bad = Buffer.from(good); bad[bad.length - 40] ^= 1;
  google.files.get(id).bytes = bad;
  let got = false;
  page.once("download", () => { got = true; });
  await page.click('.file-row button:has-text("Baixar")');
  ok(await until(async () => /Não foi possível baixar|não confere/.test(await toast(page))) && !got, "arquivo adulterado no Drive: download recusado");
  google.files.get(id).bytes = good;
  await page.click("#project-close");

  // bloquear descarta o token; baixar de novo reconecta
  await page.click("#account-menu-trigger");
  await page.click("#btn-lock-now");
  await page.locator("#lock-overlay").waitFor({ state: "visible" });
  await page.fill("#unlock-password", MASTER);
  await page.press("#unlock-password", "Enter");
  await page.locator(".proj-card", { hasText: "App com instalador" }).waitFor();
  ok((await page.evaluate(() => GoogleDrive.connected())) === false, "ao bloquear o cofre o token do Google é descartado");
  await page.locator(".proj-card", { hasText: "App com instalador" }).click();
  await page.click('.ptab:has-text("Arquivos")');
  const [d2] = await Promise.all([page.waitForEvent("download", { timeout: 20000 }), page.click('.file-row button:has-text("Baixar")')]);
  ok(readFileSync(await d2.path()).equals(original) && google.consentUrls.length === 3, "baixar sem conexão pede o Google de novo e então baixa (idêntico)");

  // desconectar revoga
  const before = google.revoked.length;
  await page.click('.drive-bar button:has-text("Desconectar")');
  ok(await until(async () => google.revoked.length === before + 1 && /^TOKEN-\d+$/.test(google.revoked.at(-1))), "Desconectar revoga a autorização no Google");
  ok((await page.locator(".drive-bar button:has-text(\"Conectar\")").count()) === 1, "e a tela volta a oferecer Conectar");
  await page.click("#project-close");

  // excluir projeto sem Google conectado: avisa que o arquivo continua no Drive
  const dialogs = [];
  page.removeAllListeners("dialog");
  page.on("dialog", (dg) => { dialogs.push(dg.message()); dg.accept(); });
  await page.locator(".proj-card", { hasText: "App com instalador" }).click();
  await page.click("#btn-delete-project");
  ok(await until(async () => (await page.locator(".proj-card").count()) === 0), "excluir projeto desconectado funciona");
  ok(dialogs.some((m) => /continuar[ãa]o no seu Drive/.test(m)) && google.files.size === 2, "e avisa que os arquivos continuam no Drive (não deu para apagar sem a conta)");
  ok(/continuam no seu Google Drive/.test(await toast(page)), "o aviso final também lembra disso");

  // novo projeto conectado: excluir apaga o arquivo do Drive
  await page.click("#btn-new-project");
  await page.fill('#project-body .field:has-text("Nome do projeto") input', "Segundo");
  await page.click('.ptab:has-text("Arquivos")');
  await page.click('.drive-bar button:has-text("Conectar")');
  await page.locator(".drive-bar__ok").waitFor({ timeout: 10000 });
  await page.setInputFiles("#project-file-input", { name: "b.bin", mimeType: "application/octet-stream", buffer: Buffer.alloc(5000, 3) });
  await page.locator(".file-row").waitFor();
  await page.click("#btn-save-project");
  await page.locator("#project-modal").waitFor({ state: "hidden" });
  const nBefore = google.files.size;
  await page.locator(".proj-card", { hasText: "Segundo" }).click();
  await page.click("#btn-delete-project");
  ok(await until(async () => google.files.size === nBefore - 1 && google.deleted.length >= 1), "excluir projeto conectado apaga também o arquivo do Google Drive");
  await ctx.close();

  // Google fora do ar para o Supabase? sem GOOGLE_CLIENT_ID o app volta ao armazenamento do Supabase: testado no e2e principal.
  ok(cspErrors.length === 0, "nenhuma violação de CSP com o Google ligado" + (cspErrors.length ? ": " + cspErrors[0] : ""));
  ok(foreign.size === 0, "nenhuma requisição além do site, do Supabase e dos 3 hosts do Google" + (foreign.size ? ": " + [...foreign].join(", ") : ""));
} finally {
  await br.close();
  await server.close();
}
done("Google Drive pessoal: ponta a ponta");
