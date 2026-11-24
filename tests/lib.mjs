// Utilidades dos testes: servidor estático com os MESMOS cabeçalhos de segurança do Netlify (_headers),
// navegador sem janela e pequenas funções de conferência.
import { createServer } from "node:http";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const FAKE_HOST = "fake.supabase.test";

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".png": "image/png", ".json": "application/json", ".txt": "text/plain" };
const PUBLIC = [/^\/(index|vault|projects|google-callback)\.html$/, /^\/css\//, /^\/img\//, /^\/vendor\//, /^\/js\/(?!config)/];

// Lê o primeiro bloco ("/*") do _headers, trocando o host do Supabase.
export function securityHeaders(google = false) {
  const text = readFileSync(join(ROOT, "_headers"), "utf8")
    .replaceAll("__SUPABASE_HOST__", FAKE_HOST)
    .replaceAll(" __GOOGLE_CONNECT__", google ? " https://www.googleapis.com https://oauth2.googleapis.com" : "");
  const out = {};
  const lines = text.split(/\r?\n/);
  let inBlock = false;
  for (const l of lines) {
    if (/^\/\*\s*$/.test(l)) { inBlock = true; continue; }
    if (/^\S/.test(l) && !l.startsWith("#")) { if (inBlock) break; }
    if (inBlock && /^\s+\S/.test(l)) {
      const i = l.indexOf(":");
      out[l.slice(0, i).trim()] = l.slice(i + 1).trim();
    }
  }
  return out;
}

export async function startServer(configOverrides = {}) {
  const headers = securityHeaders(!!configOverrides.GOOGLE_CLIENT_ID);
  const config = {
    SUPABASE_URL: `https://${FAKE_HOST}`,
    SUPABASE_ANON_KEY: "anon-de-teste",
    KDF_ITERATIONS: 200000,
    AUTO_LOCK_MINUTES: 5,
    CLIPBOARD_CLEAR_SECONDS: 20,
    MAX_FILE_MB: 50,
    MIN_MASTER_LENGTH: 5,
    SESSION_STORE: "tab",
    LEGACY_LOGIN: true,
    ...configOverrides
  };
  const hits = [];
  const server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    hits.push(path);
    const send = (status, body, type) => {
      res.writeHead(status, { ...headers, "Content-Type": type || "text/plain" });
      res.end(body);
    };
    if (path === "/js/config.js") return send(200, "window.APP_CONFIG = " + JSON.stringify(config) + ";", TYPES[".js"]);
    const p = path === "/" ? "/index.html" : path;
    if (!PUBLIC.some((re) => re.test(p))) return send(404, "não encontrado");
    const file = normalize(join(ROOT, p));
    if (!file.startsWith(ROOT) || !existsSync(file) || !statSync(file).isFile()) return send(404, "não encontrado");
    send(200, readFileSync(file), TYPES[extname(file)] || "application/octet-stream");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}`, hits, config, close: () => new Promise((r) => server.close(r)) };
}

export async function launch() {
  const { chromium } = await import("playwright-core");
  const candidates = [process.env.PW_BROWSER, "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe", "C:/Program Files/Google/Chrome/Application/chrome.exe", "/usr/bin/google-chrome", "/usr/bin/chromium"].filter(Boolean);
  const executablePath = candidates.find((p) => existsSync(p));
  if (!executablePath) throw new Error("Nenhum Chrome/Edge encontrado. Defina PW_BROWSER com o caminho do navegador.");
  return chromium.launch({ executablePath, headless: true });
}

let failures = 0;
export function ok(cond, name) {
  console.log((cond ? "PASS  " : "FAIL  ") + name);
  if (!cond) failures++;
}
export const done = (title) => {
  console.log(failures ? `\n${title}: ${failures} falha(s)` : `\n${title}: tudo certo`);
  process.exitCode = failures ? 1 : 0;
};
export const until = async (fn, ms = 10000) => {
  for (let t = 0; t < ms; t += 150) {
    try { if (await fn()) return true; } catch { /* tenta de novo */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
};
