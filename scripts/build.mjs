// Monta a pasta dist/ que vai para o ar (Netlify ou "arrastar e soltar").
// Só copia o que o site precisa: o resto do repositório (README, scripts, SQL, testes) NUNCA é publicado.
//
//   node scripts/build.mjs
//
// A configuração do Supabase vem de variáveis de ambiente (no Netlify: Site configuration > Environment variables):
//   SUPABASE_URL        https://<ref>.supabase.co
//   SUPABASE_ANON_KEY   a chave PÚBLICA (anon / publishable). NUNCA a service_role / secret.
// Sem as variáveis, usa js/config.js (arquivo local, fora do git).
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
// Apaga o dist/ anterior ANTES de validar: se o build falhar, não sobra uma versão velha para alguém publicar sem querer.
rmSync(dist, { recursive: true, force: true });

const PUBLISH = ["index.html", "vault.html", "projects.html", "css", "img", "vendor"];
const JS_FILES = [
  "theme.js", "ui-tabs.js", "crypto.js", "supabase-client.js", "auth.js", "session.js", "vault-data.js", "generator.js",
  "clipboard.js", "credentials.js", "import-export.js", "backup.js", "autolock.js", "settings.js", "files.js", "projects.js"
];

function fail(msg) {
  console.error("ERRO: " + msg);
  process.exit(1);
}

// Lê SUPABASE_URL e SUPABASE_ANON_KEY do ambiente ou do js/config.js local.
function readConfig() {
  let url = process.env.SUPABASE_URL;
  let key = process.env.SUPABASE_ANON_KEY;
  let extra = {};
  const local = join(root, "js", "config.js");
  if ((!url || !key) && existsSync(local)) {
    const text = readFileSync(local, "utf8");
    url ||= (text.match(/SUPABASE_URL:\s*"([^"]+)"/) || [])[1];
    key ||= (text.match(/SUPABASE_ANON_KEY:\s*"([^"]+)"/) || [])[1];
    for (const k of ["KDF_ITERATIONS", "AUTO_LOCK_MINUTES", "CLIPBOARD_CLEAR_SECONDS", "MAX_FILE_MB"]) {
      const m = text.match(new RegExp(k + ":\\s*(\\d+)"));
      if (m) extra[k] = Number(m[1]);
    }
  }
  return { url, key, extra };
}

// Trava de segurança: a chave de serviço ignora a RLS. Se ela for parar no site, qualquer pessoa leria tudo.
function assertPublicKey(key) {
  if (/^sb_secret_/.test(key)) fail("Essa é uma chave SECRETA do Supabase (sb_secret_...). Use a chave pública (anon/publishable).");
  const parts = key.split(".");
  if (parts.length === 3) {
    try {
      const role = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")).role;
      if (role && role !== "anon") fail(`A chave informada tem o papel "${role}". Só a chave "anon" pode ir para o site.`);
    } catch {
      /* não é um JWT legível: segue */
    }
  }
}

const { url, key, extra } = readConfig();
if (!url || !key) fail("Defina SUPABASE_URL e SUPABASE_ANON_KEY (variáveis de ambiente) ou crie js/config.js a partir de js/config.example.js.");
let host;
try {
  const u = new URL(url);
  if (u.protocol !== "https:") fail("SUPABASE_URL precisa ser https.");
  host = u.host;
} catch {
  fail("SUPABASE_URL inválida.");
}
assertPublicKey(key);

mkdirSync(join(dist, "js"), { recursive: true });
for (const item of PUBLISH) cpSync(join(root, item), join(dist, item), { recursive: true });
for (const f of JS_FILES) cpSync(join(root, "js", f), join(dist, "js", f));

const cfg = {
  SUPABASE_URL: url,
  SUPABASE_ANON_KEY: key,
  KDF_ITERATIONS: extra.KDF_ITERATIONS ?? 600000,
  AUTO_LOCK_MINUTES: extra.AUTO_LOCK_MINUTES ?? 5,
  CLIPBOARD_CLEAR_SECONDS: extra.CLIPBOARD_CLEAR_SECONDS ?? 20,
  MAX_FILE_MB: extra.MAX_FILE_MB ?? 50,
  MIN_MASTER_LENGTH: 5,
  SESSION_STORE: "tab",
  LEGACY_LOGIN: process.env.LEGACY_LOGIN === "false" ? false : true
};
writeFileSync(join(dist, "js", "config.js"), "window.APP_CONFIG = " + JSON.stringify(cfg, null, 2) + ";\n");

const headers = readFileSync(join(root, "_headers"), "utf8").replaceAll("__SUPABASE_HOST__", host);
writeFileSync(join(dist, "_headers"), headers);

console.log(`dist/ pronto. Supabase: ${host}. LEGACY_LOGIN=${cfg.LEGACY_LOGIN}`);
